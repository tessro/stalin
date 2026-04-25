use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, Response, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use bytes::Bytes;
use tokio::{io::copy_bidirectional, net::TcpStream};
use tracing::{error, info, warn};
use url::Url;

use crate::{
    audit::AuditLog,
    config::Config,
    policy::{PolicyDecision, PolicyEngine, RequestInfo, target_url},
};

pub struct ProxyServer {
    config: Config,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        let listen = self.config.listen;
        let audit = AuditLog::new(self.config.audit_log.as_deref()).await?;
        let state = AppState {
            client: reqwest::Client::builder()
                .http2_adaptive_window(true)
                .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                .build()?,
            policy: PolicyEngine::new(self.config, audit),
        };

        let app = Router::new()
            .fallback(any(handle_proxy))
            .with_state(Arc::new(state));
        let listener = tokio::net::TcpListener::bind(listen).await?;
        info!(%listen, "stalin proxy listening");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

struct AppState {
    client: reqwest::Client,
    policy: PolicyEngine,
}

async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    if req.method() == Method::CONNECT {
        return handle_connect(state, req).await;
    }

    let method = req.method().clone();
    let target = target_url(req.uri(), req.headers())?;
    let request_info = RequestInfo::new(method.clone(), target.clone());
    let mut outbound_headers = sanitized_headers(req.headers());

    match state
        .policy
        .evaluate(&request_info, &mut outbound_headers)
        .await?
    {
        PolicyDecision::Deny(resp) => return Ok(immediate_response(resp.status, resp.body)),
        PolicyDecision::Continue { matched_rules } => {
            if !matched_rules.is_empty() {
                info!(
                    request_id = %request_info.request_id,
                    rules = ?matched_rules,
                    url = %target,
                    "request policy applied"
                );
            }
        }
    }

    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|err| ProxyError::BadGateway(err.into()))?;

    let mut builder = state.client.request(method, target.as_str());
    for (name, value) in outbound_headers.iter() {
        builder = builder.header(name, value);
    }

    let upstream = builder
        .body(body)
        .send()
        .await
        .map_err(|err| ProxyError::BadGateway(err.into()))?;
    response_from_upstream(upstream).await
}

async fn handle_connect(
    state: Arc<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| ProxyError::BadRequest("CONNECT request missing authority".to_string()))?
        .to_string();
    let target = connect_target_url(req.uri(), &authority)?;
    let request_info = RequestInfo::new(Method::CONNECT, target);
    let mut headers = sanitized_headers(req.headers());

    match state.policy.evaluate(&request_info, &mut headers).await? {
        PolicyDecision::Deny(resp) => return Ok(immediate_response(resp.status, resp.body)),
        PolicyDecision::Continue { matched_rules } => {
            if !matched_rules.is_empty() {
                info!(
                    request_id = %request_info.request_id,
                    rules = ?matched_rules,
                    authority = %authority,
                    "connect policy applied"
                );
            }
        }
    }

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(err) = tunnel(upgraded, authority).await {
                    warn!(error = %err, "CONNECT tunnel failed");
                }
            }
            Err(err) => warn!(error = %err, "CONNECT upgrade failed"),
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|err| ProxyError::BadGateway(err.into()))
}

async fn tunnel(upgraded: hyper::upgrade::Upgraded, authority: String) -> anyhow::Result<()> {
    let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
    let mut server = TcpStream::connect(&authority)
        .await
        .with_context(|| format!("failed to connect to {authority}"))?;
    copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}

fn sanitized_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if name == http::header::PROXY_AUTHORIZATION
            || name.as_str().eq_ignore_ascii_case("proxy-connection")
            || name == http::header::CONNECTION
            || name == http::header::HOST
        {
            continue;
        }
        out.append(name, value.clone());
    }
    out
}

fn connect_target_url(uri: &Uri, authority: &str) -> anyhow::Result<Url> {
    if uri.scheme().is_some() {
        return Ok(Url::parse(&uri.to_string())?);
    }
    Ok(Url::parse(&format!("https://{authority}/"))?)
}

async fn response_from_upstream(upstream: reqwest::Response) -> Result<Response<Body>, ProxyError> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let body = upstream
        .bytes()
        .await
        .map_err(|err| ProxyError::BadGateway(err.into()))?;

    let mut response = Response::builder().status(status);
    for (name, value) in headers.iter() {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body))
        .map_err(|err| ProxyError::BadGateway(err.into()))
}

fn immediate_response(status: StatusCode, body: Bytes) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .expect("immediate response builder is valid")
}

#[derive(Debug)]
pub enum ProxyError {
    BadRequest(String),
    BadGateway(anyhow::Error),
}

impl From<anyhow::Error> for ProxyError {
    fn from(value: anyhow::Error) -> Self {
        Self::BadGateway(value)
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response<Body> {
        match self {
            ProxyError::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            ProxyError::BadGateway(err) => {
                error!(error = %err, "proxy request failed");
                (StatusCode::BAD_GATEWAY, "bad gateway\n").into_response()
            }
        }
    }
}
