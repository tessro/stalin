use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use pingora::{
    apps::{HttpPersistentSettings, HttpServerApp, HttpServerOptions, ReusedHttpStream},
    connectors::http::Connector,
    http::{RequestHeader, ResponseHeader},
    protocols::http::ServerSession,
    server::Server,
    services::listening::Service,
    upstreams::peer::HttpPeer,
};
use tokio::{io::copy_bidirectional, net::TcpStream, net::lookup_host};
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

    pub fn serve(self) -> anyhow::Result<()> {
        let listen = self.config.listen;
        let audit = AuditLog::new(self.config.audit_log.as_deref())?;
        let mut options = HttpServerOptions::default();
        options.h2c = true;
        options.allow_connect_method_proxying = true;
        options.keepalive_request_limit = Some(10_000);

        let app = StalinPingoraApp {
            connector: Connector::new(None),
            policy: PolicyEngine::new(self.config, audit)?,
            options,
        };

        let mut server = Server::new(None)?;
        server.bootstrap();

        let mut service = Service::new("stalin pingora proxy".to_string(), app);
        service.add_tcp(&listen.to_string());
        server.add_service(service);

        info!(%listen, "stalin pingora proxy listening");
        server.run_forever();
    }
}

struct StalinPingoraApp {
    connector: Connector,
    policy: PolicyEngine,
    options: HttpServerOptions,
}

#[async_trait]
impl HttpServerApp for StalinPingoraApp {
    async fn process_new_http(
        self: &Arc<Self>,
        mut http: ServerSession,
        shutdown: &pingora::server::ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        match http.read_request().await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(err) => {
                error!(error = %err, "failed to read downstream request");
                return None;
            }
        }

        if *shutdown.borrow() {
            http.set_keepalive(None);
        } else {
            http.set_keepalive(Some(60));
        }

        let result = if http.req_header().method == Method::CONNECT {
            self.handle_connect(http).await
        } else if http.is_upgrade_req() {
            self.handle_upgrade(http).await
        } else {
            match self.handle_request(&mut http).await {
                Ok(()) => Ok(Some(http)),
                Err(err) => {
                    if let Err(write_err) = write_error_response(&mut http, &err).await {
                        error!(error = %write_err, "failed to write proxy error response");
                    }
                    Ok(Some(http))
                }
            }
        };

        match result {
            Ok(Some(http)) => finish_session(http).await,
            Ok(None) => None,
            Err(err) => {
                error!(error = %err, "proxy request failed");
                None
            }
        }
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        Some(&self.options)
    }
}

impl StalinPingoraApp {
    async fn handle_request(&self, http: &mut ServerSession) -> Result<(), ProxyError> {
        let (method, mut target, protocol, mut outbound_headers) = {
            let req = http.req_header();
            (
                req.method.clone(),
                target_url(&req.uri, &req.headers)?,
                protocol_name(req.version),
                sanitized_headers(&req.headers),
            )
        };
        let request_info = RequestInfo::with_protocol(method.clone(), target.clone(), protocol);

        match self
            .policy
            .evaluate(&request_info, &mut outbound_headers)
            .await?
        {
            PolicyDecision::Deny(resp) => {
                write_immediate_response(http, resp.status, resp.body).await?;
                return Ok(());
            }
            PolicyDecision::Continue {
                matched_rules,
                upstream,
            } => {
                if let Some(upstream) = upstream {
                    target = routed_url(upstream, &target);
                }
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

        let body = read_body(http).await?;
        let peer = upstream_peer(&target).await?;
        let mut upstream_req = upstream_request(method, &target, &outbound_headers)?;
        set_host_header(&mut upstream_req, &target)?;

        let (mut upstream, _) = self.connector.get_http_session(&peer).await?;
        upstream
            .write_request_header(Box::new(upstream_req))
            .await?;
        if !body.is_empty() {
            upstream.write_request_body(body.freeze(), true).await?;
        }
        upstream.finish_request_body().await?;
        upstream.read_response_header().await?;

        write_upstream_response(http, &mut upstream).await?;
        self.connector
            .release_http_session(upstream, &peer, Some(std::time::Duration::from_secs(60)))
            .await;
        Ok(())
    }

    async fn handle_connect(
        &self,
        mut http: ServerSession,
    ) -> Result<Option<ServerSession>, ProxyError> {
        let (authority, target, protocol, mut headers) = {
            let req = http.req_header();
            let authority = req
                .uri
                .authority()
                .ok_or_else(|| {
                    ProxyError::BadRequest("CONNECT request missing authority".to_string())
                })?
                .to_string();
            (
                authority.clone(),
                connect_target_url(&req.uri, &authority)?,
                protocol_name(req.version),
                sanitized_headers(&req.headers),
            )
        };
        let request_info = RequestInfo::with_protocol(Method::CONNECT, target, protocol);

        match self.policy.evaluate(&request_info, &mut headers).await? {
            PolicyDecision::Deny(resp) => {
                write_immediate_response(&mut http, resp.status, resp.body).await?;
                return Ok(Some(http));
            }
            PolicyDecision::Continue { matched_rules, .. } => {
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

        match http {
            ServerSession::H1(session) => {
                let mut response = ResponseHeader::build_no_case(StatusCode::OK, Some(0))?;
                response.set_content_length(0)?;
                let mut http = ServerSession::H1(session);
                http.write_response_header(Box::new(response)).await?;
                let ServerSession::H1(session) = http else {
                    unreachable!("session variant is unchanged");
                };
                let downstream = session.into_inner();
                tokio::spawn(async move {
                    if let Err(err) = tunnel(downstream, authority).await {
                        warn!(error = %err, "CONNECT tunnel failed");
                    }
                });
                Ok(None)
            }
            mut http => {
                warn!("CONNECT tunneling is only implemented for HTTP/1 downstream sessions");
                write_immediate_response(
                    &mut http,
                    StatusCode::NOT_IMPLEMENTED,
                    Bytes::from_static(b"CONNECT tunneling is only implemented for HTTP/1\n"),
                )
                .await?;
                Ok(Some(http))
            }
        }
    }

    async fn handle_upgrade(
        &self,
        mut http: ServerSession,
    ) -> Result<Option<ServerSession>, ProxyError> {
        write_immediate_response(
            &mut http,
            StatusCode::NOT_IMPLEMENTED,
            Bytes::from_static(b"websocket proxying is not implemented yet\n"),
        )
        .await?;
        Ok(Some(http))
    }
}

async fn finish_session(http: ServerSession) -> Option<ReusedHttpStream> {
    let persistent_settings = HttpPersistentSettings::for_session(&http);
    match http.finish().await {
        Ok(stream) => stream.map(|stream| ReusedHttpStream::new(stream, Some(persistent_settings))),
        Err(err) => {
            error!(error = %err, "failed to finish downstream request");
            None
        }
    }
}

async fn read_body(http: &mut ServerSession) -> Result<BytesMut, ProxyError> {
    let mut body = BytesMut::new();
    while let Some(chunk) = http.read_request_body().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn write_upstream_response(
    http: &mut ServerSession,
    upstream: &mut pingora::protocols::http::client::HttpSession,
) -> Result<(), ProxyError> {
    let upstream_header = upstream
        .response_header()
        .ok_or_else(|| ProxyError::BadGateway(anyhow::anyhow!("upstream response missing header")))?
        .clone();

    let mut response =
        ResponseHeader::build_no_case(upstream_header.status, Some(upstream_header.headers.len()))?;
    for (name, value) in upstream_header.headers.iter() {
        if should_skip_response_header(name) {
            continue;
        }
        response.append_header(name, value.clone())?;
    }

    http.write_response_header(Box::new(response)).await?;
    while let Some(chunk) = upstream.read_response_body().await? {
        http.write_response_body(chunk, false).await?;
    }
    http.write_response_body(Bytes::new(), true).await?;
    Ok(())
}

async fn write_immediate_response(
    http: &mut ServerSession,
    status: StatusCode,
    body: Bytes,
) -> Result<(), ProxyError> {
    let mut response = ResponseHeader::build_no_case(status, Some(1))?;
    response.set_content_length(body.len())?;
    http.write_response_header(Box::new(response)).await?;
    http.write_response_body(body, true).await?;
    Ok(())
}

async fn write_error_response(
    http: &mut ServerSession,
    err: &ProxyError,
) -> Result<(), ProxyError> {
    match err {
        ProxyError::BadRequest(message) => {
            write_immediate_response(http, StatusCode::BAD_REQUEST, Bytes::from(message.clone()))
                .await
        }
        ProxyError::BadGateway(err) => {
            error!(error = %err, "proxy request failed");
            write_immediate_response(
                http,
                StatusCode::BAD_GATEWAY,
                Bytes::from_static(b"bad gateway\n"),
            )
            .await
        }
    }
}

async fn tunnel(
    mut downstream: pingora::protocols::Stream,
    authority: String,
) -> anyhow::Result<()> {
    let mut server = TcpStream::connect(&authority)
        .await
        .with_context(|| format!("failed to connect to {authority}"))?;
    copy_bidirectional(&mut downstream, &mut server).await?;
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

fn should_skip_response_header(name: &http::HeaderName) -> bool {
    name == http::header::CONNECTION || name.as_str().eq_ignore_ascii_case("transfer-encoding")
}

async fn upstream_peer(target: &Url) -> Result<HttpPeer, ProxyError> {
    let host = target
        .host_str()
        .ok_or_else(|| ProxyError::BadRequest("target URL is missing a host".to_string()))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| ProxyError::BadRequest("target URL is missing a port".to_string()))?;
    let mut addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve upstream {host}:{port}"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("upstream {host}:{port} resolved to no addresses"))?;
    let tls = target.scheme() == "https";
    let mut peer = HttpPeer::new(addr, tls, host.to_string());
    peer.options.set_http_version(2, 1);
    Ok(peer)
}

fn upstream_request(
    method: Method,
    target: &Url,
    headers: &HeaderMap,
) -> Result<RequestHeader, ProxyError> {
    let mut path = target.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = target.query() {
        path.push('?');
        path.push_str(query);
    }
    let mut request = RequestHeader::build(method, path.as_bytes(), Some(headers.len() + 1))?;
    for (name, value) in headers.iter() {
        request.append_header(name, value.clone())?;
    }
    Ok(request)
}

fn set_host_header(request: &mut RequestHeader, target: &Url) -> Result<(), ProxyError> {
    let host = target
        .host_str()
        .ok_or_else(|| ProxyError::BadRequest("target URL is missing a host".to_string()))?;
    let host = match target.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    request.insert_header(http::header::HOST, host)?;
    Ok(())
}

fn protocol_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => "http/1.1",
        Version::HTTP_2 => "h2",
        Version::HTTP_3 => "h3",
        _ => "http/1.1",
    }
}

fn connect_target_url(uri: &Uri, authority: &str) -> anyhow::Result<Url> {
    if uri.scheme().is_some() {
        return Ok(Url::parse(&uri.to_string())?);
    }
    Ok(Url::parse(&format!("https://{authority}/"))?)
}

fn routed_url(mut upstream: Url, original: &Url) -> Url {
    if upstream.path() == "/" && upstream.query().is_none() {
        upstream.set_path(original.path());
        upstream.set_query(original.query());
    }
    upstream
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("bad gateway: {0}")]
    BadGateway(anyhow::Error),
}

impl From<anyhow::Error> for ProxyError {
    fn from(value: anyhow::Error) -> Self {
        Self::BadGateway(value)
    }
}

impl From<Box<pingora::Error>> for ProxyError {
    fn from(value: Box<pingora::Error>) -> Self {
        Self::BadGateway(value.into())
    }
}
