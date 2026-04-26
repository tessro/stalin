use std::{
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use pingora::{
    apps::{HttpPersistentSettings, HttpServerApp, HttpServerOptions, ReusedHttpStream},
    connectors::http::Connector,
    http::{RequestHeader, ResponseHeader},
    protocols::{
        Digest, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, Ssl, Stream,
        UniqueID, UniqueIDType,
        http::{
            ServerSession, client::HttpSession as UpstreamHttpSession, v2::server as h2_server,
        },
        tls::ALPN,
    },
    server::{Server, ShutdownWatch},
    services::listening::Service,
    upstreams::peer::HttpPeer,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
    net::{TcpStream, lookup_host},
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use url::Url;

use crate::{
    audit::AuditLog,
    config::Config,
    mitm::MitmAuthority,
    policy::{PolicyDecision, PolicyEngine, RequestInfo, target_url_with_default_scheme},
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
        let mitm = MitmAuthority::from_config(&self.config.mitm)?.map(Arc::new);
        if mitm.is_some() {
            warn!("MITM TLS interception enabled for CONNECT sessions");
        }
        let mut options = HttpServerOptions::default();
        options.h2c = true;
        options.allow_connect_method_proxying = true;
        options.keepalive_request_limit = Some(10_000);

        let app = StalinPingoraApp {
            connector: Connector::new(None),
            mitm,
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
    mitm: Option<Arc<MitmAuthority>>,
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
            self.handle_connect(http, shutdown.clone()).await
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
        self.handle_request_with_default_scheme(http, "http").await
    }

    async fn handle_request_with_default_scheme(
        &self,
        http: &mut ServerSession,
        default_scheme: &str,
    ) -> Result<(), ProxyError> {
        let (method, mut target, protocol, mut outbound_headers) = {
            let req = http.req_header();
            (
                req.method.clone(),
                target_url_with_default_scheme(&req.uri, &req.headers, default_scheme)?,
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

        let peer = upstream_peer(&target).await?;
        let mut upstream_req = upstream_request(method, &target, &outbound_headers)?;
        set_host_header(&mut upstream_req, &target)?;

        let (mut upstream, _) = self.connector.get_http_session(&peer).await?;
        upstream
            .write_request_header(Box::new(upstream_req))
            .await?;
        stream_request_body(http, &mut upstream).await?;
        upstream.read_response_header().await?;

        write_upstream_response(http, &mut upstream).await?;
        self.connector
            .release_http_session(upstream, &peer, Some(std::time::Duration::from_secs(60)))
            .await;
        Ok(())
    }

    async fn handle_connect(
        self: &Arc<Self>,
        mut http: ServerSession,
        shutdown: ShutdownWatch,
    ) -> Result<Option<ServerSession>, ProxyError> {
        let (authority, cert_host, target, protocol, mut headers) = {
            let req = http.req_header();
            let authority = req.uri.authority().ok_or_else(|| {
                ProxyError::BadRequest("CONNECT request missing authority".to_string())
            })?;
            (
                authority.to_string(),
                authority.host().to_string(),
                connect_target_url(&req.uri, authority.as_str())?,
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
                if let Some(mitm) = &self.mitm {
                    let app = self.clone();
                    let mitm = mitm.clone();
                    tokio::spawn(async move {
                        if let Err(err) = app
                            .mitm_tls_session(downstream, mitm, cert_host, shutdown)
                            .await
                        {
                            warn!(error = %err, "MITM TLS session failed");
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        if let Err(err) = tunnel(downstream, authority).await {
                            warn!(error = %err, "CONNECT tunnel failed");
                        }
                    });
                }
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

    async fn mitm_tls_session(
        self: Arc<Self>,
        downstream: Stream,
        mitm: Arc<MitmAuthority>,
        cert_host: String,
        shutdown: ShutdownWatch,
    ) -> anyhow::Result<()> {
        let config = mitm.server_config_for_host(&cert_host)?;
        let tls = TlsAcceptor::from(config)
            .accept(downstream)
            .await
            .context("failed to accept downstream MITM TLS")?;
        let selected_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let stream: Stream = Box::new(TlsVirtualSocket(tls));

        if selected_h2 {
            self.process_mitm_h2(stream, shutdown).await?;
            return Ok(());
        }

        let mut result = self
            .process_mitm_http(ServerSession::new_http1(stream), &shutdown)
            .await;
        while let Some((stream, persistent_settings)) = result.map(|result| result.consume()) {
            let mut session = ServerSession::new_http1(stream);
            if let Some(persistent_settings) = persistent_settings {
                persistent_settings.apply_to_session(&mut session);
            }
            result = self.process_mitm_http(session, &shutdown).await;
        }
        Ok(())
    }

    async fn process_mitm_h2(
        self: Arc<Self>,
        stream: Stream,
        shutdown: ShutdownWatch,
    ) -> anyhow::Result<()> {
        let digest = Arc::new(Digest {
            ssl_digest: stream.get_ssl_digest(),
            timing_digest: stream.get_timing_digest(),
            proxy_digest: stream.get_proxy_digest(),
            socket_digest: stream.get_socket_digest(),
        });
        let mut h2_conn = h2_server::handshake(stream, self.h2_options())
            .await
            .map_err(|err| anyhow::anyhow!(err))
            .context("failed to accept downstream MITM h2")?;
        let mut shutdown = shutdown;

        loop {
            let h2_stream = tokio::select! {
                _ = shutdown.changed() => {
                    h2_conn.graceful_shutdown();
                    return Ok(());
                }
                h2_stream = h2_server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()) => h2_stream,
            };
            let h2_stream = h2_stream
                .map_err(|err| anyhow::anyhow!(err))
                .context("failed to accept downstream MITM h2 stream")?;
            let Some(h2_stream) = h2_stream else {
                return Ok(());
            };
            let app = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                app.process_mitm_http(ServerSession::new_http2(h2_stream), &shutdown)
                    .await;
            });
        }
    }

    async fn process_mitm_http(
        self: &Arc<Self>,
        mut http: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        match http.read_request().await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(err) => {
                error!(error = %err, "failed to read MITM downstream request");
                return None;
            }
        }

        if *shutdown.borrow() {
            http.set_keepalive(None);
        } else {
            http.set_keepalive(Some(60));
        }

        let result = if http.req_header().method == Method::CONNECT {
            write_immediate_response(
                &mut http,
                StatusCode::NOT_IMPLEMENTED,
                Bytes::from_static(b"nested CONNECT is not supported inside MITM TLS\n"),
            )
            .await
            .map(|()| Some(http))
        } else if http.is_upgrade_req() {
            self.handle_upgrade_with_default_scheme(http, "https").await
        } else {
            match self
                .handle_request_with_default_scheme(&mut http, "https")
                .await
            {
                Ok(()) => Ok(Some(http)),
                Err(err) => {
                    if let Err(write_err) = write_error_response(&mut http, &err).await {
                        error!(error = %write_err, "failed to write MITM proxy error response");
                    }
                    Ok(Some(http))
                }
            }
        };

        match result {
            Ok(Some(http)) => finish_session(http).await,
            Ok(None) => None,
            Err(err) => {
                error!(error = %err, "MITM proxy request failed");
                None
            }
        }
    }

    async fn handle_upgrade(
        &self,
        http: ServerSession,
    ) -> Result<Option<ServerSession>, ProxyError> {
        self.handle_upgrade_with_default_scheme(http, "http").await
    }

    async fn handle_upgrade_with_default_scheme(
        &self,
        http: ServerSession,
        default_scheme: &str,
    ) -> Result<Option<ServerSession>, ProxyError> {
        let (method, target, protocol, outbound_headers) = {
            let req = http.req_header();
            (
                req.method.clone(),
                target_url_with_default_scheme(&req.uri, &req.headers, default_scheme)?,
                protocol_name(req.version),
                sanitized_upgrade_headers(&req.headers),
            )
        };
        let request_info = RequestInfo::with_protocol(method.clone(), target.clone(), protocol);
        let mut policy_headers = outbound_headers.clone();

        match self
            .policy
            .evaluate(&request_info, &mut policy_headers)
            .await?
        {
            PolicyDecision::Deny(resp) => {
                let mut http = http;
                write_immediate_response(&mut http, resp.status, resp.body).await?;
                return Ok(Some(http));
            }
            PolicyDecision::Continue {
                matched_rules,
                upstream,
            } => {
                if upstream.is_some() {
                    let mut http = http;
                    write_immediate_response(
                        &mut http,
                        StatusCode::BAD_GATEWAY,
                        Bytes::from_static(b"upgrade requests cannot be routed yet\n"),
                    )
                    .await?;
                    return Ok(Some(http));
                }
                if !matched_rules.is_empty() {
                    info!(
                        request_id = %request_info.request_id,
                        rules = ?matched_rules,
                        url = %target,
                        "upgrade policy applied"
                    );
                }
            }
        }

        let ServerSession::H1(downstream) = http else {
            let mut http = http;
            write_immediate_response(
                &mut http,
                StatusCode::NOT_IMPLEMENTED,
                Bytes::from_static(b"upgrade proxying is only implemented for HTTP/1\n"),
            )
            .await?;
            return Ok(Some(http));
        };

        let peer = upstream_peer_with_version(&target, UpstreamVersion::Http1).await?;
        let mut upstream_req = upstream_request(method, &target, &policy_headers)?;
        set_host_header(&mut upstream_req, &target)?;
        let (mut upstream, _) = self.connector.get_http_session(&peer).await?;
        upstream
            .write_request_header(Box::new(upstream_req))
            .await?;
        upstream.finish_request_body().await?;
        upstream.read_response_header().await?;

        let Some(upstream_header) = upstream.response_header().cloned() else {
            return Err(ProxyError::BadGateway(anyhow::anyhow!(
                "upstream upgrade response missing header"
            )));
        };
        let upgraded = matches!(&upstream, UpstreamHttpSession::H1(h1) if h1.was_upgraded())
            && upstream_header.status == StatusCode::SWITCHING_PROTOCOLS;
        if !upgraded {
            let mut http = ServerSession::H1(downstream);
            write_upstream_response(&mut http, &mut upstream).await?;
            return Ok(Some(http));
        }

        let mut response = ResponseHeader::build_no_case(
            upstream_header.status,
            Some(upstream_header.headers.len()),
        )?;
        for (name, value) in upstream_header.headers.iter() {
            if should_skip_upgrade_response_header(name) {
                continue;
            }
            response.append_header(name, value.clone())?;
        }

        let mut http = ServerSession::H1(downstream);
        http.write_response_header(Box::new(response)).await?;
        let ServerSession::H1(downstream) = http else {
            unreachable!("session variant is unchanged");
        };
        let UpstreamHttpSession::H1(upstream) = upstream else {
            unreachable!("upgrade response required an HTTP/1 upstream session");
        };

        let downstream = downstream.into_inner();
        let upstream = upstream.into_inner();
        tokio::spawn(async move {
            if let Err(err) = tunnel_streams(downstream, upstream).await {
                warn!(error = %err, "upgrade tunnel failed");
            }
        });
        Ok(None)
    }
}

#[derive(Debug)]
struct TlsVirtualSocket(tokio_rustls::server::TlsStream<Stream>);

impl AsyncRead for TlsVirtualSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsVirtualSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for TlsVirtualSocket {
    async fn shutdown(&mut self) -> () {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.0).await;
    }
}

impl UniqueID for TlsVirtualSocket {
    fn id(&self) -> UniqueIDType {
        0
    }
}

impl Ssl for TlsVirtualSocket {
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        match self.0.get_ref().1.alpn_protocol() {
            Some(b"h2") => Some(ALPN::H2),
            Some(b"http/1.1") => Some(ALPN::H1),
            _ => None,
        }
    }
}

#[async_trait]
impl Peek for TlsVirtualSocket {}

impl GetTimingDigest for TlsVirtualSocket {
    fn get_timing_digest(&self) -> Vec<Option<pingora::protocols::TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for TlsVirtualSocket {
    fn get_proxy_digest(&self) -> Option<Arc<pingora::protocols::raw_connect::ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for TlsVirtualSocket {
    fn get_socket_digest(&self) -> Option<Arc<pingora::protocols::SocketDigest>> {
        None
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

async fn stream_request_body(
    http: &mut ServerSession,
    upstream: &mut pingora::protocols::http::client::HttpSession,
) -> Result<(), ProxyError> {
    while let Some(chunk) = http.read_request_body().await? {
        upstream.write_request_body(chunk, false).await?;
    }
    upstream.finish_request_body().await?;
    Ok(())
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

async fn tunnel_streams(
    mut downstream: pingora::protocols::Stream,
    mut upstream: pingora::protocols::Stream,
) -> anyhow::Result<()> {
    copy_bidirectional(&mut downstream, &mut upstream).await?;
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

fn sanitized_upgrade_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if name == http::header::PROXY_AUTHORIZATION
            || name.as_str().eq_ignore_ascii_case("proxy-connection")
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

fn should_skip_upgrade_response_header(name: &http::HeaderName) -> bool {
    name.as_str().eq_ignore_ascii_case("transfer-encoding")
}

async fn upstream_peer(target: &Url) -> Result<HttpPeer, ProxyError> {
    upstream_peer_with_version(target, UpstreamVersion::Http2Preferred).await
}

#[derive(Debug, Clone, Copy)]
enum UpstreamVersion {
    Http1,
    Http2Preferred,
}

async fn upstream_peer_with_version(
    target: &Url,
    version: UpstreamVersion,
) -> Result<HttpPeer, ProxyError> {
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
    let tls = matches!(target.scheme(), "https" | "wss");
    let mut peer = HttpPeer::new(addr, tls, host.to_string());
    match version {
        UpstreamVersion::Http1 => peer.options.set_http_version(1, 1),
        UpstreamVersion::Http2Preferred => peer.options.set_http_version(2, 1),
    }
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

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn upgrade_header_sanitization_preserves_upgrade_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("secret"),
        );
        headers.insert(http::header::HOST, HeaderValue::from_static("example.com"));

        let sanitized = sanitized_upgrade_headers(&headers);

        assert_eq!(
            sanitized.get(http::header::CONNECTION).unwrap(),
            HeaderValue::from_static("Upgrade")
        );
        assert_eq!(
            sanitized.get(http::header::UPGRADE).unwrap(),
            HeaderValue::from_static("websocket")
        );
        assert!(!sanitized.contains_key(http::header::PROXY_AUTHORIZATION));
        assert!(!sanitized.contains_key(http::header::HOST));
    }

    #[test]
    fn upstream_request_uses_origin_form_path_and_query() {
        let target = Url::parse("http://example.com/socket?token=abc").unwrap();
        let request = upstream_request(Method::GET, &target, &HeaderMap::new()).unwrap();

        assert_eq!(request.uri, "/socket?token=abc");
    }

    #[test]
    fn host_header_includes_explicit_port() {
        let target = Url::parse("http://example.com:8080/").unwrap();
        let mut request = upstream_request(Method::GET, &target, &HeaderMap::new()).unwrap();

        set_host_header(&mut request, &target).unwrap();

        assert_eq!(
            request.headers.get(http::header::HOST).unwrap(),
            HeaderValue::from_static("example.com:8080")
        );
    }
}
