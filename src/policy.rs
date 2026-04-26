use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use url::Url;
use uuid::Uuid;

use crate::{
    audit::{AuditEvent, AuditLog},
    config::{Config, DenyConfig, HeaderPatchConfig, HeaderValueConfig, MatchConfig, RuleConfig},
    oauth::OAuthRefreshTokenProvider,
    plugin::{
        PluginBodyDoneResult, PluginBodyPolicy, PluginHeaderPatch, PluginResponseHeadersResult,
        PluginResult, PluginRuntime,
    },
    secrets::SecretStore,
};

#[derive(Clone)]
pub struct PolicyEngine {
    rules: Vec<RuleConfig>,
    secrets: SecretStore,
    oauth: OAuthRefreshTokenProvider,
    audit: AuditLog,
    plugins: Option<PluginRuntime>,
}

impl PolicyEngine {
    pub fn new(config: Config, audit: AuditLog) -> anyhow::Result<Self> {
        let secrets = SecretStore::new(config.secrets.clone());
        let plugins = PluginRuntime::new(config.plugins, secrets.clone(), audit.clone())?;
        Ok(Self {
            rules: config.rules,
            secrets,
            oauth: OAuthRefreshTokenProvider::new()?,
            audit,
            plugins,
        })
    }

    pub async fn evaluate(
        &self,
        req: &RequestInfo,
        headers: &mut HeaderMap,
    ) -> anyhow::Result<PolicyDecision> {
        let mut matched_rules = Vec::new();
        for rule in &self.rules {
            if !matches_rule(&rule.matcher, req) {
                continue;
            }

            matched_rules.push(rule.name.clone());
            if rule.audit {
                self.audit
                    .write(&AuditEvent {
                        r#type: "rule.match",
                        level: "info",
                        request_id: &req.request_id,
                        connection_id: &req.connection_id,
                        method: req.method.as_str(),
                        url: req.url.as_str(),
                        matched_rule: Some(&rule.name),
                        message: Some("request matched policy rule"),
                    })
                    .await?;
            }

            if let Some(deny) = &rule.deny {
                return Ok(PolicyDecision::Deny(deny_response(deny)));
            }

            apply_patch(headers, &rule.request_headers, &self.secrets, &self.oauth).await?;
        }

        let mut upstream = None;
        let mut body_policy = None;
        if let Some(plugins) = &self.plugins {
            for outcome in plugins.on_request_headers(req, headers).await? {
                if let Some(policy) = outcome.result.body_policy() {
                    body_policy = merge_body_policy(body_policy, policy);
                }
                match &outcome.result {
                    PluginResult::Continue { .. } => {
                        if let Some(patch) = outcome.result.patches() {
                            apply_plugin_patch(headers, patch, &self.secrets)?;
                        }
                        matched_rules.push(format!("plugin:{}", outcome.plugin_name));
                    }
                    PluginResult::Route {
                        upstream: route_upstream,
                        ..
                    } => {
                        if let Some(patch) = outcome.result.patches() {
                            apply_plugin_patch(headers, patch, &self.secrets)?;
                        }
                        upstream = Some(Url::parse(route_upstream)?);
                        matched_rules.push(format!("plugin:{}", outcome.plugin_name));
                    }
                    PluginResult::Deny {
                        status,
                        body,
                        headers,
                    }
                    | PluginResult::Respond {
                        status,
                        body,
                        headers,
                    } => {
                        return Ok(PolicyDecision::Deny(plugin_immediate_response(
                            *status,
                            StatusCode::FORBIDDEN,
                            body,
                            headers,
                            &self.secrets,
                        )?));
                    }
                }
            }
        }

        Ok(PolicyDecision::Continue {
            matched_rules,
            upstream,
            body_policy,
        })
    }

    pub async fn observe_request_body_data(
        &self,
        req: &RequestInfo,
        index: usize,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(plugins) = &self.plugins {
            plugins
                .on_request_body_data(req, index, bytes, content_type)
                .await?;
        }
        Ok(())
    }

    pub async fn finish_request_body(
        &self,
        req: &RequestInfo,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> anyhow::Result<BodyDecision> {
        let Some(plugins) = &self.plugins else {
            return Ok(BodyDecision::Continue { replacement: None });
        };

        let mut replacement = None;
        for outcome in plugins
            .on_request_body_done(req, bytes_seen, chunks_seen, body, content_type)
            .await?
        {
            match outcome.result {
                PluginBodyDoneResult::Continue => {}
                PluginBodyDoneResult::Replace { body } => {
                    replacement = Some(Bytes::from(body.into_bytes()));
                }
                PluginBodyDoneResult::Deny {
                    status,
                    body,
                    headers,
                }
                | PluginBodyDoneResult::Respond {
                    status,
                    body,
                    headers,
                } => {
                    return Ok(BodyDecision::Deny(plugin_immediate_response(
                        status,
                        StatusCode::FORBIDDEN,
                        &body,
                        &headers,
                        &self.secrets,
                    )?));
                }
            }
        }

        Ok(BodyDecision::Continue { replacement })
    }

    pub async fn evaluate_response_headers(
        &self,
        req: &RequestInfo,
        status: StatusCode,
        headers: &mut HeaderMap,
    ) -> anyhow::Result<ResponseDecision> {
        let Some(plugins) = &self.plugins else {
            return Ok(ResponseDecision::Continue { body_policy: None });
        };

        let mut body_policy = None;
        for outcome in plugins
            .on_response_headers(req, status.as_u16(), headers)
            .await?
        {
            if let Some(policy) = outcome.result.body_policy() {
                body_policy = merge_body_policy(body_policy, policy);
            }
            match &outcome.result {
                PluginResponseHeadersResult::Continue { .. } => {
                    if let Some(patch) = outcome.result.patches() {
                        apply_plugin_patch(headers, patch, &self.secrets)?;
                    }
                }
                PluginResponseHeadersResult::Respond {
                    status,
                    body,
                    headers,
                } => {
                    return Ok(ResponseDecision::Respond(plugin_immediate_response(
                        *status,
                        StatusCode::OK,
                        body,
                        headers,
                        &self.secrets,
                    )?));
                }
            }
        }

        Ok(ResponseDecision::Continue { body_policy })
    }

    pub async fn observe_response_body_data(
        &self,
        req: &RequestInfo,
        index: usize,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(plugins) = &self.plugins {
            plugins
                .on_response_body_data(req, index, bytes, content_type)
                .await?;
        }
        Ok(())
    }

    pub async fn finish_response_body(
        &self,
        req: &RequestInfo,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> anyhow::Result<BodyDecision> {
        let Some(plugins) = &self.plugins else {
            return Ok(BodyDecision::Continue { replacement: None });
        };

        let mut replacement = None;
        for outcome in plugins
            .on_response_body_done(req, bytes_seen, chunks_seen, body, content_type)
            .await?
        {
            match outcome.result {
                PluginBodyDoneResult::Continue => {}
                PluginBodyDoneResult::Replace { body } => {
                    replacement = Some(Bytes::from(body.into_bytes()));
                }
                PluginBodyDoneResult::Deny {
                    status,
                    body,
                    headers,
                }
                | PluginBodyDoneResult::Respond {
                    status,
                    body,
                    headers,
                } => {
                    return Ok(BodyDecision::Deny(plugin_immediate_response(
                        status,
                        StatusCode::FORBIDDEN,
                        &body,
                        &headers,
                        &self.secrets,
                    )?));
                }
            }
        }

        Ok(BodyDecision::Continue { replacement })
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub request_id: String,
    pub connection_id: String,
    pub method: Method,
    pub url: Url,
    pub protocol: &'static str,
}

impl RequestInfo {
    pub fn new(method: Method, url: Url) -> Self {
        Self::with_protocol(method, url, "http/1.1")
    }

    pub fn with_protocol(method: Method, url: Url, protocol: &'static str) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            connection_id: Uuid::new_v4().to_string(),
            method,
            url,
            protocol,
        }
    }
}

#[derive(Debug)]
pub enum PolicyDecision {
    Continue {
        matched_rules: Vec<String>,
        upstream: Option<Url>,
        body_policy: Option<PluginBodyPolicy>,
    },
    Deny(ImmediateResponse),
}

#[derive(Debug)]
pub enum BodyDecision {
    Continue { replacement: Option<Bytes> },
    Deny(ImmediateResponse),
}

#[derive(Debug)]
pub enum ResponseDecision {
    Continue {
        body_policy: Option<PluginBodyPolicy>,
    },
    Respond(ImmediateResponse),
}

#[derive(Debug)]
pub struct ImmediateResponse {
    pub status: StatusCode,
    pub body: Bytes,
    pub headers: HeaderMap,
}

fn deny_response(deny: &DenyConfig) -> ImmediateResponse {
    ImmediateResponse {
        status: StatusCode::from_u16(deny.status).unwrap_or(StatusCode::FORBIDDEN),
        body: Bytes::from(
            deny.body
                .clone()
                .unwrap_or_else(|| "request denied by Stalin policy\n".to_string()),
        ),
        headers: HeaderMap::new(),
    }
}

fn plugin_immediate_response(
    status: u16,
    default_status: StatusCode,
    body: &Option<crate::plugin::PluginBody>,
    headers: &serde_json::Map<String, serde_json::Value>,
    secrets: &SecretStore,
) -> anyhow::Result<ImmediateResponse> {
    Ok(ImmediateResponse {
        status: StatusCode::from_u16(status).unwrap_or(default_status),
        body: Bytes::from(
            body.clone()
                .map(crate::plugin::PluginBody::into_bytes)
                .unwrap_or_default(),
        ),
        headers: plugin_response_headers(headers, secrets)?,
    })
}

fn plugin_response_headers(
    headers: &serde_json::Map<String, serde_json::Value>,
    secrets: &SecretStore,
) -> anyhow::Result<HeaderMap> {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        out.append(header_name(name)?, plugin_header_value(value, secrets)?);
    }
    Ok(out)
}

fn merge_body_policy(
    current: Option<PluginBodyPolicy>,
    next: &PluginBodyPolicy,
) -> Option<PluginBodyPolicy> {
    if !next.is_buffered() {
        return current;
    }

    let mut next = next.clone();
    if let Some(current) = current
        && current.is_buffered()
    {
        next.max_bytes = Some(current.max_bytes().min(next.max_bytes()));
    }
    Some(next)
}

fn matches_rule(matcher: &MatchConfig, req: &RequestInfo) -> bool {
    if let Some(method) = &matcher.method
        && method.to_uppercase() != req.method.as_str()
    {
        return false;
    }
    if let Some(scheme) = &matcher.scheme
        && scheme != req.url.scheme()
    {
        return false;
    }
    if let Some(host) = &matcher.host
        && !host_matches(host, req.url.host_str().unwrap_or_default())
    {
        return false;
    }
    if let Some(path_prefix) = &matcher.path_prefix
        && !req.url.path().starts_with(path_prefix)
    {
        return false;
    }
    true
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

async fn apply_patch(
    headers: &mut HeaderMap,
    patch: &HeaderPatchConfig,
    secrets: &SecretStore,
    oauth: &OAuthRefreshTokenProvider,
) -> anyhow::Result<()> {
    for name in &patch.remove {
        headers.remove(header_name(name)?);
    }

    for (name, value) in &patch.set {
        headers.insert(
            header_name(name)?,
            header_value(value, secrets, oauth).await?,
        );
    }

    for (name, value) in &patch.add {
        headers.append(
            header_name(name)?,
            header_value(value, secrets, oauth).await?,
        );
    }

    Ok(())
}

fn apply_plugin_patch(
    headers: &mut HeaderMap,
    patch: PluginHeaderPatch<'_>,
    secrets: &SecretStore,
) -> anyhow::Result<()> {
    for name in patch.remove_headers {
        headers.remove(header_name(name)?);
    }

    for (name, value) in patch.set_headers {
        headers.insert(header_name(name)?, plugin_header_value(value, secrets)?);
    }

    for (name, value) in patch.add_headers {
        headers.append(header_name(name)?, plugin_header_value(value, secrets)?);
    }

    Ok(())
}

fn header_name(name: &str) -> anyhow::Result<HeaderName> {
    Ok(HeaderName::from_bytes(name.as_bytes())?)
}

async fn header_value(
    value: &HeaderValueConfig,
    secrets: &SecretStore,
    oauth: &OAuthRefreshTokenProvider,
) -> anyhow::Result<HeaderValue> {
    let raw = match value {
        HeaderValueConfig::Literal(value) => value.clone(),
        HeaderValueConfig::Secret { secret, format } => {
            let secret = secrets.text(secret)?;
            format.replace("{value}", &secret)
        }
        HeaderValueConfig::OAuthRefreshToken {
            oauth_refresh_token,
            format,
        } => {
            let access_token = oauth.access_token(oauth_refresh_token).await?;
            format.replace("{value}", &access_token)
        }
    };
    Ok(HeaderValue::from_str(&raw)?)
}

fn plugin_header_value(
    value: &serde_json::Value,
    secrets: &SecretStore,
) -> anyhow::Result<HeaderValue> {
    let raw = match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Object(object) => {
            let secret_name = object
                .get("secret")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("plugin header object must include `secret`"))?;
            let format = object
                .get("format")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("{value}");
            format.replace("{value}", &secrets.text(secret_name)?)
        }
        _ => anyhow::bail!("plugin header value must be a string or secret object"),
    };
    Ok(HeaderValue::from_str(&raw)?)
}

pub fn target_url(uri: &Uri, headers: &HeaderMap) -> anyhow::Result<Url> {
    target_url_with_default_scheme(uri, headers, "http")
}

pub fn target_url_with_default_scheme(
    uri: &Uri,
    headers: &HeaderMap,
    default_scheme: &str,
) -> anyhow::Result<Url> {
    if uri.scheme().is_some() {
        return Ok(Url::parse(uri.to_string().trim_start_matches('/'))?);
    }

    let host = headers
        .get(http::header::HOST)
        .ok_or_else(|| anyhow::anyhow!("origin-form request is missing Host header"))?
        .to_str()?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Ok(Url::parse(&format!("{default_scheme}://{host}{path}"))?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::config::{HeaderValueConfig, SecretConfig};

    use super::*;

    #[test]
    fn wildcard_host_matches_base_and_subdomains() {
        assert!(host_matches("*.example.com", "example.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
    }

    #[test]
    fn target_url_supports_origin_form() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("example.com"));
        let url = target_url(&"/v1?a=b".parse().unwrap(), &headers).unwrap();
        assert_eq!(url.as_str(), "http://example.com/v1?a=b");
    }

    #[test]
    fn target_url_supports_absolute_form() {
        let headers = HeaderMap::new();
        let url = target_url(&"http://example.com/v1?a=b".parse().unwrap(), &headers).unwrap();
        assert_eq!(url.as_str(), "http://example.com/v1?a=b");
    }

    #[test]
    fn target_url_uses_default_scheme_for_origin_form() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("example.com"));
        let url =
            target_url_with_default_scheme(&"/v1?a=b".parse().unwrap(), &headers, "https").unwrap();
        assert_eq!(url.as_str(), "https://example.com/v1?a=b");
    }

    #[tokio::test]
    async fn header_patch_sets_literals_and_removes() {
        let mut headers = HeaderMap::new();
        headers.insert("x-old", HeaderValue::from_static("1"));
        let patch = HeaderPatchConfig {
            set: HashMap::from([(
                "x-new".to_string(),
                HeaderValueConfig::Literal("2".to_string()),
            )]),
            add: HashMap::new(),
            remove: vec!["x-old".to_string()],
        };
        let secrets = SecretStore::new(HashMap::<String, SecretConfig>::new());
        let oauth = OAuthRefreshTokenProvider::new().unwrap();

        apply_patch(&mut headers, &patch, &secrets, &oauth)
            .await
            .unwrap();

        assert!(!headers.contains_key("x-old"));
        assert_eq!(headers.get("x-new").unwrap(), "2");
    }

    #[test]
    fn plugin_immediate_response_preserves_headers() {
        let secrets = SecretStore::new(HashMap::<String, SecretConfig>::new());
        let headers = serde_json::Map::from_iter([(
            "x-denied-by".to_string(),
            serde_json::Value::String("plugin".to_string()),
        )]);

        let response = plugin_immediate_response(
            418,
            StatusCode::FORBIDDEN,
            &Some(crate::plugin::PluginBody::Text("nope".to_string())),
            &headers,
            &secrets,
        )
        .unwrap();

        assert_eq!(response.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(response.body, Bytes::from_static(b"nope"));
        assert_eq!(response.headers.get("x-denied-by").unwrap(), "plugin");
    }
}
