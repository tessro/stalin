use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use url::Url;
use uuid::Uuid;

use crate::{
    audit::{AuditEvent, AuditLog},
    config::{Config, DenyConfig, HeaderPatchConfig, HeaderValueConfig, MatchConfig, RuleConfig},
    plugin::{PluginHeaderPatch, PluginResult, PluginRuntime},
    secrets::SecretStore,
};

#[derive(Clone)]
pub struct PolicyEngine {
    rules: Vec<RuleConfig>,
    secrets: SecretStore,
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

            apply_patch(headers, &rule.request_headers, &self.secrets)?;
        }

        let mut upstream = None;
        if let Some(plugins) = &self.plugins {
            for outcome in plugins.on_request_headers(req, headers).await? {
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
                    PluginResult::Deny { status, body }
                    | PluginResult::Respond { status, body } => {
                        return Ok(PolicyDecision::Deny(ImmediateResponse {
                            status: StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN),
                            body: Bytes::from(body.clone().unwrap_or_default()),
                        }));
                    }
                }
            }
        }

        Ok(PolicyDecision::Continue {
            matched_rules,
            upstream,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub request_id: String,
    pub connection_id: String,
    pub method: Method,
    pub url: Url,
}

impl RequestInfo {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            connection_id: Uuid::new_v4().to_string(),
            method,
            url,
        }
    }
}

#[derive(Debug)]
pub enum PolicyDecision {
    Continue {
        matched_rules: Vec<String>,
        upstream: Option<Url>,
    },
    Deny(ImmediateResponse),
}

#[derive(Debug)]
pub struct ImmediateResponse {
    pub status: StatusCode,
    pub body: Bytes,
}

fn deny_response(deny: &DenyConfig) -> ImmediateResponse {
    ImmediateResponse {
        status: StatusCode::from_u16(deny.status).unwrap_or(StatusCode::FORBIDDEN),
        body: Bytes::from(
            deny.body
                .clone()
                .unwrap_or_else(|| "request denied by Stalin policy\n".to_string()),
        ),
    }
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

fn apply_patch(
    headers: &mut HeaderMap,
    patch: &HeaderPatchConfig,
    secrets: &SecretStore,
) -> anyhow::Result<()> {
    for name in &patch.remove {
        headers.remove(header_name(name)?);
    }

    for (name, value) in &patch.set {
        headers.insert(header_name(name)?, header_value(value, secrets)?);
    }

    for (name, value) in &patch.add {
        headers.append(header_name(name)?, header_value(value, secrets)?);
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

fn header_value(value: &HeaderValueConfig, secrets: &SecretStore) -> anyhow::Result<HeaderValue> {
    let raw = match value {
        HeaderValueConfig::Literal(value) => value.clone(),
        HeaderValueConfig::Secret { secret, format } => {
            let secret = secrets.text(secret)?;
            format.replace("{value}", &secret)
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
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(Url::parse(&uri.to_string())?);
    }

    let host = headers
        .get(http::header::HOST)
        .ok_or_else(|| anyhow::anyhow!("origin-form request is missing Host header"))?
        .to_str()?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Ok(Url::parse(&format!("http://{host}{path}"))?)
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
    fn header_patch_sets_literals_and_removes() {
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

        apply_patch(&mut headers, &patch, &secrets).unwrap();

        assert!(!headers.contains_key("x-old"));
        assert_eq!(headers.get("x-new").unwrap(), "2");
    }
}
