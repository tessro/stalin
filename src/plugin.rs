use std::{
    collections::HashMap,
    convert::TryFrom,
    path::PathBuf,
    process::Command,
    sync::{LazyLock, Mutex, Once},
};

use anyhow::{Context, anyhow};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task;
use tracing::warn;
use url::Url;
use uuid::Uuid;

use crate::{
    audit::{AuditEvent, AuditLog},
    config::PluginConfig,
    policy::RequestInfo,
    secrets::SecretStore,
};

static V8_INIT: Once = Once::new();
static HOST_STATE: LazyLock<HostState> = LazyLock::new(HostState::new);

struct HostState {
    session: Mutex<HashMap<String, Value>>,
    http: reqwest::blocking::Client,
}

impl HostState {
    fn new() -> Self {
        let http = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("plugin host HTTP client can be built");
        Self {
            session: Mutex::new(HashMap::new()),
            http,
        }
    }
}

#[derive(Clone)]
pub struct PluginRuntime {
    plugins: Vec<LoadedPlugin>,
    secrets: SecretStore,
    audit: AuditLog,
}

impl PluginRuntime {
    pub fn new(
        configs: Vec<PluginConfig>,
        secrets: SecretStore,
        audit: AuditLog,
    ) -> anyhow::Result<Option<Self>> {
        let mut plugins = Vec::new();
        for config in configs {
            let Some(source) = bundle_plugin_source(&config) else {
                continue;
            };
            plugins.push(LoadedPlugin {
                name: config.name,
                version: config.version,
                path: config.path,
                source,
                config: config
                    .config
                    .map(serde_json::to_value)
                    .transpose()?
                    .unwrap_or(Value::Null),
            });
        }

        if plugins.is_empty() {
            Ok(None)
        } else {
            init_v8();
            Ok(Some(Self {
                plugins,
                secrets,
                audit,
            }))
        }
    }

    pub async fn on_request_headers(
        &self,
        req: &RequestInfo,
        headers: &HeaderMap,
    ) -> anyhow::Result<Vec<PluginOutcome>> {
        let mut outcomes = Vec::new();
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input = PluginInput::new(req, headers);
            let output =
                task::spawn_blocking(move || run_request_headers_plugin(plugin, secrets, input))
                    .await
                    .context("plugin task panicked")??;

            for event in output.audit_events {
                self.audit
                    .write(&AuditEvent {
                        r#type: event
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("plugin.audit"),
                        level: event.get("level").and_then(Value::as_str).unwrap_or("info"),
                        request_id: &req.request_id,
                        connection_id: &req.connection_id,
                        method: req.method.as_str(),
                        url: req.url.as_str(),
                        matched_rule: Some(&plugin_name),
                        message: event.get("message").and_then(Value::as_str),
                    })
                    .await?;
            }

            outcomes.push(PluginOutcome {
                plugin_name,
                result: output.result.unwrap_or_default(),
            });
        }
        Ok(outcomes)
    }

    pub async fn on_request_body_data(
        &self,
        req: &RequestInfo,
        index: usize,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> anyhow::Result<()> {
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input = BodyDataInput::new(req, index, bytes, content_type);
            let output: PluginBodyOutput = task::spawn_blocking(move || {
                run_plugin_hook(plugin, secrets, input, "onRequestBodyData")
            })
            .await
            .context("plugin task panicked")??;

            self.write_audit_events(req, &plugin_name, output.audit_events)
                .await?;
        }
        Ok(())
    }

    pub async fn on_response_body_data(
        &self,
        req: &RequestInfo,
        index: usize,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> anyhow::Result<()> {
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input =
                BodyDataInput::new_with_direction(req, "response", index, bytes, content_type);
            let output: PluginBodyOutput = task::spawn_blocking(move || {
                run_plugin_hook(plugin, secrets, input, "onResponseBodyData")
            })
            .await
            .context("plugin task panicked")??;

            self.write_audit_events(req, &plugin_name, output.audit_events)
                .await?;
        }
        Ok(())
    }

    pub async fn on_request_body_done(
        &self,
        req: &RequestInfo,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> anyhow::Result<Vec<PluginBodyOutcome>> {
        let mut outcomes = Vec::new();
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input = BodyDoneInput::new(req, bytes_seen, chunks_seen, body, content_type);
            let output: PluginBodyOutput = task::spawn_blocking(move || {
                run_plugin_hook(plugin, secrets, input, "onRequestBodyDone")
            })
            .await
            .context("plugin task panicked")??;

            self.write_audit_events(req, &plugin_name, output.audit_events)
                .await?;
            outcomes.push(PluginBodyOutcome {
                plugin_name,
                result: output.result.unwrap_or_default(),
            });
        }
        Ok(outcomes)
    }

    pub async fn on_response_body_done(
        &self,
        req: &RequestInfo,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> anyhow::Result<Vec<PluginBodyOutcome>> {
        let mut outcomes = Vec::new();
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input = BodyDoneInput::new_with_direction(
                req,
                "response",
                bytes_seen,
                chunks_seen,
                body,
                content_type,
            );
            let output: PluginBodyOutput = task::spawn_blocking(move || {
                run_plugin_hook(plugin, secrets, input, "onResponseBodyDone")
            })
            .await
            .context("plugin task panicked")??;

            self.write_audit_events(req, &plugin_name, output.audit_events)
                .await?;
            outcomes.push(PluginBodyOutcome {
                plugin_name,
                result: output.result.unwrap_or_default(),
            });
        }
        Ok(outcomes)
    }

    pub async fn on_response_headers(
        &self,
        req: &RequestInfo,
        status: u16,
        headers: &HeaderMap,
    ) -> anyhow::Result<Vec<PluginResponseHeadersOutcome>> {
        let mut outcomes = Vec::new();
        for plugin in &self.plugins {
            let plugin = plugin.clone();
            let plugin_name = plugin.name.clone();
            let secrets = self.secrets.clone();
            let input = ResponseHeadersInput::new(req, status, headers);
            let output: PluginResponseHeadersOutput = task::spawn_blocking(move || {
                run_plugin_hook(plugin, secrets, input, "onResponseHeaders")
            })
            .await
            .context("plugin task panicked")??;

            self.write_audit_events(req, &plugin_name, output.audit_events)
                .await?;
            outcomes.push(PluginResponseHeadersOutcome {
                plugin_name,
                result: output.result.unwrap_or_default(),
            });
        }
        Ok(outcomes)
    }

    async fn write_audit_events(
        &self,
        req: &RequestInfo,
        plugin_name: &str,
        events: Vec<Value>,
    ) -> anyhow::Result<()> {
        for event in events {
            self.audit
                .write(&AuditEvent {
                    r#type: event
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("plugin.audit"),
                    level: event.get("level").and_then(Value::as_str).unwrap_or("info"),
                    request_id: &req.request_id,
                    connection_id: &req.connection_id,
                    method: req.method.as_str(),
                    url: req.url.as_str(),
                    matched_rule: Some(plugin_name),
                    message: event.get("message").and_then(Value::as_str),
                })
                .await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct LoadedPlugin {
    name: String,
    version: String,
    path: PathBuf,
    source: String,
    config: Value,
}

#[derive(Debug)]
pub struct PluginOutcome {
    pub plugin_name: String,
    pub result: PluginResult,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PluginResult {
    Continue {
        #[serde(default, rename = "setHeaders")]
        set_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "addHeaders")]
        add_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "removeHeaders")]
        remove_headers: Vec<String>,
        body: Option<PluginBodyPolicy>,
    },
    Deny {
        status: u16,
        body: Option<PluginBody>,
        #[serde(default)]
        headers: serde_json::Map<String, Value>,
    },
    Respond {
        status: u16,
        body: Option<PluginBody>,
        #[serde(default)]
        headers: serde_json::Map<String, Value>,
    },
    Route {
        upstream: String,
        #[serde(default, rename = "setHeaders")]
        set_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "addHeaders")]
        add_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "removeHeaders")]
        remove_headers: Vec<String>,
        body: Option<PluginBodyPolicy>,
    },
}

impl Default for PluginResult {
    fn default() -> Self {
        Self::Continue {
            set_headers: serde_json::Map::new(),
            add_headers: serde_json::Map::new(),
            remove_headers: Vec::new(),
            body: None,
        }
    }
}

impl PluginResult {
    pub fn patches(&self) -> Option<PluginHeaderPatch<'_>> {
        match self {
            PluginResult::Continue {
                set_headers,
                add_headers,
                remove_headers,
                ..
            } => Some(PluginHeaderPatch {
                set_headers,
                add_headers,
                remove_headers,
            }),
            PluginResult::Deny { .. } | PluginResult::Respond { .. } => None,
            PluginResult::Route {
                set_headers,
                add_headers,
                remove_headers,
                ..
            } => Some(PluginHeaderPatch {
                set_headers,
                add_headers,
                remove_headers,
            }),
        }
    }

    pub fn body_policy(&self) -> Option<&PluginBodyPolicy> {
        match self {
            PluginResult::Continue { body, .. } | PluginResult::Route { body, .. } => body.as_ref(),
            PluginResult::Deny { .. } | PluginResult::Respond { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginBodyPolicy {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(rename = "maxBytes")]
    pub max_bytes: Option<usize>,
    #[serde(default)]
    pub overflow: Option<String>,
}

impl PluginBodyPolicy {
    pub fn is_buffered(&self) -> bool {
        self.mode.as_deref() == Some("buffer")
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes.unwrap_or(1024 * 1024)
    }
}

#[derive(Debug)]
pub struct PluginHeaderPatch<'a> {
    pub set_headers: &'a serde_json::Map<String, Value>,
    pub add_headers: &'a serde_json::Map<String, Value>,
    pub remove_headers: &'a [String],
}

#[derive(Debug)]
pub struct PluginBodyOutcome {
    pub plugin_name: String,
    pub result: PluginBodyDoneResult,
}

#[derive(Debug)]
pub struct PluginResponseHeadersOutcome {
    pub plugin_name: String,
    pub result: PluginResponseHeadersResult,
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PluginBodyDoneResult {
    #[default]
    Continue,
    Replace {
        body: PluginBody,
    },
    Deny {
        status: u16,
        body: Option<PluginBody>,
        #[serde(default)]
        headers: serde_json::Map<String, Value>,
    },
    Respond {
        status: u16,
        body: Option<PluginBody>,
        #[serde(default)]
        headers: serde_json::Map<String, Value>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PluginBody {
    Text(String),
    Bytes(Vec<u8>),
}

impl PluginBody {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Text(text) => text.into_bytes(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PluginResponseHeadersResult {
    Continue {
        #[serde(default, rename = "setHeaders")]
        set_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "addHeaders")]
        add_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "removeHeaders")]
        remove_headers: Vec<String>,
        body: Option<PluginBodyPolicy>,
    },
    Respond {
        status: u16,
        body: Option<PluginBody>,
        #[serde(default)]
        headers: serde_json::Map<String, Value>,
    },
}

impl Default for PluginResponseHeadersResult {
    fn default() -> Self {
        Self::Continue {
            set_headers: serde_json::Map::new(),
            add_headers: serde_json::Map::new(),
            remove_headers: Vec::new(),
            body: None,
        }
    }
}

impl PluginResponseHeadersResult {
    pub fn patches(&self) -> Option<PluginHeaderPatch<'_>> {
        match self {
            PluginResponseHeadersResult::Continue {
                set_headers,
                add_headers,
                remove_headers,
                ..
            } => Some(PluginHeaderPatch {
                set_headers,
                add_headers,
                remove_headers,
            }),
            PluginResponseHeadersResult::Respond { .. } => None,
        }
    }

    pub fn body_policy(&self) -> Option<&PluginBodyPolicy> {
        match self {
            PluginResponseHeadersResult::Continue { body, .. } => body.as_ref(),
            PluginResponseHeadersResult::Respond { .. } => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PluginOutput {
    result: Option<PluginResult>,
    #[serde(default, rename = "auditEvents")]
    audit_events: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PluginBodyOutput {
    result: Option<PluginBodyDoneResult>,
    #[serde(default, rename = "auditEvents")]
    audit_events: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PluginResponseHeadersOutput {
    result: Option<PluginResponseHeadersResult>,
    #[serde(default, rename = "auditEvents")]
    audit_events: Vec<Value>,
}

#[derive(Serialize)]
struct PluginInput {
    req: RequestHeadersPayload,
    ctx: HookContextPayload,
}

impl PluginInput {
    fn new(req: &RequestInfo, headers: &HeaderMap) -> Self {
        Self {
            req: RequestHeadersPayload::new(req, headers),
            ctx: HookContextPayload {
                request_id: req.request_id.clone(),
                connection_id: req.connection_id.clone(),
                phase: "request_headers",
            },
        }
    }
}

#[derive(Serialize)]
struct BodyDataInput {
    chunk: BodyChunkPayload,
    ctx: HookContextPayload,
}

impl BodyDataInput {
    fn new(req: &RequestInfo, index: usize, bytes: &[u8], content_type: Option<&str>) -> Self {
        Self::new_with_direction(req, "request", index, bytes, content_type)
    }

    fn new_with_direction(
        req: &RequestInfo,
        direction: &'static str,
        index: usize,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> Self {
        let phase = match direction {
            "response" => "response_body",
            _ => "request_body",
        };
        Self {
            chunk: BodyChunkPayload {
                request_id: req.request_id.clone(),
                direction,
                index,
                bytes: bytes.to_vec(),
                content_type: content_type.map(ToOwned::to_owned),
            },
            ctx: HookContextPayload {
                request_id: req.request_id.clone(),
                connection_id: req.connection_id.clone(),
                phase,
            },
        }
    }
}

#[derive(Serialize)]
struct BodyDoneInput {
    body: BodyDonePayload,
    ctx: HookContextPayload,
}

#[derive(Serialize)]
struct ResponseHeadersInput {
    res: ResponseHeadersPayload,
    ctx: HookContextPayload,
}

impl ResponseHeadersInput {
    fn new(req: &RequestInfo, status: u16, headers: &HeaderMap) -> Self {
        Self {
            res: ResponseHeadersPayload {
                request_id: req.request_id.clone(),
                status,
                header_entries: headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
                    })
                    .collect(),
            },
            ctx: HookContextPayload {
                request_id: req.request_id.clone(),
                connection_id: req.connection_id.clone(),
                phase: "response_headers",
            },
        }
    }
}

#[derive(Serialize)]
struct ResponseHeadersPayload {
    #[serde(rename = "requestId")]
    request_id: String,
    status: u16,
    #[serde(rename = "headerEntries")]
    header_entries: Vec<(String, String)>,
}

impl BodyDoneInput {
    fn new(
        req: &RequestInfo,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Self {
        Self::new_with_direction(req, "request", bytes_seen, chunks_seen, body, content_type)
    }

    fn new_with_direction(
        req: &RequestInfo,
        direction: &'static str,
        bytes_seen: usize,
        chunks_seen: usize,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Self {
        let phase = match direction {
            "response" => "response_end",
            _ => "request_end",
        };
        Self {
            body: BodyDonePayload {
                request_id: req.request_id.clone(),
                direction,
                bytes_seen,
                chunks_seen,
                bytes: body.map(|body| body.to_vec()),
                text: body.and_then(|body| std::str::from_utf8(body).ok().map(ToOwned::to_owned)),
                content_type: content_type.map(ToOwned::to_owned),
            },
            ctx: HookContextPayload {
                request_id: req.request_id.clone(),
                connection_id: req.connection_id.clone(),
                phase,
            },
        }
    }
}

#[derive(Serialize)]
struct BodyChunkPayload {
    #[serde(rename = "requestId")]
    request_id: String,
    direction: &'static str,
    index: usize,
    bytes: Vec<u8>,
    #[serde(rename = "contentType")]
    content_type: Option<String>,
}

#[derive(Serialize)]
struct BodyDonePayload {
    #[serde(rename = "requestId")]
    request_id: String,
    direction: &'static str,
    #[serde(rename = "bytesSeen")]
    bytes_seen: usize,
    #[serde(rename = "chunksSeen")]
    chunks_seen: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(rename = "contentType")]
    content_type: Option<String>,
}

#[derive(Serialize)]
struct HookContextPayload {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "connectionId")]
    connection_id: String,
    phase: &'static str,
}

#[derive(Serialize)]
struct RequestHeadersPayload {
    id: String,
    method: String,
    url: UrlPayload,
    protocol: &'static str,
    #[serde(rename = "headerEntries")]
    header_entries: Vec<(String, String)>,
}

impl RequestHeadersPayload {
    fn new(req: &RequestInfo, headers: &HeaderMap) -> Self {
        Self {
            id: req.request_id.clone(),
            method: req.method.as_str().to_string(),
            url: UrlPayload::new(&req.url),
            protocol: req.protocol,
            header_entries: headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct UrlPayload {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    full: String,
}

impl UrlPayload {
    fn new(url: &Url) -> Self {
        Self {
            scheme: url.scheme().to_string(),
            host: url.host_str().unwrap_or_default().to_string(),
            port: url.port(),
            path: url.path().to_string(),
            query: url.query().map(ToOwned::to_owned),
            full: url.as_str().to_string(),
        }
    }
}

fn init_v8() {
    V8_INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

fn run_request_headers_plugin(
    plugin: LoadedPlugin,
    secrets: SecretStore,
    input: PluginInput,
) -> anyhow::Result<PluginOutput> {
    run_plugin_hook(plugin, secrets, input, "onRequestHeaders")
}

fn run_plugin_hook<I, O>(
    plugin: LoadedPlugin,
    secrets: SecretStore,
    input: I,
    hook: &str,
) -> anyhow::Result<O>
where
    I: Serialize,
    O: for<'de> Deserialize<'de>,
{
    let mut isolate = v8::Isolate::new(v8::CreateParams::default());
    isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
    v8::scope!(let scope, &mut isolate);

    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    install_host_functions(scope);

    let secrets_json = secrets_json(&secrets)?;
    let plugin_info_json = serde_json::json!({
        "name": plugin.name,
        "version": plugin.version,
        "config": plugin.config,
    })
    .to_string();
    run_script(
        scope,
        &bootstrap_source(&plugin_info_json, &secrets_json),
        "stalin:bootstrap",
    )?;
    run_script(
        scope,
        &plugin.source,
        plugin.path.to_string_lossy().as_ref(),
    )?;

    let input_json = serde_json::to_string(&input)?;
    let hook_json = serde_json::to_string(hook)?;
    let invoke_source = format!(
        r#"
const __stalinInput = {input_json};
globalThis.__stalinAuditEvents.length = 0;
globalThis.__stalinInvoke({hook_json}, __stalinInput)
  .then((result) => ({{
    result: __stalinNormalizeResult(result),
    auditEvents: globalThis.__stalinAuditEvents,
  }}));
"#
    );
    let value = run_script(scope, &invoke_source, "stalin:invoke")?;
    let value = resolve_promises(scope, value)?;
    let json = v8::json::stringify(scope, value)
        .ok_or_else(|| anyhow!("plugin result is not JSON serializable"))?
        .to_rust_string_lossy(scope);

    Ok(serde_json::from_str(&json)?)
}

fn secrets_json(secrets: &SecretStore) -> anyhow::Result<String> {
    let mut values = serde_json::Map::new();
    for name in secrets.names() {
        values.insert(name.to_string(), Value::String(secrets.text(name)?));
    }
    Ok(Value::Object(values).to_string())
}

fn install_host_functions(scope: &mut v8::PinScope) {
    let global = scope.get_current_context().global(scope);
    set_function(scope, global, "__stalinSha256", sha256_callback);
    set_function(scope, global, "__stalinRandomUUID", random_uuid_callback);
    set_function(scope, global, "__stalinSessionGet", session_get_callback);
    set_function(scope, global, "__stalinSessionSet", session_set_callback);
    set_function(
        scope,
        global,
        "__stalinSessionDelete",
        session_delete_callback,
    );
    set_function(
        scope,
        global,
        "__stalinSessionClear",
        session_clear_callback,
    );
    set_function(scope, global, "__stalinFetch", fetch_callback);
}

fn set_function(
    scope: &mut v8::PinScope,
    global: v8::Local<v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) {
    let key = v8::String::new(scope, name).expect("host function name is valid");
    let function = v8::FunctionTemplate::new(scope, callback)
        .get_function(scope)
        .expect("host function can be created");
    global.set(scope, key.into(), function.into());
}

fn sha256_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let input = args
        .get(0)
        .to_string(scope)
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let digest = Sha256::digest(input.as_bytes());
    let value = v8::String::new(scope, &hex::encode(digest)).expect("sha256 digest is valid UTF-8");
    retval.set(value.into());
}

fn random_uuid_callback(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let uuid = Uuid::new_v4().to_string();
    let value = v8::String::new(scope, &uuid).expect("UUID is valid UTF-8");
    retval.set(value.into());
}

fn session_get_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let key = session_key(scope, &args, 0, 1);
    let Some(value) = HOST_STATE
        .session
        .lock()
        .expect("session store lock is not poisoned")
        .get(&key)
        .cloned()
    else {
        retval.set(v8::undefined(scope).into());
        return;
    };

    if let Some(value) = json_to_v8(scope, &value) {
        retval.set(value);
    }
}

fn session_set_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _retval: v8::ReturnValue,
) {
    let key = session_key(scope, &args, 0, 1);
    let value = args.get(2);
    let Some(value) = v8_to_json(scope, value) else {
        throw_type_error(scope, "session value is not JSON serializable");
        return;
    };
    HOST_STATE
        .session
        .lock()
        .expect("session store lock is not poisoned")
        .insert(key, value);
}

fn session_delete_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let key = session_key(scope, &args, 0, 1);
    let removed = HOST_STATE
        .session
        .lock()
        .expect("session store lock is not poisoned")
        .remove(&key)
        .is_some();
    retval.set(v8::Boolean::new(scope, removed).into());
}

fn session_clear_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _retval: v8::ReturnValue,
) {
    let namespace = argument_string(scope, &args, 0);
    let prefix = format!("{namespace}\0");
    HOST_STATE
        .session
        .lock()
        .expect("session store lock is not poisoned")
        .retain(|key, _| !key.starts_with(&prefix));
}

fn fetch_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let raw = argument_string(scope, &args, 0);
    let payload = match serde_json::from_str::<FetchPayload>(&raw) {
        Ok(payload) => payload,
        Err(err) => {
            throw_type_error(scope, &format!("invalid fetch payload: {err}"));
            return;
        }
    };
    let response = match plugin_fetch(payload) {
        Ok(response) => response,
        Err(err) => {
            throw_type_error(scope, &format!("fetch failed: {err}"));
            return;
        }
    };
    if let Some(value) = json_to_v8(
        scope,
        &serde_json::to_value(response).unwrap_or(Value::Null),
    ) {
        retval.set(value);
    }
}

#[derive(Debug, Deserialize)]
struct FetchPayload {
    input: String,
    #[serde(default)]
    init: FetchInit,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FetchInit {
    method: Option<String>,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FetchOutput {
    ok: bool,
    status: u16,
    status_text: String,
    headers: Vec<(String, String)>,
    text: String,
}

fn plugin_fetch(payload: FetchPayload) -> anyhow::Result<FetchOutput> {
    let method = payload
        .init
        .method
        .unwrap_or_else(|| "GET".to_string())
        .parse()?;
    let mut request = HOST_STATE.http.request(method, payload.input);
    if let Some(headers) = payload.init.headers {
        for (name, value) in headers {
            request = request.header(name, value);
        }
    }
    if let Some(body) = payload.init.body {
        request = request.body(body);
    }

    let response = request.send()?;
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let text = response.text()?;

    Ok(FetchOutput {
        ok: status.is_success(),
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").to_string(),
        headers,
        text,
    })
}

fn argument_string(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments,
    index: i32,
) -> String {
    args.get(index)
        .to_string(scope)
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default()
}

fn session_key(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments,
    namespace_index: i32,
    key_index: i32,
) -> String {
    let namespace = argument_string(scope, args, namespace_index);
    let key = argument_string(scope, args, key_index);
    format!("{namespace}\0{key}")
}

fn v8_to_json(scope: &mut v8::PinScope, value: v8::Local<v8::Value>) -> Option<Value> {
    let json = v8::json::stringify(scope, value)?;
    serde_json::from_str(&json.to_rust_string_lossy(scope)).ok()
}

fn json_to_v8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &Value,
) -> Option<v8::Local<'s, v8::Value>> {
    let raw = serde_json::to_string(value).ok()?;
    let raw = v8::String::new(scope, &raw)?;
    v8::json::parse(scope, raw)
}

fn throw_type_error(scope: &mut v8::PinScope, message: &str) {
    let message = v8::String::new(scope, message).expect("error message is valid UTF-8");
    let exception = v8::Exception::type_error(scope, message);
    scope.throw_exception(exception);
}

fn run_script<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
    name: &str,
) -> anyhow::Result<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(scope, source).ok_or_else(|| anyhow!("invalid JS source"))?;
    let name = v8::String::new(scope, name).ok_or_else(|| anyhow!("invalid JS source name"))?;
    let origin = v8::ScriptOrigin::new(
        scope,
        name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        false,
        None,
    );
    let script = v8::Script::compile(scope, source, Some(&origin))
        .ok_or_else(|| anyhow!("failed to compile JavaScript plugin"))?;
    script
        .run(scope)
        .ok_or_else(|| anyhow!("failed to run JavaScript plugin"))
}

fn resolve_promises<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> anyhow::Result<v8::Local<'s, v8::Value>> {
    if !value.is_promise() {
        return Ok(value);
    }

    let promise = v8::Local::<v8::Promise>::try_from(value)
        .map_err(|_| anyhow!("expected JavaScript promise"))?;
    for _ in 0..16 {
        scope.perform_microtask_checkpoint();
        match promise.state() {
            v8::PromiseState::Fulfilled => return Ok(promise.result(scope)),
            v8::PromiseState::Rejected => {
                let error = promise
                    .result(scope)
                    .to_string(scope)
                    .map(|value| value.to_rust_string_lossy(scope))
                    .unwrap_or_else(|| "promise rejected".to_string());
                return Err(anyhow!("plugin promise rejected: {error}"));
            }
            v8::PromiseState::Pending => {}
        }
    }

    Err(anyhow!("plugin promise did not settle"))
}

fn bootstrap_source(plugin_info_json: &str, secrets_json: &str) -> String {
    format!(
        r#"
globalThis.__stalinAuditEvents = [];
const __stalinPluginInfo = {plugin_info_json};
const __stalinSecrets = {secrets_json};

function __stalinSecretValue(name) {{
  return {{
    name,
    text() {{
      globalThis.__stalinAuditEvents.push({{
        type: "secret.access",
        fields: {{ name }},
      }});
      if (!Object.prototype.hasOwnProperty.call(__stalinSecrets, name)) {{
        throw new Error(`unknown secret ${{name}}`);
      }}
      return __stalinSecrets[name];
    }},
    bearer() {{
      return `Bearer ${{this.text()}}`;
    }},
    toJSON() {{
      return {{ secret: name }};
    }},
  }};
}}

function __stalinFetchResponse(raw) {{
  return Object.freeze({{
    ok: Boolean(raw.ok),
    status: Number(raw.status),
    statusText: String(raw.statusText ?? ""),
    headers: __stalinHeaders(raw.headers ?? []),
    text() {{
      return String(raw.text ?? "");
    }},
    json() {{
      return JSON.parse(String(raw.text ?? ""));
    }},
  }});
}}

const __stalinSessionNamespace = `${{__stalinPluginInfo.name}}@${{__stalinPluginInfo.version}}`;

globalThis.proxy = Object.freeze({{
  plugin: Object.freeze(__stalinPluginInfo),
  secrets: Object.freeze({{
    get(name) {{
      return __stalinSecretValue(String(name));
    }},
  }}),
  session: Object.freeze({{
    get(key) {{
      return globalThis.__stalinSessionGet(__stalinSessionNamespace, String(key));
    }},
    set(key, value) {{
      globalThis.__stalinSessionSet(__stalinSessionNamespace, String(key), value);
    }},
    delete(key) {{
      return globalThis.__stalinSessionDelete(__stalinSessionNamespace, String(key));
    }},
    clear() {{
      globalThis.__stalinSessionClear(__stalinSessionNamespace);
    }},
  }}),
  fetch(input, init = {{}}) {{
    const raw = globalThis.__stalinFetch(JSON.stringify({{
      input: String(input),
      init,
    }}));
    return __stalinFetchResponse(raw);
  }},
  audit: Object.freeze({{
    write(event) {{
      globalThis.__stalinAuditEvents.push(event ?? {{ type: "plugin.audit" }});
    }},
  }}),
  crypto: Object.freeze({{
    sha256(data) {{
      return globalThis.__stalinSha256(String(data));
    }},
    randomUUID() {{
      return globalThis.__stalinRandomUUID();
    }},
  }}),
  clock: Object.freeze({{
    now() {{
      return new Date().toISOString();
    }},
    unixMillis() {{
      return Date.now();
    }},
  }}),
}});

globalThis.console = Object.freeze({{
  log(...values) {{
    globalThis.__stalinAuditEvents.push({{
      type: "console.log",
      message: values.map(String).join(" "),
    }});
  }},
  warn(...values) {{
    globalThis.__stalinAuditEvents.push({{
      type: "console.warn",
      level: "warn",
      message: values.map(String).join(" "),
    }});
  }},
  error(...values) {{
    globalThis.__stalinAuditEvents.push({{
      type: "console.error",
      level: "error",
      message: values.map(String).join(" "),
    }});
  }},
}});

function __stalinHeaders(entries) {{
  const normalized = entries.map(([name, value]) => [String(name).toLowerCase(), String(value)]);
  return Object.freeze({{
    get(name) {{
      const needle = String(name).toLowerCase();
      const entry = normalized.find(([key]) => key === needle);
      return entry?.[1];
    }},
    getAll(name) {{
      const needle = String(name).toLowerCase();
      return normalized.filter(([key]) => key === needle).map(([, value]) => value);
    }},
    has(name) {{
      const needle = String(name).toLowerCase();
      return normalized.some(([key]) => key === needle);
    }},
    entries() {{
      return normalized.slice();
    }},
  }});
}}

function __stalinBodyEvent(event) {{
  if (Array.isArray(event.bytes)) {{
    event.bytes = new Uint8Array(event.bytes);
  }}
  return event;
}}

function __stalinNormalizeResult(result) {{
  if (!result || typeof result !== "object") {{
    return result;
  }}
  if (result.body instanceof Uint8Array) {{
    return {{ ...result, body: Array.from(result.body) }};
  }}
  return result;
}}

globalThis.__stalinInvoke = async function(hook, input) {{
  const plugin = globalThis.__stalinPlugin;
  if (!plugin || typeof plugin[hook] !== "function") {{
    return {{ action: "continue" }};
  }}

  if (hook === "onRequestHeaders") {{
    const req = input.req;
    req.headers = __stalinHeaders(req.headerEntries ?? []);
    delete req.headerEntries;
    return await plugin[hook](Object.freeze(req), Object.freeze(input.ctx));
  }}

  if (hook === "onRequestBodyData") {{
    return await plugin[hook](
      Object.freeze(__stalinBodyEvent(input.chunk)),
      Object.freeze(input.ctx),
    );
  }}

  if (hook === "onRequestBodyDone") {{
    return await plugin[hook](
      Object.freeze(__stalinBodyEvent(input.body)),
      Object.freeze(input.ctx),
    );
  }}

  if (hook === "onResponseHeaders") {{
    const res = input.res;
    res.headers = __stalinHeaders(res.headerEntries ?? []);
    delete res.headerEntries;
    return await plugin[hook](Object.freeze(res), Object.freeze(input.ctx));
  }}

  if (hook === "onResponseBodyData") {{
    return await plugin[hook](
      Object.freeze(__stalinBodyEvent(input.chunk)),
      Object.freeze(input.ctx),
    );
  }}

  if (hook === "onResponseBodyDone") {{
    return await plugin[hook](
      Object.freeze(__stalinBodyEvent(input.body)),
      Object.freeze(input.ctx),
    );
  }}

  return {{ action: "continue" }};
}};
"#
    )
}

fn bundle_plugin_source(config: &PluginConfig) -> Option<String> {
    let output = match Command::new("esbuild")
        .arg(&config.path)
        .arg("--bundle")
        .arg("--format=iife")
        .arg("--global-name=__stalinBundle")
        .arg("--platform=neutral")
        .arg("--log-level=warning")
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                plugin = %config.name,
                path = %config.path.display(),
                "esbuild is not on PATH; skipping plugin"
            );
            return None;
        }
        Err(err) => {
            warn!(
                plugin = %config.name,
                path = %config.path.display(),
                error = %err,
                "failed to start esbuild; skipping plugin"
            );
            return None;
        }
    };

    if !output.status.success() {
        warn!(
            plugin = %config.name,
            path = %config.path.display(),
            status = %output.status,
            stderr = %String::from_utf8_lossy(&output.stderr),
            "esbuild failed; skipping plugin"
        );
        return None;
    }

    let mut source = String::from_utf8_lossy(&output.stdout).to_string();
    source.push_str(
        "\nglobalThis.__stalinPlugin = globalThis.__stalinBundle.default ?? globalThis.__stalinBundle;\n",
    );
    Some(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit::AuditLog, config::PluginConfig};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[tokio::test]
    async fn plugin_can_patch_headers_and_use_secret() {
        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            r#"
const plugin = {
  async onRequestHeaders(req) {
    if (req.url.host !== "api.example.com") return { action: "continue" };
    return {
      action: "route",
      upstream: "https://api.example.com",
      setHeaders: {
        authorization: (await proxy.secrets.get("token")).bearer(),
        "x-plugin": await proxy.crypto.sha256("abc"),
      },
      removeHeaders: ["x-placeholder"],
    };
  },
};
export default plugin;
"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("STALIN_TEST_TOKEN", "secret");
        }
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::from([(
                "token".to_string(),
                crate::config::SecretConfig {
                    env: "STALIN_TEST_TOKEN".to_string(),
                },
            )])),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::GET,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let headers = HeaderMap::new();
        let outcomes = runtime.on_request_headers(&req, &headers).await.unwrap();

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0].result {
            PluginResult::Route { set_headers, .. } => {
                assert_eq!(set_headers["authorization"], "Bearer secret");
                assert_eq!(
                    set_headers["x-plugin"],
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                );
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_session_persists_across_invocations() {
        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            r#"
const plugin = {
  onRequestHeaders() {
    const count = Number(proxy.session.get("count") ?? 0) + 1;
    proxy.session.set("count", count);
    return {
      action: "continue",
      setHeaders: { "x-count": String(count) },
    };
  },
};
export default plugin;
"#,
        )
        .unwrap();
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: format!("test-{}", Uuid::new_v4()),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::new()),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::GET,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let headers = HeaderMap::new();

        let first = runtime.on_request_headers(&req, &headers).await.unwrap();
        let second = runtime.on_request_headers(&req, &headers).await.unwrap();

        match &first[0].result {
            PluginResult::Continue { set_headers, .. } => {
                assert_eq!(set_headers["x-count"], "1");
            }
            other => panic!("unexpected result: {other:?}"),
        }
        match &second[0].result {
            PluginResult::Continue { set_headers, .. } => {
                assert_eq!(set_headers["x-count"], "2");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_can_fetch_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
                )
                .unwrap();
        });

        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            format!(
                r#"
const plugin = {{
  async onRequestHeaders() {{
    const res = await proxy.fetch({url:?}, {{
      method: "POST",
      headers: {{ "content-type": "text/plain" }},
      body: "ping",
    }});
    const body = await res.text();
    return {{
      action: "continue",
      setHeaders: {{
        "x-fetch-status": String(res.status),
        "x-fetch-body": body,
      }},
    }};
  }},
}};
export default plugin;
"#
            ),
        )
        .unwrap();
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::new()),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::GET,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let headers = HeaderMap::new();
        let outcomes = runtime.on_request_headers(&req, &headers).await.unwrap();
        server.join().unwrap();

        match &outcomes[0].result {
            PluginResult::Continue { set_headers, .. } => {
                assert_eq!(set_headers["x-fetch-status"], "200");
                assert_eq!(set_headers["x-fetch-body"], "hello");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_can_request_buffered_body_and_replace_it() {
        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            r#"
const plugin = {
  onRequestHeaders() {
    return {
      action: "continue",
      body: { mode: "buffer", maxBytes: 64 },
    };
  },
  onRequestBodyDone(body) {
    if (body.text !== "before") throw new Error(`unexpected body ${body.text}`);
    return { action: "replace", body: new Uint8Array([97, 102, 116, 101, 114]) };
  },
};
export default plugin;
"#,
        )
        .unwrap();
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::new()),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::POST,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let headers = HeaderMap::new();
        let outcomes = runtime.on_request_headers(&req, &headers).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        let policy = outcomes[0].result.body_policy().unwrap();
        assert!(policy.is_buffered());
        assert_eq!(policy.max_bytes(), 64);

        let outcomes = runtime
            .on_request_body_done(&req, 6, 1, Some(b"before"), Some("text/plain"))
            .await
            .unwrap();

        match &outcomes[0].result {
            PluginBodyDoneResult::Replace { body } => {
                assert_eq!(body, &PluginBody::Bytes(b"after".to_vec()));
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_can_patch_response_headers() {
        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            r#"
const plugin = {
  onResponseHeaders(res) {
    if (res.status !== 201) throw new Error(`unexpected status ${res.status}`);
    if (res.headers.get("x-upstream") !== "1") throw new Error("missing upstream header");
    return {
      action: "continue",
      setHeaders: { "x-plugin-response": "yes" },
      removeHeaders: ["x-upstream"],
    };
  },
};
export default plugin;
"#,
        )
        .unwrap();
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::new()),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::POST,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-upstream", "1".parse().unwrap());

        let outcomes = runtime
            .on_response_headers(&req, 201, &headers)
            .await
            .unwrap();

        match &outcomes[0].result {
            PluginResponseHeadersResult::Continue {
                set_headers,
                remove_headers,
                ..
            } => {
                assert_eq!(set_headers["x-plugin-response"], "yes");
                assert_eq!(remove_headers, &["x-upstream"]);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_can_request_buffered_response_body_and_replace_it() {
        let file = tempfile::Builder::new().suffix(".ts").tempfile().unwrap();
        std::fs::write(
            file.path(),
            r#"
const plugin = {
  onResponseHeaders(res) {
    if (res.status !== 200) throw new Error(`unexpected status ${res.status}`);
    return {
      action: "continue",
      body: { mode: "buffer", maxBytes: 64 },
    };
  },
  onResponseBodyDone(body, ctx) {
    if (ctx.phase !== "response_end") throw new Error(`unexpected phase ${ctx.phase}`);
    if (body.direction !== "response") throw new Error(`unexpected direction ${body.direction}`);
    if (body.text !== "before") throw new Error(`unexpected body ${body.text}`);
    return { action: "replace", body: "after" };
  },
};
export default plugin;
"#,
        )
        .unwrap();
        let runtime = PluginRuntime::new(
            vec![PluginConfig {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                path: file.path().to_path_buf(),
                config: None,
            }],
            SecretStore::new(std::collections::HashMap::new()),
            AuditLog::new(None).unwrap(),
        )
        .unwrap()
        .unwrap();
        let req = RequestInfo::new(
            http::Method::POST,
            Url::parse("https://api.example.com/v1").unwrap(),
        );
        let headers = HeaderMap::new();
        let outcomes = runtime
            .on_response_headers(&req, 200, &headers)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        let policy = outcomes[0].result.body_policy().unwrap();
        assert!(policy.is_buffered());
        assert_eq!(policy.max_bytes(), 64);

        let outcomes = runtime
            .on_response_body_done(&req, 6, 1, Some(b"before"), Some("text/plain"))
            .await
            .unwrap();

        match &outcomes[0].result {
            PluginBodyDoneResult::Replace { body } => {
                assert_eq!(body, &PluginBody::Text("after".to_string()));
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
