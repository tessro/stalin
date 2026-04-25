use std::{convert::TryFrom, path::PathBuf, process::Command, sync::Once};

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
    },
    Deny {
        status: u16,
        body: Option<String>,
    },
    Respond {
        status: u16,
        body: Option<String>,
    },
    Route {
        upstream: String,
        #[serde(default, rename = "setHeaders")]
        set_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "addHeaders")]
        add_headers: serde_json::Map<String, Value>,
        #[serde(default, rename = "removeHeaders")]
        remove_headers: Vec<String>,
    },
}

impl Default for PluginResult {
    fn default() -> Self {
        Self::Continue {
            set_headers: serde_json::Map::new(),
            add_headers: serde_json::Map::new(),
            remove_headers: Vec::new(),
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
}

#[derive(Debug)]
pub struct PluginHeaderPatch<'a> {
    pub set_headers: &'a serde_json::Map<String, Value>,
    pub add_headers: &'a serde_json::Map<String, Value>,
    pub remove_headers: &'a [String],
}

#[derive(Debug, Deserialize)]
struct PluginOutput {
    result: Option<PluginResult>,
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
            protocol: "http/1.1",
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
    let invoke_source = format!(
        r#"
const __stalinInput = {input_json};
globalThis.__stalinAuditEvents.length = 0;
globalThis.__stalinInvoke(__stalinInput.req, __stalinInput.ctx)
  .then((result) => ({{ result, auditEvents: globalThis.__stalinAuditEvents }}));
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

globalThis.proxy = Object.freeze({{
  plugin: Object.freeze(__stalinPluginInfo),
  secrets: Object.freeze({{
    get(name) {{
      return __stalinSecretValue(String(name));
    }},
  }}),
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

globalThis.__stalinInvoke = async function(req, ctx) {{
  req.headers = __stalinHeaders(req.headerEntries ?? []);
  delete req.headerEntries;
  const plugin = globalThis.__stalinPlugin;
  if (!plugin || typeof plugin.onRequestHeaders !== "function") {{
    return {{ action: "continue" }};
  }}
  return await plugin.onRequestHeaders(Object.freeze(req), Object.freeze(ctx));
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
            AuditLog::new(None).await.unwrap(),
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
}
