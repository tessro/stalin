use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub audit_log: Option<String>,
    pub mitm: MitmConfig,
    pub secrets: HashMap<String, SecretConfig>,
    pub rules: Vec<RuleConfig>,
    pub plugins: Vec<PluginConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080"
                .parse()
                .expect("default listen address is valid"),
            audit_log: None,
            mitm: MitmConfig::default(),
            secrets: HashMap::new(),
            rules: Vec::new(),
            plugins: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&raw)?;
        if let Some(parent) = path.parent() {
            if let Some(ca_cert) = &mut config.mitm.ca_cert
                && ca_cert.is_relative()
            {
                *ca_cert = parent.join(&ca_cert);
            }
            if let Some(ca_key) = &mut config.mitm.ca_key
                && ca_key.is_relative()
            {
                *ca_key = parent.join(&ca_key);
            }
            for plugin in &mut config.plugins {
                if plugin.path.is_relative() {
                    plugin.path = parent.join(&plugin.path);
                }
            }
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MitmConfig {
    pub enabled: bool,
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretConfig {
    pub env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    #[serde(default = "default_plugin_version")]
    pub version: String,
    pub path: PathBuf,
    #[serde(default)]
    pub config: Option<toml::Value>,
}

fn default_plugin_version() -> String {
    "0.1.0".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default, rename = "match")]
    pub matcher: MatchConfig,
    #[serde(default)]
    pub request_headers: HeaderPatchConfig,
    pub deny: Option<DenyConfig>,
    #[serde(default)]
    pub audit: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchConfig {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeaderPatchConfig {
    #[serde(default)]
    pub set: HashMap<String, HeaderValueConfig>,
    #[serde(default)]
    pub add: HashMap<String, HeaderValueConfig>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HeaderValueConfig {
    Literal(String),
    Secret {
        secret: String,
        #[serde(default = "default_secret_format")]
        format: String,
    },
}

fn default_secret_format() -> String {
    "{value}".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DenyConfig {
    #[serde(default = "default_deny_status")]
    pub status: u16,
    pub body: Option<String>,
}

fn default_deny_status() -> u16 {
    403
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_shape() {
        let cfg: Config = toml::from_str(
            r#"
listen = "127.0.0.1:8080"

[secrets.openai_api_key]
env = "OPENAI_API_KEY"

[[rules]]
name = "openai"

[rules.match]
host = "api.openai.com"

[rules.request_headers.set]
authorization = { secret = "openai_api_key", format = "Bearer {value}" }

[rules.request_headers]
remove = ["x-placeholder-authorization"]
"#,
        )
        .unwrap();

        assert_eq!(cfg.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.rules[0].name, "openai");
    }

    #[test]
    fn parses_mitm_config() {
        let cfg: Config = toml::from_str(
            r#"
[mitm]
enabled = true
ca_cert = "certs/ca.pem"
ca_key = "certs/ca-key.pem"
"#,
        )
        .unwrap();

        assert!(cfg.mitm.enabled);
        assert_eq!(cfg.mitm.ca_cert.unwrap(), PathBuf::from("certs/ca.pem"));
        assert_eq!(cfg.mitm.ca_key.unwrap(), PathBuf::from("certs/ca-key.pem"));
    }
}
