use std::{collections::HashMap, net::SocketAddr, path::Path};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub audit_log: Option<String>,
    pub secrets: HashMap<String, SecretConfig>,
    pub rules: Vec<RuleConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080"
                .parse()
                .expect("default listen address is valid"),
            audit_log: None,
            secrets: HashMap::new(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&raw)?)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretConfig {
    pub env: String,
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
        let cfg: Config = serde_yaml::from_str(
            r#"
listen: 127.0.0.1:8080
secrets:
  openai_api_key:
    env: OPENAI_API_KEY
rules:
  - name: openai
    match:
      host: api.openai.com
    request_headers:
      set:
        authorization:
          secret: openai_api_key
          format: "Bearer {value}"
      remove:
        - x-placeholder-authorization
"#,
        )
        .unwrap();

        assert_eq!(cfg.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.rules[0].name, "openai");
    }
}
