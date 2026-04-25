use std::{collections::HashMap, sync::Arc};

use thiserror::Error;

use crate::config::SecretConfig;

#[derive(Debug, Clone)]
pub struct SecretStore {
    configs: Arc<HashMap<String, SecretConfig>>,
}

impl SecretStore {
    pub fn new(configs: HashMap<String, SecretConfig>) -> Self {
        Self {
            configs: Arc::new(configs),
        }
    }

    pub fn text(&self, name: &str) -> Result<String, SecretError> {
        let cfg = self
            .configs
            .get(name)
            .ok_or_else(|| SecretError::Unknown(name.to_string()))?;
        std::env::var(&cfg.env).map_err(|_| SecretError::MissingEnv {
            name: name.to_string(),
            env: cfg.env.clone(),
        })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.configs.keys().map(String::as_str)
    }
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("unknown secret `{0}`")]
    Unknown(String),
    #[error("secret `{name}` depends on unset environment variable `{env}`")]
    MissingEnv { name: String, env: String },
}
