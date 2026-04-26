use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

use crate::config::OAuthRefreshTokenConfig;

#[derive(Debug, Clone)]
pub struct OAuthRefreshTokenProvider {
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<OAuthRefreshTokenConfig, CachedAccessToken>>>,
}

impl OAuthRefreshTokenProvider {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn access_token(&self, cfg: &OAuthRefreshTokenConfig) -> anyhow::Result<String> {
        let now = Instant::now();
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.get(cfg)
            && cached.refresh_after > now
        {
            return Ok(cached.token.clone());
        }

        let token = refresh_access_token(&self.client, cfg).await?;
        cache.insert(cfg.clone(), token.clone());
        Ok(token.token)
    }
}

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    refresh_after: Instant,
}

async fn refresh_access_token(
    client: &reqwest::Client,
    cfg: &OAuthRefreshTokenConfig,
) -> anyhow::Result<CachedAccessToken> {
    let token_url = Url::parse(&cfg.token_url)?;
    let client_id = env_var(&cfg.client_id_env)?;
    let client_secret = env_var(&cfg.client_secret_env)?;
    let refresh_token = env_var(&cfg.refresh_token_env)?;

    let response = client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("OAuth refresh token request failed with {status}: {body}");
    }

    let token: TokenResponse = serde_json::from_str(&body)?;
    let expires_in = token.expires_in.unwrap_or(cfg.default_expires_in_seconds);
    let refresh_after_seconds = expires_in.saturating_sub(cfg.refresh_before_expiry_seconds);
    let refresh_after = Instant::now() + Duration::from_secs(refresh_after_seconds.max(1));

    Ok(CachedAccessToken {
        token: token.access_token,
        refresh_after,
    })
}

fn env_var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("OAuth secret env var `{name}` is unset"))
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cached_token_is_reused_until_refresh_after() {
        let provider = OAuthRefreshTokenProvider::new().unwrap();
        let cfg = OAuthRefreshTokenConfig {
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            client_id_env: "CLIENT_ID".to_string(),
            client_secret_env: "CLIENT_SECRET".to_string(),
            refresh_token_env: "REFRESH_TOKEN".to_string(),
            refresh_before_expiry_seconds: 300,
            default_expires_in_seconds: 3600,
        };
        provider.cache.lock().await.insert(
            cfg.clone(),
            CachedAccessToken {
                token: "cached".to_string(),
                refresh_after: Instant::now() + Duration::from_secs(60),
            },
        );

        assert_eq!(provider.access_token(&cfg).await.unwrap(), "cached");
    }
}
