use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};

use crate::config::MitmConfig;

#[derive(Debug)]
pub struct MitmAuthority {
    ca_cert_pem: String,
    ca_key_pem: String,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmAuthority {
    pub fn from_config(config: &MitmConfig) -> anyhow::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let authority = match (&config.ca_cert, &config.ca_key) {
            (Some(cert_path), Some(key_path)) => {
                let ca_cert_pem = fs::read_to_string(cert_path).with_context(|| {
                    format!("failed to read MITM CA cert {}", cert_path.display())
                })?;
                let ca_key_pem = fs::read_to_string(key_path).with_context(|| {
                    format!("failed to read MITM CA key {}", key_path.display())
                })?;
                Self::from_pem(ca_cert_pem, ca_key_pem)?
            }
            (None, None) => {
                anyhow::bail!("mitm.ca_cert and mitm.ca_key are required when MITM is enabled")
            }
            _ => anyhow::bail!("mitm.ca_cert and mitm.ca_key must be configured together"),
        };

        Ok(Some(authority))
    }

    pub fn generate() -> anyhow::Result<Self> {
        let mut params = CertificateParams::new(Vec::default())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "stalin local MITM CA");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        Self::from_pem(cert.pem(), key_pair.serialize_pem())
    }

    pub fn from_pem(ca_cert_pem: String, ca_key_pem: String) -> anyhow::Result<Self> {
        let ca_key = KeyPair::from_pem(&ca_key_pem).context("failed to parse MITM CA key")?;
        Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key).context("failed to parse MITM CA cert")?;

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_certificate_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn server_config_for_host(&self, host: &str) -> anyhow::Result<Arc<ServerConfig>> {
        let host = normalize_host(host)?;
        if let Some(config) = self
            .cache
            .lock()
            .expect("MITM cert cache mutex poisoned")
            .get(&host)
            .cloned()
        {
            return Ok(config);
        }

        let config = Arc::new(self.issue_server_config(&host)?);
        self.cache
            .lock()
            .expect("MITM cert cache mutex poisoned")
            .insert(host, config.clone());
        Ok(config)
    }

    fn issue_server_config(&self, host: &str) -> anyhow::Result<ServerConfig> {
        let ca_key = KeyPair::from_pem(&self.ca_key_pem).context("failed to parse MITM CA key")?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key)
            .context("failed to parse MITM CA cert")?;
        let (leaf_cert, leaf_key) = issue_leaf(host, &issuer)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf_cert.der().clone()],
                pkcs8_key(leaf_key.serialize_der()),
            )
            .context("failed to build MITM TLS server config")?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn issue_leaf(
    host: &str,
    issuer: &Issuer<'_, impl rcgen::SigningKey>,
) -> anyhow::Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((cert, key_pair))
}

fn pkcs8_key(bytes: Vec<u8>) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes))
}

fn normalize_host(host: &str) -> anyhow::Result<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        anyhow::bail!("MITM host is empty");
    }
    Ok(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;

    #[test]
    fn generated_authority_exports_ca_certificate() {
        let authority = MitmAuthority::generate().unwrap();

        assert!(
            authority
                .ca_certificate_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
    }

    #[test]
    fn authority_mints_and_caches_server_config() {
        let authority = MitmAuthority::generate().unwrap();

        let first = authority.server_config_for_host("Example.COM.").unwrap();
        let second = authority.server_config_for_host("example.com").unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn server_config_advertises_h2_before_http1() {
        let authority = MitmAuthority::generate().unwrap();
        let config = authority.server_config_for_host("example.com").unwrap();

        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn authority_round_trips_through_pem() {
        let generated = MitmAuthority::generate().unwrap();
        let loaded =
            MitmAuthority::from_pem(generated.ca_cert_pem.clone(), generated.ca_key_pem.clone())
                .unwrap();

        loaded.server_config_for_host("api.openai.com").unwrap();
    }

    #[test]
    fn rejects_partial_ca_config() {
        let config = MitmConfig {
            enabled: true,
            ca_cert: Some("ca.pem".into()),
            ca_key: None,
        };

        assert!(MitmAuthority::from_config(&config).is_err());
    }

    #[test]
    fn rejects_enabled_config_without_ca_files() {
        let config = MitmConfig {
            enabled: true,
            ca_cert: None,
            ca_key: None,
        };

        assert!(MitmAuthority::from_config(&config).is_err());
    }

    #[test]
    fn disabled_config_skips_authority() {
        assert!(
            MitmAuthority::from_config(&MitmConfig::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn leaf_cert_der_is_rustls_compatible() {
        let authority = MitmAuthority::generate().unwrap();
        let ca_key = KeyPair::from_pem(&authority.ca_key_pem).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&authority.ca_cert_pem, ca_key).unwrap();
        let (leaf, _) = issue_leaf("localhost", &issuer).unwrap();
        let cert: CertificateDer<'static> = leaf.der().clone();

        assert!(!cert.as_ref().is_empty());
    }
}
