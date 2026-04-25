use std::{path::Path, sync::Arc};

use anyhow::Context;
use serde::Serialize;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

#[derive(Clone)]
pub struct AuditLog {
    sink: AuditSink,
}

#[derive(Clone)]
enum AuditSink {
    Stdout,
    File(Arc<Mutex<tokio::fs::File>>),
}

impl AuditLog {
    pub async fn new(path: Option<&str>) -> anyhow::Result<Self> {
        let sink = match path {
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(Path::new(path))
                    .await
                    .with_context(|| format!("failed to open audit log {path}"))?;
                AuditSink::File(Arc::new(Mutex::new(file)))
            }
            None => AuditSink::Stdout,
        };
        Ok(Self { sink })
    }

    pub async fn write<T: Serialize>(&self, event: &T) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        match &self.sink {
            AuditSink::Stdout => {
                let mut out = tokio::io::stdout();
                out.write_all(&line).await?;
            }
            AuditSink::File(file) => {
                let mut file = file.lock().await;
                file.write_all(&line).await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub r#type: &'a str,
    pub level: &'a str,
    pub request_id: &'a str,
    pub connection_id: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub matched_rule: Option<&'a str>,
    pub message: Option<&'a str>,
}
