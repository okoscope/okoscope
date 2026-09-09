use std::path::PathBuf;

use thiserror::Error;
use tonic::transport::{Identity, ServerTlsConfig};

#[derive(Clone, Debug)]
pub enum TransportSecurity {
    DevelopmentPlaintext,
    Tls {
        certificate: PathBuf,
        private_key: PathBuf,
    },
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("failed to read TLS material: {0}")]
    Io(#[from] std::io::Error),
}

impl TransportSecurity {
    pub async fn tls_config(&self) -> Result<Option<ServerTlsConfig>, TransportError> {
        match self {
            Self::DevelopmentPlaintext => Ok(None),
            Self::Tls {
                certificate,
                private_key,
            } => {
                let certificate = tokio::fs::read(certificate).await?;
                let private_key = tokio::fs::read(private_key).await?;
                Ok(Some(
                    ServerTlsConfig::new().identity(Identity::from_pem(certificate, private_key)),
                ))
            }
        }
    }
}
