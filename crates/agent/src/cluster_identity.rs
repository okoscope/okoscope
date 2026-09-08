use k8s_openapi::api::core::v1::Namespace;
use kube::{Api, Client};
use thiserror::Error;
use uuid::Uuid;

const SYSTEM_NAMESPACE: &str = "kube-system";

pub async fn discover(client: Client) -> Result<String, ClusterIdentityError> {
    let namespace = Api::<Namespace>::all(client)
        .get(SYSTEM_NAMESPACE)
        .await
        .map_err(ClusterIdentityError::Kubernetes)?;
    canonicalize(
        namespace
            .metadata
            .uid
            .as_deref()
            .ok_or(ClusterIdentityError::MissingUid)?,
    )
}

pub fn canonicalize(value: &str) -> Result<String, ClusterIdentityError> {
    let uid = Uuid::parse_str(value).map_err(|_| ClusterIdentityError::InvalidUid)?;
    let canonical = uid.to_string();
    if canonical == value {
        Ok(canonical)
    } else {
        Err(ClusterIdentityError::InvalidUid)
    }
}

#[derive(Debug, Error)]
pub enum ClusterIdentityError {
    #[error("cannot read kube-system Namespace identity")]
    Kubernetes(#[source] kube::Error),
    #[error("kube-system Namespace has no UID")]
    MissingUid,
    #[error("kube-system Namespace UID is not a canonical UUID")]
    InvalidUid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_uuid_identity() {
        let value = Uuid::new_v4().to_string();
        assert_eq!(canonicalize(&value).unwrap(), value);
        for invalid in ["", "cluster", "018F4F9C-3F9A-7DE1-8000-000000000000"] {
            assert!(canonicalize(invalid).is_err());
        }
    }
}
