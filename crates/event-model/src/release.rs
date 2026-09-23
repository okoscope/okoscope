use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RELEASE_IDENTITY_VERSION: u16 = 1;
pub const MAX_RELEASE_CONTAINERS: usize = 64;
pub const MAX_CONTAINER_NAME_BYTES: usize = 253;
pub const MAX_IMAGE_REFERENCE_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerCategory {
    Init,
    Application,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContainerImageIdentity {
    pub category: ContainerCategory,
    pub name: String,
    pub image: Option<String>,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseIdentity {
    pub version: u16,
    pub digest: [u8; 32],
    pub containers: Vec<ContainerImageIdentity>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReleaseIdentityError {
    #[error("release identity must contain 1..={MAX_RELEASE_CONTAINERS} containers")]
    InvalidContainerCount,
    #[error("container name must contain 1..={MAX_CONTAINER_NAME_BYTES} bytes")]
    InvalidContainerName,
    #[error("image reference must contain 1..={MAX_IMAGE_REFERENCE_BYTES} bytes")]
    InvalidImageReference,
    #[error("container names must be unique within their category")]
    DuplicateContainer,
    #[error("image ID must contain an immutable sha256 digest")]
    InvalidImageId,
    #[error("release identity version is unsupported")]
    UnsupportedVersion,
    #[error("release identity digest does not match its components")]
    DigestMismatch,
}

impl ReleaseIdentity {
    pub fn from_image_ids<I, N, S>(components: I) -> Result<Self, ReleaseIdentityError>
    where
        I: IntoIterator<Item = (ContainerCategory, N, S)>,
        N: Into<String>,
        S: AsRef<str>,
    {
        let mut containers = components
            .into_iter()
            .map(|(category, name, image_id)| {
                Ok(ContainerImageIdentity {
                    category,
                    name: name.into(),
                    image: None,
                    digest: parse_image_id(image_id.as_ref())?,
                })
            })
            .collect::<Result<Vec<_>, ReleaseIdentityError>>()?;
        validate_components(&mut containers)?;
        Ok(Self {
            version: RELEASE_IDENTITY_VERSION,
            digest: digest_components(&containers),
            containers,
        })
    }

    pub fn from_images<I, N, S, D>(components: I) -> Result<Self, ReleaseIdentityError>
    where
        I: IntoIterator<Item = (ContainerCategory, N, S, D)>,
        N: Into<String>,
        S: Into<String>,
        D: AsRef<str>,
    {
        let mut containers = components
            .into_iter()
            .map(|(category, name, image, image_id)| {
                Ok(ContainerImageIdentity {
                    category,
                    name: name.into(),
                    image: Some(image.into()),
                    digest: parse_image_id(image_id.as_ref())?,
                })
            })
            .collect::<Result<Vec<_>, ReleaseIdentityError>>()?;
        validate_components(&mut containers)?;
        Ok(Self {
            version: RELEASE_IDENTITY_VERSION,
            digest: digest_components(&containers),
            containers,
        })
    }

    pub fn validate(&self) -> Result<(), ReleaseIdentityError> {
        if self.version != RELEASE_IDENTITY_VERSION {
            return Err(ReleaseIdentityError::UnsupportedVersion);
        }
        let mut components = self.containers.clone();
        validate_components(&mut components)?;
        if components != self.containers || digest_components(&components) != self.digest {
            return Err(ReleaseIdentityError::DigestMismatch);
        }
        Ok(())
    }
}

fn validate_components(values: &mut [ContainerImageIdentity]) -> Result<(), ReleaseIdentityError> {
    if values.is_empty() || values.len() > MAX_RELEASE_CONTAINERS {
        return Err(ReleaseIdentityError::InvalidContainerCount);
    }
    if values
        .iter()
        .any(|v| v.name.is_empty() || v.name.len() > MAX_CONTAINER_NAME_BYTES)
    {
        return Err(ReleaseIdentityError::InvalidContainerName);
    }
    if values.iter().any(|value| {
        value.image.as_ref().is_some_and(|image| {
            image.is_empty() || image.len() > MAX_IMAGE_REFERENCE_BYTES || image.trim() != image
        })
    }) {
        return Err(ReleaseIdentityError::InvalidImageReference);
    }
    values.sort();
    if values
        .windows(2)
        .any(|v| v[0].category == v[1].category && v[0].name == v[1].name)
    {
        return Err(ReleaseIdentityError::DuplicateContainer);
    }
    Ok(())
}

fn parse_image_id(value: &str) -> Result<[u8; 32], ReleaseIdentityError> {
    let encoded = value
        .rsplit_once("sha256:")
        .map(|(_, digest)| digest)
        .ok_or(ReleaseIdentityError::InvalidImageId)?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReleaseIdentityError::InvalidImageId);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| ReleaseIdentityError::InvalidImageId)?;
        digest[index] =
            u8::from_str_radix(text, 16).map_err(|_| ReleaseIdentityError::InvalidImageId)?;
    }
    Ok(digest)
}

fn digest_components(values: &[ContainerImageIdentity]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_IDENTITY_VERSION.to_be_bytes());
    for value in values {
        hasher.update([match value.category {
            ContainerCategory::Init => 0,
            ContainerCategory::Application => 1,
        }]);
        hasher.update(value.name.len().to_be_bytes());
        hasher.update(value.name.as_bytes());
        hasher.update(value.digest);
    }
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeState {
    Detected,
    Active,
    Inactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTransitionKind {
    Rollout,
    RollbackCandidate,
    Concurrent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSelectionSource {
    Explicit,
    Transition,
    ConcurrentTransitionFallback,
    LegacyDeploymentOrder,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRevisionEvidence {
    pub evidence_id: String,
    pub observed_at: DateTime<Utc>,
    pub namespace: String,
    pub workload_uid: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub replica_set_uid: String,
    pub replica_set_name: String,
    pub pod_uid: String,
    pub pod_template_hash: Option<String>,
    pub release_identity: ReleaseIdentity,
    pub ready: bool,
}

pub fn revision_digest(evidence: &WorkloadRevisionEvidence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_IDENTITY_VERSION.to_be_bytes());
    for value in [&evidence.workload_uid, &evidence.replica_set_uid] {
        hasher.update(value.len().to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(evidence.release_identity.digest);
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionReadinessSnapshot {
    pub snapshot_id: String,
    pub observed_at: DateTime<Utc>,
    pub initialized: bool,
    pub continuous: bool,
    pub revision_digest: [u8; 32],
    pub pod_count: u32,
    pub ready_pod_count: u32,
    pub workload_ready_pod_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(byte: char) -> String {
        format!("registry/app@sha256:{}", byte.to_string().repeat(64))
    }
    #[test]
    fn identity_is_order_independent() {
        let a = ReleaseIdentity::from_image_ids([
            (ContainerCategory::Application, "web", image('a')),
            (ContainerCategory::Init, "migrate", image('b')),
        ])
        .unwrap();
        let b = ReleaseIdentity::from_image_ids([
            (ContainerCategory::Init, "migrate", image('b')),
            (ContainerCategory::Application, "web", image('a')),
        ])
        .unwrap();
        assert_eq!(a, b);
        a.validate().unwrap();
    }
    #[test]
    fn rejects_mutable_and_duplicate_components() {
        assert!(matches!(
            ReleaseIdentity::from_image_ids([(
                ContainerCategory::Application,
                "web",
                "app:latest"
            )]),
            Err(ReleaseIdentityError::InvalidImageId)
        ));
        assert!(matches!(
            ReleaseIdentity::from_image_ids([
                (ContainerCategory::Application, "web", image('a')),
                (ContainerCategory::Application, "web", image('b'))
            ]),
            Err(ReleaseIdentityError::DuplicateContainer)
        ));
    }
}
