//! Onboarding: the first super administrator's setup, and installing the
//! agent for an application (installations, their credentials, and whether
//! the agent has connected).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
use crate::application_credentials;
use crate::auth::{SessionToken, UserPrincipal, hash_password, normalize_email, validate_password};
use crate::repository::application_credentials::ApplicationCredentialRepository;
use crate::repository::events::EventRepository;
use crate::repository::installations::InstallationRepository;
use crate::repository::{ApplicationRepository, UserRepository};
use crate::service::identity::{insert_identity_session, valid_name};
use crate::service::project_access::member_project_role;
use crate::transactional_mail::Locale;
use crate::web_api::WebApiConfig;

const STATUS_FRESH_SECONDS: i64 = 300;

/// Why an onboarding use case failed.
#[derive(Debug, Error)]
pub enum OnboardingServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(&'static str),
    /// The setup token is wrong or expired.
    #[error("setup authorization is invalid")]
    InvalidSetupToken,
    /// A super administrator already exists.
    #[error("setup is already complete")]
    SetupAlreadyCompleted,
    /// The deployment has no usable agent installation metadata; the message
    /// says why.
    #[error("{0}")]
    MetadataUnavailable(&'static str),
    /// The application or installation does not exist in the principal's
    /// organization, or the principal may not change it.
    #[error("resource not found")]
    NotFound,
    /// The idempotency key was used for a different installation request.
    #[error("idempotency key was used for another request")]
    IdempotencyKeyReused,
    /// Hashing a password or a request failed.
    #[error("internal error")]
    Internal,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

type Result<T, E = OnboardingServiceError> = std::result::Result<T, E>;

#[derive(Clone, Debug, Serialize)]
pub struct AgentInstallationMetadata {
    pub chart_reference: String,
    pub chart_version: String,
    pub recommended_agent_version: String,
    pub minimum_agent_version: String,
    pub configuration_schema_version: i32,
    pub grpc_endpoint: String,
    pub tls_mode: String,
    pub ca_secret_name: Option<String>,
    pub ca_secret_key: Option<String>,
    pub namespace: String,
    pub credential_secret_name: String,
    pub credential_secret_key: String,
    pub supported_workload_kinds: Vec<String>,
}

impl AgentInstallationMetadata {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chart_reference.starts_with("oci://")
            && !self.chart_version.is_empty()
            && !self.grpc_endpoint.is_empty()
            && self.valid_tls_metadata()
            && self.configuration_schema_version > 0
            && self.supported_workload_kinds == ["Deployment"]
        {
            Ok(())
        } else {
            Err("agent installation metadata is incomplete")
        }
    }

    fn valid_tls_metadata(&self) -> bool {
        match self.tls_mode.as_str() {
            "system" => self.ca_secret_name.is_none() && self.ca_secret_key.is_none(),
            "custom_ca" => {
                self.ca_secret_name
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    && self
                        .ca_secret_key
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
            }
            _ => false,
        }
    }
}

/// Whether the platform still needs its first super administrator.
#[derive(Debug, Serialize)]
pub struct SetupStatus {
    state: &'static str,
}

/// The first super administrator, authorized by the setup token.
#[derive(Clone, Debug)]
pub struct FirstAdministrator {
    pub setup_token: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub locale: Locale,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    user_id: Uuid,
    platform_role: &'static str,
    active_organization_id: Option<Uuid>,
    privileged_until: DateTime<Utc>,
}

/// A completed setup and the privileged session opened for the new
/// administrator.
#[derive(Debug)]
pub struct SetupCompleted {
    pub result: SetupResponse,
    pub session: SessionToken,
}

/// The workload an installation watches: a Deployment by name or by labels.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIntent {
    pub namespace: String,
    pub kind: String,
    pub name: Option<String>,
    pub labels: Option<BTreeMap<String, String>>,
}

/// An installation to create or the new shape of one.
///
/// Its JSON serialization is hashed to recognise a retried creation under the
/// same idempotency key, so its fields and their order are part of the
/// stored state.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRequest {
    pub cluster_name: String,
    pub workload: WorkloadIntent,
}

#[derive(Debug, Serialize)]
pub struct InstallationPage {
    items: Vec<Installation>,
}

/// Holds the plaintext credential, so it has no `Debug`.
#[allow(missing_debug_implementations)]
#[derive(Serialize)]
pub struct IssuedInstallation {
    installation: Installation,
    credential: IssuedCredential,
    command: CommandModel,
}

/// Holds the plaintext credential, so it has no `Debug`.
#[allow(missing_debug_implementations)]
#[derive(Serialize)]
pub struct IssuedCredential {
    id: Uuid,
    token: String,
    token_hint: String,
    shown_once: bool,
}

#[derive(Serialize)]
pub(crate) struct CommandModel {
    chart_reference: String,
    chart_version: String,
    namespace: String,
    secret_name: String,
    secret_key: String,
    grpc_endpoint: String,
    tls_mode: String,
    ca_secret_name: Option<String>,
    ca_secret_key: Option<String>,
}

/// The result of creating an installation. It is returned once, so the
/// variants' sizes do not matter.
#[allow(missing_debug_implementations, clippy::large_enum_variant)]
pub enum InstallationIssue {
    /// The request repeats an earlier one under the same idempotency key; the
    /// installation it created is returned without its credential.
    Replayed(Installation),
    /// A new installation with its credential, shown once.
    Issued(IssuedInstallation),
}

type CredentialEvidence = Option<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)>;
type StatusEvidence = Option<(String, Option<String>, DateTime<Utc>, i64)>;

#[derive(Clone, Debug)]
pub struct OnboardingService {
    pool: PgPool,
    setup_digest: Option<[u8; 32]>,
    setup_expires_at: Option<DateTime<Utc>>,
    session_lifetime: std::time::Duration,
    metadata: Option<AgentInstallationMetadata>,
}

impl OnboardingService {
    pub fn new(pool: PgPool, config: &WebApiConfig) -> Self {
        Self {
            pool,
            setup_digest: config.setup_token_digest,
            setup_expires_at: config.setup_token_expires_at,
            session_lifetime: config.session_lifetime,
            metadata: config.agent_installation.clone(),
        }
    }

    /// Ready once a super administrator exists; otherwise setup is needed,
    /// unless the setup token has expired.
    pub async fn setup_status(&self) -> Result<SetupStatus> {
        let exists = UserRepository::active_super_admin_exists(&self.pool).await?;
        let expired = self
            .setup_expires_at
            .is_some_and(|value| value <= Utc::now());
        Ok(SetupStatus {
            state: if exists {
                "ready"
            } else if expired {
                "setup_unavailable"
            } else {
                "platform_admin_required"
            },
        })
    }

    /// Creates the first super administrator and opens a session for them
    /// that may perform privileged actions for 15 minutes. Only while no
    /// super administrator exists.
    pub async fn complete_setup(
        &self,
        input: FirstAdministrator,
        request_id: &str,
    ) -> Result<SetupCompleted> {
        let email = validate_setup(&input, self.setup_digest, self.setup_expires_at)?;
        let password_hash =
            hash_password(&input.password).map_err(|_| OnboardingServiceError::Internal)?;
        let mut tx = self.pool.begin().await?;
        UserRepository::lock_setup(&mut *tx).await?;
        let has_super_admin = UserRepository::active_super_admin_exists(&mut *tx).await?;
        if has_super_admin {
            return Err(OnboardingServiceError::SetupAlreadyCompleted);
        }
        let user_id = Uuid::new_v4();
        UserRepository::insert_verified(
            &mut *tx,
            user_id,
            &email,
            &password_hash,
            input.locale.as_str(),
            &input.display_name,
        )
        .await?;
        UserRepository::assign_super_admin(&mut *tx, user_id).await?;
        write_access_audit(
            &mut tx,
            AccessAuditEvent {
                actor: AccessAuditActor::User(user_id),
                action: "setup.completed",
                organization_id: None,
                project_id: None,
                target_user_id: Some(user_id),
                invitation_id: None,
                previous_role: None,
                new_role: Some("super_admin"),
                request_id: Some(request_id),
            },
        )
        .await?;
        let privileged_until = Utc::now() + chrono::Duration::minutes(15);
        let (_, session) = insert_identity_session(
            &mut tx,
            user_id,
            Some(privileged_until),
            self.session_lifetime,
        )
        .await?;
        tx.commit().await?;
        Ok(SetupCompleted {
            result: SetupResponse {
                user_id,
                platform_role: "super_admin",
                active_organization_id: None,
                privileged_until,
            },
            session,
        })
    }

    /// What the UI needs to render the agent installation command.
    pub fn installation_metadata(&self) -> Result<AgentInstallationMetadata> {
        let metadata = self
            .metadata
            .clone()
            .ok_or(OnboardingServiceError::MetadataUnavailable(
                "agent installation metadata is unavailable",
            ))?;
        metadata
            .validate()
            .map_err(OnboardingServiceError::MetadataUnavailable)?;
        Ok(metadata)
    }

    /// Creates an installation with a fresh application credential. Owners
    /// only. The idempotency key is required: a retry with the same key and
    /// request returns the installation it created, without the credential.
    pub async fn create_installation(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        idempotency_key: Option<&str>,
        input: InstallationRequest,
    ) -> Result<InstallationIssue> {
        if !principal.role.is_owner() {
            return Err(OnboardingServiceError::NotFound);
        }
        self.owned_application(principal, project_id, application_id)
            .await?;
        validate_installation(&input)?;
        let key = idempotency_key
            .filter(|v| !v.is_empty() && v.len() <= 128)
            .ok_or(OnboardingServiceError::Invalid(
                "a bounded Idempotency-Key header is required",
            ))?;
        let metadata = self.installation_metadata()?;
        let hash: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&input).map_err(|_| OnboardingServiceError::Internal)?,
        )
        .into();
        let existing = InstallationRepository::by_idempotency_key::<_, InstallationWithHash>(
            &self.pool,
            principal.organization_id,
            key,
        )
        .await?;
        if let Some(existing) = existing {
            if existing.request_hash.as_slice() == hash {
                return Ok(InstallationIssue::Replayed(existing.installation()));
            }
            return Err(OnboardingServiceError::IdempotencyKeyReused);
        }
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        let issued = application_credentials::issue(
            &mut tx,
            principal.organization_id,
            project_id,
            application_id,
            &format!("installation-{}", &id.to_string()[..8]),
        )
        .await?;
        let installation = InstallationRepository::insert::<_, Installation>(
            &mut *tx,
            id,
            principal.organization_id,
            project_id,
            application_id,
            issued.summary.id,
            key,
            hash.as_slice(),
            &input.cluster_name,
            &input.workload.namespace,
            &input.workload.kind,
            input.workload.name.as_deref(),
            input
                .workload
                .labels
                .as_ref()
                .map(|v| serde_json::to_value(v).expect("labels serialize")),
            &metadata.chart_version,
            metadata.configuration_schema_version,
        )
        .await?;
        tx.commit().await?;
        Ok(InstallationIssue::Issued(IssuedInstallation {
            command: command_model(&metadata),
            credential: IssuedCredential {
                id: issued.summary.id,
                token: issued.token().to_owned(),
                token_hint: issued.summary.token_hint,
                shown_once: true,
            },
            installation,
        }))
    }

    /// The installations of an application.
    pub async fn list_installations(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<InstallationPage> {
        self.owned_application(principal, project_id, application_id)
            .await?;
        let items = InstallationRepository::for_application(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await?;
        Ok(InstallationPage { items })
    }

    /// One installation of an application in a project the principal can see.
    pub async fn get_installation(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
    ) -> Result<Installation> {
        self.ensure_project_access(principal, project_id).await?;
        InstallationRepository::get(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            installation_id,
        )
        .await?
        .ok_or(OnboardingServiceError::NotFound)
    }

    /// Changes the cluster name and workload of an installation. Owners only.
    pub async fn update_installation(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
        input: InstallationRequest,
    ) -> Result<Installation> {
        if !principal.role.is_owner() {
            return Err(OnboardingServiceError::NotFound);
        }
        validate_installation(&input)?;
        InstallationRepository::update::<_, Installation>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            installation_id,
            &input.cluster_name,
            &input.workload.namespace,
            &input.workload.kind,
            input.workload.name.as_deref(),
            input
                .workload
                .labels
                .as_ref()
                .map(|labels| serde_json::to_value(labels).expect("bounded labels serialize")),
        )
        .await?
        .ok_or(OnboardingServiceError::NotFound)
    }

    /// Revokes an installation's credential and issues its replacement, shown
    /// once. Owners only.
    pub async fn replace_credential(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
    ) -> Result<IssuedCredential> {
        if !principal.role.is_owner() {
            return Err(OnboardingServiceError::NotFound);
        }
        let mut tx = self.pool.begin().await?;
        let old: Option<Uuid> = InstallationRepository::credential_for_update(
            &mut *tx,
            principal.organization_id,
            project_id,
            application_id,
            installation_id,
        )
        .await?;
        let old = old.ok_or(OnboardingServiceError::NotFound)?;
        ApplicationCredentialRepository::revoke(&mut *tx, old).await?;
        let issued = application_credentials::issue(
            &mut tx,
            principal.organization_id,
            project_id,
            application_id,
            &format!("replacement-{}", &Uuid::new_v4().to_string()[..8]),
        )
        .await?;
        InstallationRepository::set_credential(&mut *tx, issued.summary.id, installation_id)
            .await?;
        tx.commit().await?;
        Ok(IssuedCredential {
            id: issued.summary.id,
            token: issued.token().to_owned(),
            token_hint: issued.summary.token_hint,
            shown_once: true,
        })
    }

    /// How far the application's agent has got: from waiting for it, through
    /// its diagnostics, to receiving events.
    pub async fn connection_readiness(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Readiness> {
        self.owned_application(principal, project_id, application_id)
            .await?;
        let events: (Option<DateTime<Utc>>, Option<DateTime<Utc>>) =
            EventRepository::received_window(
                &self.pool,
                principal.organization_id,
                project_id,
                application_id,
            )
            .await?;
        let cred: CredentialEvidence = InstallationRepository::latest_credential_use(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await?;
        let status: StatusEvidence = InstallationRepository::latest_status(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await?;
        Ok(derive_readiness(events, cred, status))
    }

    /// The application must be in a project the principal can see: owners
    /// and admins see every project, members those they hold a role in.
    async fn owned_application(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<()> {
        self.ensure_project_access(principal, project_id).await?;
        let found = ApplicationRepository::exists(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await?;
        if found {
            Ok(())
        } else {
            Err(OnboardingServiceError::NotFound)
        }
    }

    /// A project the principal cannot see does not exist for them.
    async fn ensure_project_access(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
    ) -> Result<()> {
        if member_project_role(&self.pool, principal, project_id)
            .await?
            .is_some()
        {
            Ok(())
        } else {
            Err(OnboardingServiceError::NotFound)
        }
    }
}

fn validate_setup(
    input: &FirstAdministrator,
    expected: Option<[u8; 32]>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<String> {
    let email = normalize_email(&input.email).map_err(OnboardingServiceError::Invalid)?;
    validate_password(&input.password).map_err(OnboardingServiceError::Invalid)?;
    if !valid_name(&input.display_name) {
        return Err(OnboardingServiceError::Invalid("display name is invalid"));
    }
    let candidate: [u8; 32] = Sha256::digest(input.setup_token.as_bytes()).into();
    if expires_at.is_some_and(|value| value <= Utc::now())
        || input.setup_token.len() < 32
        || !expected.is_some_and(|digest| bool::from(digest.ct_eq(&candidate)))
    {
        return Err(OnboardingServiceError::InvalidSetupToken);
    }
    Ok(email)
}

fn validate_installation(input: &InstallationRequest) -> Result<()> {
    let dns = |value: &str, max| {
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
    };
    if !valid_name(&input.cluster_name)
        || !dns(&input.workload.namespace, 63)
        || input.workload.kind != "Deployment"
    {
        return Err(OnboardingServiceError::Invalid(
            "cluster or workload identity is invalid",
        ));
    }
    match (&input.workload.name, &input.workload.labels) {
        (Some(name), None) if dns(name, 253) => Ok(()),
        (None, Some(labels))
            if !labels.is_empty()
                && labels.len() <= 16
                && labels
                    .iter()
                    .all(|(k, v)| dns(k, 63) && !v.is_empty() && v.len() <= 63) =>
        {
            Ok(())
        }
        _ => Err(OnboardingServiceError::Invalid(
            "provide exactly one valid Deployment name or label map",
        )),
    }
}

#[derive(Debug, FromRow, Serialize)]
pub struct Installation {
    id: Uuid,
    application_id: Uuid,
    credential_id: Uuid,
    cluster_name: String,
    workload_namespace: String,
    workload_kind: String,
    workload_name: Option<String>,
    workload_labels: Option<serde_json::Value>,
    chart_version: String,
    configuration_schema_version: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct InstallationWithHash {
    id: Uuid,
    application_id: Uuid,
    credential_id: Uuid,
    cluster_name: String,
    workload_namespace: String,
    workload_kind: String,
    workload_name: Option<String>,
    workload_labels: Option<serde_json::Value>,
    chart_version: String,
    configuration_schema_version: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    request_hash: Vec<u8>,
}
impl InstallationWithHash {
    fn installation(self) -> Installation {
        Installation {
            id: self.id,
            application_id: self.application_id,
            credential_id: self.credential_id,
            cluster_name: self.cluster_name,
            workload_namespace: self.workload_namespace,
            workload_kind: self.workload_kind,
            workload_name: self.workload_name,
            workload_labels: self.workload_labels,
            chart_version: self.chart_version,
            configuration_schema_version: self.configuration_schema_version,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

pub(crate) fn command_model(metadata: &AgentInstallationMetadata) -> CommandModel {
    CommandModel {
        chart_reference: metadata.chart_reference.clone(),
        chart_version: metadata.chart_version.clone(),
        namespace: metadata.namespace.clone(),
        secret_name: metadata.credential_secret_name.clone(),
        secret_key: metadata.credential_secret_key.clone(),
        grpc_endpoint: metadata.grpc_endpoint.clone(),
        tls_mode: metadata.tls_mode.clone(),
        ca_secret_name: metadata.ca_secret_name.clone(),
        ca_secret_key: metadata.ca_secret_key.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct Readiness {
    state: &'static str,
    reason: Option<String>,
    credential_last_used_at: Option<DateTime<Utc>>,
    first_event_at: Option<DateTime<Utc>>,
    last_event_at: Option<DateTime<Utc>>,
    reporting_nodes: i64,
    stale_after_seconds: i64,
}

fn derive_readiness(
    events: (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
    cred: CredentialEvidence,
    status: StatusEvidence,
) -> Readiness {
    let now = Utc::now();
    let fresh =
        |at: DateTime<Utc>| now.signed_duration_since(at).num_seconds() <= STATUS_FRESH_SECONDS;
    let credential_last_used_at = cred.and_then(|v| v.0);
    let revoked = cred.is_some_and(|v| v.1.is_some());
    let (state, reason, nodes) = if revoked {
        ("credential_revoked", None, 0)
    } else if events.1.is_some_and(fresh) {
        ("receiving_events", None, 0)
    } else if let Some((s, r, at, n)) = status {
        if fresh(at) {
            (
                match s.as_str() {
                    "workload_not_matched" => "workload_not_matched",
                    "permission_denied" => "permission_denied",
                    "kernel_unsupported" => "kernel_unsupported",
                    "waiting_for_event" => "waiting_for_event",
                    _ => "agent_authenticated",
                },
                r,
                n,
            )
        } else {
            ("stale", None, n)
        }
    } else if credential_last_used_at.is_some_and(fresh) {
        ("agent_authenticated", None, 0)
    } else if credential_last_used_at.is_some() || events.1.is_some() {
        ("stale", None, 0)
    } else {
        ("waiting_for_agent", None, 0)
    };
    Readiness {
        state,
        reason,
        credential_last_used_at,
        first_event_at: events.0,
        last_event_at: events.1,
        reporting_nodes: nodes,
        stale_after_seconds: STATUS_FRESH_SECONDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_bounded() {
        let mut metadata = AgentInstallationMetadata {
            chart_reference: "oci://registry/chart".into(),
            chart_version: "1.0.0".into(),
            recommended_agent_version: "1.0.0".into(),
            minimum_agent_version: "1.0.0".into(),
            configuration_schema_version: 1,
            grpc_endpoint: "grpc.example:443".into(),
            tls_mode: "system".into(),
            ca_secret_name: None,
            ca_secret_key: None,
            namespace: "okoscope-system".into(),
            credential_secret_name: "okoscope-agent-credentials".into(),
            credential_secret_key: "application-token".into(),
            supported_workload_kinds: vec!["Deployment".into()],
        };
        assert!(metadata.validate().is_ok());
        metadata.tls_mode = "custom_ca".into();
        assert!(metadata.validate().is_err());
        metadata.ca_secret_name = Some("okoscope-ca".into());
        metadata.ca_secret_key = Some("ca.crt".into());
        assert!(metadata.validate().is_ok());
        metadata.grpc_endpoint.clear();
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn custom_ca_is_propagated_to_installation_command() {
        let metadata = AgentInstallationMetadata {
            chart_reference: "oci://registry/chart".into(),
            chart_version: "1.0.0".into(),
            recommended_agent_version: "1.0.0".into(),
            minimum_agent_version: "1.0.0".into(),
            configuration_schema_version: 1,
            grpc_endpoint: "grpc.example:443".into(),
            tls_mode: "custom_ca".into(),
            ca_secret_name: Some("private-ca".into()),
            ca_secret_key: Some("ca.crt".into()),
            namespace: "okoscope-system".into(),
            credential_secret_name: "credentials".into(),
            credential_secret_key: "token".into(),
            supported_workload_kinds: vec!["Deployment".into()],
        };
        let command = serde_json::to_value(command_model(&metadata)).unwrap();
        assert_eq!(command["ca_secret_name"], "private-ca");
        assert_eq!(command["ca_secret_key"], "ca.crt");
    }

    #[test]
    fn readiness_precedence_and_staleness_are_stable() {
        let now = Utc::now();
        let recent = now - chrono::Duration::seconds(10);
        let old = now - chrono::Duration::seconds(STATUS_FRESH_SECONDS + 10);
        let diagnostic = Some((
            "permission_denied".into(),
            Some("kubernetes_watch_forbidden".into()),
            recent,
            2,
        ));
        let receiving = derive_readiness((Some(recent), Some(recent)), None, diagnostic.clone());
        assert_eq!(receiving.state, "receiving_events");
        let revoked = derive_readiness(
            (Some(recent), Some(recent)),
            Some((Some(recent), Some(recent))),
            diagnostic.clone(),
        );
        assert_eq!(revoked.state, "credential_revoked");
        let denied = derive_readiness((None, None), Some((Some(recent), None)), diagnostic);
        assert_eq!(denied.state, "permission_denied");
        assert_eq!(denied.reporting_nodes, 2);
        let stale = derive_readiness((Some(old), Some(old)), Some((Some(old), None)), None);
        assert_eq!(stale.state, "stale");
        let older_agent = derive_readiness((None, None), Some((Some(recent), None)), None);
        assert_eq!(older_agent.state, "agent_authenticated");
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::auth::OrganizationRole;
        use crate::repository::test_support::tenant;

        const SETUP_TOKEN: &str = "setup-token-that-is-long-enough-for-tests";

        fn metadata() -> AgentInstallationMetadata {
            AgentInstallationMetadata {
                chart_reference: "oci://registry/chart".into(),
                chart_version: "1.0.0".into(),
                recommended_agent_version: "1.0.0".into(),
                minimum_agent_version: "1.0.0".into(),
                configuration_schema_version: 1,
                grpc_endpoint: "grpc.example:443".into(),
                tls_mode: "system".into(),
                ca_secret_name: None,
                ca_secret_key: None,
                namespace: "okoscope-system".into(),
                credential_secret_name: "credentials".into(),
                credential_secret_key: "token".into(),
                supported_workload_kinds: vec!["Deployment".into()],
            }
        }

        fn administrator(token: &str, email: &str) -> FirstAdministrator {
            FirstAdministrator {
                setup_token: token.into(),
                email: email.into(),
                password: "correct horse battery staple".into(),
                display_name: "Owner".into(),
                locale: Locale::En,
            }
        }

        fn principal(organization_id: Uuid, role: OrganizationRole) -> UserPrincipal {
            UserPrincipal {
                user_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                organization_id,
                role,
            }
        }

        fn request(name: &str) -> InstallationRequest {
            InstallationRequest {
                cluster_name: "Production".into(),
                workload: WorkloadIntent {
                    namespace: "payments".into(),
                    kind: "Deployment".into(),
                    name: Some(name.into()),
                    labels: None,
                },
            }
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn setup_creates_the_first_super_administrator_once(pool: PgPool) {
            let config = WebApiConfig::default().with_setup_token(Some(SETUP_TOKEN));
            let service = OnboardingService::new(pool.clone(), &config);
            assert_eq!(
                service.setup_status().await.unwrap().state,
                "platform_admin_required"
            );

            // The identity is validated before the token.
            assert!(matches!(
                service
                    .complete_setup(administrator("short", "not-an-email"), "r")
                    .await,
                Err(OnboardingServiceError::Invalid(_))
            ));
            assert!(matches!(
                service
                    .complete_setup(administrator("short", "owner@example.test"), "r")
                    .await,
                Err(OnboardingServiceError::InvalidSetupToken)
            ));
            let completed = service
                .complete_setup(administrator(SETUP_TOKEN, "owner@example.test"), "r")
                .await
                .unwrap();
            assert_eq!(completed.result.platform_role, "super_admin");
            assert!(completed.result.privileged_until > Utc::now());
            assert_eq!(service.setup_status().await.unwrap().state, "ready");
            assert!(matches!(
                service
                    .complete_setup(administrator(SETUP_TOKEN, "second@example.test"), "r")
                    .await,
                Err(OnboardingServiceError::SetupAlreadyCompleted)
            ));

            let expired = OnboardingService::new(
                pool.clone(),
                &config.with_setup_token_expiry(Some(Utc::now() - chrono::Duration::seconds(1))),
            );
            // A super administrator exists, so setup reads as done anyway.
            assert_eq!(expired.setup_status().await.unwrap().state, "ready");
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn installations_are_owned_idempotent_and_replaceable(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let config = WebApiConfig::default().with_agent_installation(Some(metadata()));
            let service = OnboardingService::new(pool.clone(), &config);
            let owner = principal(tenant.organization_id, OrganizationRole::Owner);
            let member = principal(tenant.organization_id, OrganizationRole::Member);
            let (project, application) = (tenant.project_id, tenant.application_id);

            // Ownership is checked before the application, which is checked
            // before the request and its idempotency key.
            let created = service
                .create_installation(member, project, application, None, request("api"))
                .await;
            assert!(matches!(created, Err(OnboardingServiceError::NotFound)));
            let created = service
                .create_installation(owner, project, Uuid::new_v4(), None, request("api"))
                .await;
            assert!(matches!(created, Err(OnboardingServiceError::NotFound)));
            let mut invalid = request("api");
            invalid.workload.kind = "StatefulSet".into();
            let created = service
                .create_installation(owner, project, application, None, invalid)
                .await;
            assert!(matches!(
                created,
                Err(OnboardingServiceError::Invalid(
                    "cluster or workload identity is invalid"
                ))
            ));
            let created = service
                .create_installation(owner, project, application, None, request("api"))
                .await;
            assert!(matches!(
                created,
                Err(OnboardingServiceError::Invalid(
                    "a bounded Idempotency-Key header is required"
                ))
            ));
            let without_metadata = OnboardingService::new(pool.clone(), &WebApiConfig::default());
            let created = without_metadata
                .create_installation(owner, project, application, Some("k1"), request("api"))
                .await;
            assert!(matches!(
                created,
                Err(OnboardingServiceError::MetadataUnavailable(_))
            ));

            let InstallationIssue::Issued(issued) = service
                .create_installation(owner, project, application, Some("k1"), request("api"))
                .await
                .unwrap()
            else {
                panic!("the first request issues an installation");
            };
            assert!(issued.credential.shown_once);
            let InstallationIssue::Replayed(replayed) = service
                .create_installation(owner, project, application, Some("k1"), request("api"))
                .await
                .unwrap()
            else {
                panic!("the same request under the same key replays");
            };
            assert_eq!(replayed.id, issued.installation.id);
            assert!(matches!(
                service
                    .create_installation(owner, project, application, Some("k1"), request("web"))
                    .await,
                Err(OnboardingServiceError::IdempotencyKeyReused)
            ));

            let listed = service
                .list_installations(owner, project, application)
                .await
                .unwrap();
            assert_eq!(listed.items.len(), 1);
            let id = issued.installation.id;
            assert!(matches!(
                service
                    .update_installation(member, project, application, id, request("web"))
                    .await,
                Err(OnboardingServiceError::NotFound)
            ));
            let updated = service
                .update_installation(owner, project, application, id, request("web"))
                .await
                .unwrap();
            assert_eq!(updated.workload_name.as_deref(), Some("web"));
            assert_eq!(
                service
                    .get_installation(owner, project, application, id)
                    .await
                    .unwrap()
                    .workload_name
                    .as_deref(),
                Some("web")
            );

            let replaced = service
                .replace_credential(owner, project, application, id)
                .await
                .unwrap();
            assert_ne!(replaced.id, issued.credential.id);
            let installation = service
                .get_installation(owner, project, application, id)
                .await
                .unwrap();
            assert_eq!(installation.credential_id, replaced.id);
            assert!(matches!(
                service
                    .replace_credential(owner, project, application, Uuid::new_v4())
                    .await,
                Err(OnboardingServiceError::NotFound)
            ));

            let readiness = service
                .connection_readiness(owner, project, application)
                .await
                .unwrap();
            assert_eq!(readiness.state, "waiting_for_agent");
        }

        /// Installations and connection readiness belong to an application of
        /// a project; a member who cannot see the project reads neither.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn installation_reads_need_access_to_the_project(pool: PgPool) {
            use crate::repository::MembershipRepository;
            use crate::repository::test_support::user;

            let tenant = tenant(&pool, "onboarding-project-access").await;
            let config = WebApiConfig::default().with_agent_installation(Some(metadata()));
            let service = OnboardingService::new(pool.clone(), &config);
            let owner = principal(tenant.organization_id, OrganizationRole::Owner);
            let (project, application) = (tenant.project_id, tenant.application_id);
            let InstallationIssue::Issued(issued) = service
                .create_installation(owner, project, application, Some("k1"), request("api"))
                .await
                .unwrap()
            else {
                panic!("the first request issues an installation");
            };
            let installation = issued.installation.id;

            let user_id = user(&pool).await;
            MembershipRepository::insert_organization_role(
                &pool,
                tenant.organization_id,
                user_id,
                "member",
            )
            .await
            .unwrap();
            let member = UserPrincipal {
                user_id,
                ..principal(tenant.organization_id, OrganizationRole::Member)
            };
            assert!(matches!(
                service
                    .list_installations(member, project, application)
                    .await,
                Err(OnboardingServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .get_installation(member, project, application, installation)
                    .await,
                Err(OnboardingServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .connection_readiness(member, project, application)
                    .await,
                Err(OnboardingServiceError::NotFound)
            ));

            MembershipRepository::insert_project_role(
                &pool,
                tenant.organization_id,
                project,
                user_id,
                "member",
            )
            .await
            .unwrap();
            let listed = service
                .list_installations(member, project, application)
                .await
                .unwrap();
            assert_eq!(listed.items.len(), 1);
            service
                .get_installation(member, project, application, installation)
                .await
                .unwrap();
            service
                .connection_readiness(member, project, application)
                .await
                .unwrap();
        }
    }
}
