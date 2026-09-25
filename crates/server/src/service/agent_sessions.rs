//! What an agent's session does to the platform: authenticating the
//! application credential, registering the cluster and the agent, and
//! recording what the agent sends (heartbeats, runtime events, resource
//! aggregates, release evidence and onboarding status). The gRPC transport
//! reads the stream and negotiates capabilities; this module holds the rules
//! and the writes.

use protocol::v1::{AgentHello, Heartbeat, ResourceBatchAcknowledgement};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::application_credentials::{ApplicationCredentialScope, authenticate};
use crate::auth::SessionScope;
use crate::ingestion::{IngestionError, persist_application_batch_outcome};
use crate::repository::clusters::ClusterRepository;
use crate::repository::installations::InstallationRepository;

/// Why an agent session step failed.
#[derive(Debug, Error)]
pub enum AgentSessionError {
    /// The credential is missing, invalid or revoked; the message says which.
    #[error("{0}")]
    Unauthenticated(&'static str),
    /// The agent sent something malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// Storing failed; the text describes the underlying error.
    #[error("{0}")]
    Internal(String),
}

impl AgentSessionError {
    fn invalid(message: &str) -> Self {
        Self::Invalid(message.into())
    }
}

fn internal(error: impl std::fmt::Display) -> AgentSessionError {
    AgentSessionError::Internal(error.to_string())
}

type Result<T, E = AgentSessionError> = std::result::Result<T, E>;

/// A registered agent's session: where it reports, and its ids.
#[derive(Clone, Copy, Debug)]
pub struct EstablishedSession {
    pub scope: SessionScope,
    pub agent_id: Uuid,
    pub session_id: Uuid,
}

/// Records what agents report.
#[derive(Clone, Debug)]
pub struct AgentIntakeService {
    pool: PgPool,
}

impl AgentIntakeService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The application an agent's bearer credential belongs to.
    pub async fn authenticate(&self, credential: &str) -> Result<ApplicationCredentialScope> {
        authenticate_application(&self.pool, credential).await
    }

    /// Validates the agent's hello, resolves its cluster in the credential's
    /// organization, registers the agent and opens its session.
    pub async fn establish(
        &self,
        application_scope: ApplicationCredentialScope,
        hello: &AgentHello,
    ) -> Result<EstablishedSession> {
        let (scope, agent_id, session_id) =
            establish_agent(&self.pool, application_scope, hello).await?;
        Ok(EstablishedSession {
            scope,
            agent_id,
            session_id,
        })
    }

    /// Marks the agent alive and records its heartbeat diagnostics.
    pub async fn heartbeat(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
        heartbeat: &Heartbeat,
    ) -> Result<()> {
        touch_agent(&self.pool, session.agent_id)
            .await
            .map_err(internal)?;
        crate::service::agent_health::record_heartbeat(
            &self.pool,
            application_scope,
            session.scope.cluster_id,
            session.agent_id,
            heartbeat,
        )
        .await
        .map_err(|message| {
            if message.starts_with("heartbeat") {
                AgentSessionError::invalid(message)
            } else {
                internal(message)
            }
        })
    }

    /// Ingests a batch of runtime events; returns how many were accepted and
    /// how many were already past retention.
    pub async fn persist_events(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
        events: &mut [event_model::RuntimeEvent],
    ) -> Result<(u32, u32)> {
        persist_application_batch_outcome(
            &self.pool,
            session.scope,
            application_scope,
            session.agent_id,
            events,
        )
        .await
        .map_err(|error| match error {
            IngestionError::RevokedCredential => {
                AgentSessionError::Unauthenticated("application credential was revoked")
            }
            other => internal(other),
        })
    }

    /// Records a batch of resource aggregates from the agent's node.
    pub async fn persist_resources(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
        node_name: &str,
        batch: protocol::v1::ResourceSampleBatch,
    ) -> Result<ResourceBatchAcknowledgement> {
        persist_resource_batch(
            &self.pool,
            session.scope,
            application_scope,
            session.agent_id,
            node_name,
            batch,
        )
        .await
    }

    /// Records evidence of a workload revision.
    pub async fn persist_revision_evidence(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
        evidence: &event_model::WorkloadRevisionEvidence,
    ) -> Result<()> {
        crate::release_discovery::persist_revision_evidence(
            &self.pool,
            session.scope,
            application_scope,
            evidence,
        )
        .await
        .map_err(internal)
    }

    /// Records a revision's readiness.
    pub async fn persist_readiness_snapshot(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
        snapshot: &event_model::RevisionReadinessSnapshot,
    ) -> Result<()> {
        crate::release_discovery::persist_readiness_snapshot(
            &self.pool,
            session.scope,
            application_scope,
            snapshot,
        )
        .await
        .map_err(internal)
    }

    /// Records the agent's onboarding status for its node.
    pub async fn persist_onboarding_status(
        &self,
        application_scope: ApplicationCredentialScope,
        node_name: &str,
        value: protocol::v1::OnboardingStatus,
    ) -> Result<()> {
        persist_onboarding_status(&self.pool, application_scope, node_name, value).await
    }

    /// Closes the session when the stream ends.
    pub async fn end(
        &self,
        session: EstablishedSession,
        application_scope: ApplicationCredentialScope,
    ) {
        crate::service::agent_health::end_session(
            &self.pool,
            session.session_id,
            application_scope,
            session.agent_id,
        )
        .await;
    }
}

async fn establish_agent(
    pool: &PgPool,
    application_scope: ApplicationCredentialScope,
    hello: &AgentHello,
) -> Result<(SessionScope, Uuid, Uuid), AgentSessionError> {
    let bounded = crate::service::agent_health::validate_capabilities(&hello.capabilities)
        .map_err(|message| AgentSessionError::Invalid(message.into()))?;
    let scope = resolve_session_scope(pool, application_scope, hello).await?;
    let (agent_id, session_id) = register(pool, scope, hello, &bounded)
        .await
        .map_err(internal)?;
    crate::service::agent_health::register_application_agent(
        pool,
        application_scope,
        scope.cluster_id,
        agent_id,
        &bounded,
    )
    .await
    .map_err(internal)?;
    Ok((scope, agent_id, session_id))
}

async fn persist_resource_batch(
    pool: &PgPool,
    scope: SessionScope,
    application_scope: ApplicationCredentialScope,
    agent_id: Uuid,
    node_name: &str,
    batch: protocol::v1::ResourceSampleBatch,
) -> Result<ResourceBatchAcknowledgement, AgentSessionError> {
    let mut accepted = 0_u32;
    let mut duplicate = 0_u32;
    let mut expired = 0_u32;
    let mut invalid = 0_u32;
    for wire in batch.aggregates {
        let aggregate = match event_model::ResourceAggregate::try_from(wire) {
            Ok(value) if value.node_name == node_name => value,
            Ok(_) | Err(_) => {
                invalid = invalid.saturating_add(1);
                continue;
            }
        };
        match crate::resources::persist_resource_aggregate(
            pool,
            scope,
            application_scope,
            agent_id,
            &aggregate,
        )
        .await
        .map_err(internal)?
        {
            crate::resources::PersistResourceOutcome::Accepted => {
                accepted = accepted.saturating_add(1);
            }
            crate::resources::PersistResourceOutcome::Duplicate => {
                duplicate = duplicate.saturating_add(1);
            }
            crate::resources::PersistResourceOutcome::Expired => {
                expired = expired.saturating_add(1);
            }
        }
    }
    Ok(ResourceBatchAcknowledgement {
        sequence: batch.sequence,
        accepted_aggregates: accepted,
        duplicate_aggregates: duplicate,
        retention_expired_aggregates: expired,
        invalid_aggregates: invalid,
    })
}

async fn authenticate_application(
    pool: &PgPool,
    credential: &str,
) -> Result<ApplicationCredentialScope, AgentSessionError> {
    authenticate(pool, credential)
        .await
        .map_err(|error| match error {
            crate::application_credentials::ApplicationCredentialError::InvalidToken(_) => {
                AgentSessionError::Unauthenticated("invalid or revoked application credential")
            }
            crate::application_credentials::ApplicationCredentialError::Database(error) => {
                internal(error)
            }
        })?
        .ok_or(AgentSessionError::Unauthenticated(
            "invalid or revoked application credential",
        ))
}

async fn resolve_session_scope(
    pool: &PgPool,
    application: ApplicationCredentialScope,
    hello: &AgentHello,
) -> Result<SessionScope, AgentSessionError> {
    let cluster_uid = Uuid::parse_str(&hello.cluster_uid)
        .map_err(|_| AgentSessionError::invalid("cluster_uid must be a UUID"))?;
    let canonical_uid = cluster_uid.to_string();
    if canonical_uid != hello.cluster_uid {
        return Err(AgentSessionError::invalid("cluster_uid must be canonical"));
    }
    let cluster_name = cluster_display_name(&hello.cluster_name)?;
    let resolved_cluster_id: Uuid = ClusterRepository::upsert_by_external_id(
        pool,
        Uuid::new_v4(),
        application.organization_id,
        canonical_uid,
        cluster_name,
    )
    .await
    .map_err(internal)?;
    Ok(SessionScope {
        organization_id: application.organization_id,
        cluster_id: resolved_cluster_id,
    })
}

fn cluster_display_name(value: &str) -> Result<Option<&str>, AgentSessionError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.trim() != value || value.chars().count() > 64 || value.chars().any(char::is_control) {
        return Err(AgentSessionError::invalid(
            "cluster_name must be a trimmed name of 1 to 64 characters",
        ));
    }
    Ok(Some(value))
}

async fn register(
    pool: &PgPool,
    scope: SessionScope,
    hello: &AgentHello,
    capabilities: &[String],
) -> Result<(Uuid, Uuid), sqlx::Error> {
    let architecture = platform_value(&hello.architecture, 64);
    let kernel_release = platform_value(&hello.kernel_release, 255);
    let agent_id: Uuid = ClusterRepository::register_agent(
        pool,
        Uuid::new_v4(),
        scope.organization_id,
        scope.cluster_id,
        &hello.node_name,
        &hello.agent_version,
        architecture,
        kernel_release,
        serde_json::json!(capabilities),
    )
    .await?;
    let session_id = Uuid::new_v4();
    ClusterRepository::open_session(
        pool,
        session_id,
        scope.organization_id,
        scope.cluster_id,
        agent_id,
        i32::try_from(event_model::PROTOCOL_VERSION).unwrap_or(i32::MAX),
    )
    .await?;
    Ok((agent_id, session_id))
}

fn platform_value(value: &str, max_len: usize) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()
        && !value.eq_ignore_ascii_case("unknown")
        && value.chars().count() <= max_len)
        .then_some(value)
}

async fn touch_agent(pool: &PgPool, agent_id: Uuid) -> Result<(), sqlx::Error> {
    ClusterRepository::touch_agent(pool, agent_id).await?;
    Ok(())
}

async fn persist_onboarding_status(
    pool: &PgPool,
    scope: ApplicationCredentialScope,
    node_name: &str,
    value: protocol::v1::OnboardingStatus,
) -> Result<(), AgentSessionError> {
    use protocol::v1::{OnboardingReason, OnboardingState};
    let state = match OnboardingState::try_from(value.state).ok() {
        Some(OnboardingState::AgentAuthenticated) => "agent_authenticated",
        Some(OnboardingState::WorkloadNotMatched) => "workload_not_matched",
        Some(OnboardingState::PermissionDenied) => "permission_denied",
        Some(OnboardingState::KernelUnsupported) => "kernel_unsupported",
        Some(OnboardingState::WaitingForEvent) => "waiting_for_event",
        _ => return Err(AgentSessionError::invalid("onboarding state is invalid")),
    };
    let reason = match OnboardingReason::try_from(value.reason).ok() {
        Some(OnboardingReason::Unspecified) => None,
        Some(OnboardingReason::SelectorNoMatch) => Some("selector_no_match"),
        Some(OnboardingReason::KubernetesWatchForbidden) => Some("kubernetes_watch_forbidden"),
        Some(OnboardingReason::EbpfUnavailable) => Some("ebpf_unavailable"),
        Some(OnboardingReason::BtfUnavailable) => Some("btf_unavailable"),
        Some(OnboardingReason::EventNotObserved) => Some("event_not_observed"),
        None => return Err(AgentSessionError::invalid("onboarding reason is invalid")),
    };
    let observed_at = chrono::DateTime::from_timestamp_nanos(value.observed_at_unix_nanos);
    if (chrono::Utc::now() - observed_at)
        .num_hours()
        .unsigned_abs()
        > 24
    {
        return Err(AgentSessionError::invalid(
            "onboarding timestamp is outside the accepted window",
        ));
    }
    InstallationRepository::record_status(
        pool,
        scope.organization_id,
        scope.project_id,
        scope.application_id,
        node_name,
        state,
        reason,
        observed_at,
    )
    .await
    .map_err(internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application_credentials::issue,
        bootstrap::{BootstrapConfig, bootstrap},
    };

    fn config(name: &str) -> BootstrapConfig {
        BootstrapConfig {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            cluster_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            organization_slug: name.into(),
            organization_name: name.into(),
            project_slug: "project".into(),
            project_name: "Project".into(),
            cluster_external_id: "cluster".into(),
            cluster_name: "Cluster".into(),
            application_slug: "app".into(),
            application_name: "Application".into(),
            cluster_credential: format!("cluster-{name}"),
            api_credential: format!("api-{name}"),
        }
    }

    fn hello(node_name: &str, architecture: &str, kernel_release: &str) -> AgentHello {
        AgentHello {
            agent_version: "test".into(),
            node_name: node_name.into(),
            architecture: architecture.into(),
            kernel_release: kernel_release.into(),
            capabilities: vec!["process.exec/v1".into()],
            drop_counters: None,
            cluster_uid: Uuid::new_v4().to_string(),
            cluster_name: "aliens".into(),
            resource_counters: None,
        }
    }

    #[test]
    fn validates_cluster_display_names_with_legacy_empty_support() {
        assert_eq!(cluster_display_name("").unwrap(), None);
        assert_eq!(
            cluster_display_name("production").unwrap(),
            Some("production")
        );
        assert!(cluster_display_name(&"я".repeat(64)).is_ok());
        for invalid in [
            " ",
            " production",
            "production ",
            "a\0b",
            "a\nb",
            &"я".repeat(65),
        ] {
            assert!(matches!(
                cluster_display_name(invalid).unwrap_err(),
                AgentSessionError::Invalid(_)
            ));
        }
    }

    #[test]
    fn normalizes_platform_values() {
        assert_eq!(platform_value(" x86_64 ", 64), Some("x86_64"));
        assert_eq!(platform_value("", 64), None);
        assert_eq!(platform_value(" UNKNOWN ", 64), None);
        assert_eq!(platform_value(&"x".repeat(65), 64), None);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn registration_persists_normalizes_and_refreshes_platform(pool: PgPool) {
        let values = config("agent-platform");
        let ids = bootstrap(&pool, &values).await.unwrap();
        let scope = SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        };

        let first = hello("node-a", " x86_64 ", "6.8.1");
        let (agent_id, _) = register(&pool, scope, &first, &first.capabilities)
            .await
            .unwrap();
        let stored: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT architecture,kernel_release FROM agents WHERE id=$1")
                .bind(agent_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, (Some("x86_64".into()), Some("6.8.1".into())));

        let second = hello("node-a", "unknown", "6.9.2");
        let (same_agent_id, _) = register(&pool, scope, &second, &second.capabilities)
            .await
            .unwrap();
        assert_eq!(same_agent_id, agent_id);
        let refreshed: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT architecture,kernel_release FROM agents WHERE id=$1")
                .bind(agent_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(refreshed, (None, Some("6.9.2".into())));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn cluster_name_refresh_preserves_identity_and_tenant_isolation(pool: PgPool) {
        let first = bootstrap(&pool, &config("cluster-name-first"))
            .await
            .unwrap();
        let second = bootstrap(&pool, &config("cluster-name-second"))
            .await
            .unwrap();
        let application = ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: first.organization_id,
            project_id: first.project_id,
            application_id: first.application_id,
        };
        let other_application = ApplicationCredentialScope {
            organization_id: second.organization_id,
            project_id: second.project_id,
            application_id: second.application_id,
            ..application
        };
        let mut greeting = hello("worker", "x86_64", "6.8");
        greeting.cluster_name.clear();
        let original = resolve_session_scope(&pool, application, &greeting)
            .await
            .unwrap();
        assert_eq!(
            stored_cluster_name(&pool, original.cluster_id).await,
            greeting.cluster_uid
        );
        greeting.cluster_name = "other tenant".into();
        let other = resolve_session_scope(&pool, other_application, &greeting)
            .await
            .unwrap();
        assert_ne!(original.cluster_id, other.cluster_id);
        for name in ["production", "renamed production", ""] {
            greeting.cluster_name = name.into();
            assert_eq!(
                resolve_session_scope(&pool, application, &greeting)
                    .await
                    .unwrap(),
                original
            );
            let expected = if name.is_empty() {
                "renamed production"
            } else {
                name
            };
            assert_eq!(
                stored_cluster_name(&pool, original.cluster_id).await,
                expected
            );
            assert_eq!(
                stored_cluster_name(&pool, other.cluster_id).await,
                "other tenant"
            );
        }
        greeting.cluster_name = " invalid ".into();
        assert!(matches!(
            resolve_session_scope(&pool, application, &greeting)
                .await
                .unwrap_err(),
            AgentSessionError::Invalid(_)
        ));
        assert_eq!(
            stored_cluster_name(&pool, original.cluster_id).await,
            "renamed production"
        );
    }

    async fn stored_cluster_name(pool: &PgPool, id: Uuid) -> String {
        sqlx::query_scalar("SELECT name FROM clusters WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn application_scope_discovers_and_reuses_tenant_cluster(pool: PgPool) {
        let first = bootstrap(&pool, &config("session-scope-first"))
            .await
            .unwrap();
        let second = bootstrap(&pool, &config("session-scope-second"))
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let issued = issue(
            &mut tx,
            first.organization_id,
            first.project_id,
            first.application_id,
            "session",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let application = authenticate_application(&pool, issued.token())
            .await
            .unwrap();
        let cluster_uid = Uuid::new_v4().to_string();
        let first_hello = AgentHello {
            cluster_uid: cluster_uid.clone(),
            ..hello("node-a", "x86_64", "6.8.1")
        };
        let (first_scope, repeated_scope) = tokio::join!(
            resolve_session_scope(&pool, application, &first_hello),
            resolve_session_scope(&pool, application, &first_hello)
        );
        let first_scope = first_scope.unwrap();
        let repeated_scope = repeated_scope.unwrap();
        assert_eq!(first_scope, repeated_scope);
        assert_eq!(
            stored_cluster_name(&pool, first_scope.cluster_id).await,
            "aliens"
        );

        let (first_registration, same_registration) = tokio::join!(
            register(&pool, first_scope, &first_hello, &first_hello.capabilities),
            register(&pool, first_scope, &first_hello, &first_hello.capabilities)
        );
        assert_eq!(first_registration.unwrap().0, same_registration.unwrap().0);

        let second_application = ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: second.organization_id,
            project_id: second.project_id,
            application_id: second.application_id,
        };
        let second_scope = resolve_session_scope(&pool, second_application, &first_hello)
            .await
            .unwrap();
        assert_ne!(first_scope.cluster_id, second_scope.cluster_id);
        assert_ne!(first_scope.organization_id, second_scope.organization_id);

        let malformed = AgentHello {
            cluster_uid: cluster_uid.to_ascii_uppercase(),
            ..first_hello
        };
        assert!(matches!(
            resolve_session_scope(&pool, application, &malformed)
                .await
                .unwrap_err(),
            AgentSessionError::Invalid(_)
        ));
    }

    /// An unknown or malformed credential is refused the same way, without
    /// telling which.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn unknown_credentials_are_unauthenticated(pool: PgPool) {
        let service = AgentIntakeService::new(pool);
        for credential in [
            "garbage",
            "oko_app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(matches!(
                service.authenticate(credential).await,
                Err(AgentSessionError::Unauthenticated(
                    "invalid or revoked application credential"
                ))
            ));
        }
    }
}
