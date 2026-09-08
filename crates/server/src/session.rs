use std::pin::Pin;

use futures::{Stream, StreamExt};
use protocol::{
    v1::{
        AgentHello, AgentMessage, BatchAcknowledgement, ResourceBatchAcknowledgement,
        ServerMessage, SessionAccepted, agent_message, agent_service_server::AgentService,
        server_message,
    },
    validate_protocol,
};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming, metadata::MetadataMap};
use uuid::Uuid;

use crate::{
    application_credentials::{ApplicationCredentialScope, authenticate},
    auth::SessionScope,
    ingestion::persist_application_batch_outcome,
};

#[derive(Clone, Debug)]
pub struct AgentSessionService {
    pool: PgPool,
}

impl AgentSessionService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

type ResponseStream = Pin<Box<dyn Stream<Item = Result<ServerMessage, Status>> + Send + 'static>>;

#[derive(Clone, Copy)]
struct AgentCapabilities {
    mask: u8,
}

impl AgentCapabilities {
    fn has(self, flag: u8) -> bool {
        self.mask & flag != 0
    }
}

fn agent_capabilities(hello: &AgentHello) -> AgentCapabilities {
    let has = |capability: &str| hello.capabilities.iter().any(|value| value == capability);
    AgentCapabilities {
        mask: u8::from(has(protocol::FILE_ACTIVITY_CAPABILITY))
            | u8::from(has(protocol::KUBERNETES_RELEASE_DISCOVERY_CAPABILITY)) << 1
            | u8::from(has(protocol::ONBOARDING_STATUS_CAPABILITY)) << 2
            | u8::from(has(protocol::RESOURCE_UTILIZATION_CAPABILITY)) << 3,
    }
}

#[tonic::async_trait]
impl AgentService for AgentSessionService {
    type OpenSessionStream = ResponseStream;

    async fn open_session(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        let credential = bearer(request.metadata())?;
        let application_scope = authenticate_application(&self.pool, &credential).await?;
        let mut incoming = request.into_inner();
        let first = incoming
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("hello message is required"))?;
        validate_protocol(first.protocol_version)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let hello = match first.message {
            Some(agent_message::Message::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("first message must be hello")),
        };
        let scope = resolve_session_scope(&self.pool, application_scope, &hello).await?;
        let (agent_id, _session_id) = register(&self.pool, scope, &hello)
            .await
            .map_err(internal)?;
        let capabilities = agent_capabilities(&hello);
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(Ok(ServerMessage {
                protocol_version: event_model::PROTOCOL_VERSION,
                message: Some(server_message::Message::SessionAccepted(SessionAccepted {
                    organization_id: scope.organization_id.to_string(),
                    cluster_id: scope.cluster_id.to_string(),
                    agent_id: agent_id.to_string(),
                    negotiated_protocol_version: event_model::PROTOCOL_VERSION,
                    project_id: application_scope.project_id.to_string(),
                    application_id: application_scope.application_id.to_string(),
                })),
            }))
            .await
            .map_err(|_| Status::unavailable("session response channel closed"))?;
        let pool = self.pool.clone();
        tokio::spawn(async move {
            while let Some(next) = incoming.next().await {
                let result = async {
                    let message = next?;
                    validate_protocol(message.protocol_version).map_err(|error| Status::failed_precondition(error.to_string()))?;
                    match message.message {
                        Some(agent_message::Message::EventBatch(batch)) => {
                            let mut events = batch.events.into_iter().map(event_model::RuntimeEvent::try_from).collect::<Result<Vec<_>, _>>().map_err(|error| Status::invalid_argument(error.to_string()))?;
                            if !capabilities.has(1) && events.iter().any(|event| matches!(event.payload,
                                event_model::EventPayload::FileCreate(_)
                                | event_model::EventPayload::FileModify(_)
                                | event_model::EventPayload::FileDelete(_)
                                | event_model::EventPayload::FileRename(_))) {
                                return Err(Status::failed_precondition("file activity event requires file.activity.syscall-path/v1 capability"));
                            }
                            let (accepted, retention_expired_events) = persist_application_batch_outcome(&pool, scope, application_scope, agent_id, &mut events).await.map_err(|error| match error {
                                crate::ingestion::IngestionError::RevokedCredential => Status::unauthenticated("application credential was revoked"),
                                other => internal(other),
                            })?;
                            sender.send(Ok(ServerMessage { protocol_version: event_model::PROTOCOL_VERSION, message: Some(server_message::Message::BatchAcknowledgement(BatchAcknowledgement { sequence: batch.sequence, accepted_events: accepted, retention_expired_events })) })).await.map_err(|_| Status::unavailable("session response channel closed"))?;
                        }
                        Some(agent_message::Message::Heartbeat(_)) => { touch_agent(&pool, agent_id).await.map_err(internal)?; }
                        Some(agent_message::Message::ResourceSampleBatch(_)) if !capabilities.has(1 << 3) => return Err(Status::failed_precondition("resource samples require resource.utilization/v1 capability")),
                        Some(agent_message::Message::ResourceSampleBatch(batch)) => {
                            if batch.aggregates.len() > event_model::MAX_RESOURCE_BATCH_AGGREGATES {
                                return Err(Status::invalid_argument("resource batch exceeds 256 aggregates"));
                            }
                            let acknowledgement = persist_resource_batch(
                                &pool, scope, application_scope, agent_id, &hello.node_name, batch,
                            ).await?;
                            sender.send(Ok(ServerMessage {
                                protocol_version: event_model::PROTOCOL_VERSION,
                                message: Some(server_message::Message::ResourceBatchAcknowledgement(acknowledgement)),
                            })).await.map_err(|_| Status::unavailable("session response channel closed"))?;
                        }
                        Some(agent_message::Message::ControlResult(result)) => { tracing::info!(agent_id=%agent_id, request_id=%result.request_id, status=result.status, "agent control result"); }
                        Some(agent_message::Message::RevisionEvidence(_) | agent_message::Message::ReadinessSnapshot(_)) if !capabilities.has(1 << 1) => return Err(Status::failed_precondition("revision evidence requires kubernetes.release-discovery/v1 capability")),
                        Some(agent_message::Message::RevisionEvidence(value)) => {
                            let evidence = event_model::WorkloadRevisionEvidence::try_from(value).map_err(|error| Status::invalid_argument(error.to_string()))?;
                            crate::release_discovery::persist_revision_evidence(&pool, scope, application_scope, &evidence).await.map_err(internal)?;
                        }
                        Some(agent_message::Message::ReadinessSnapshot(value)) => {
                            let snapshot = event_model::RevisionReadinessSnapshot::try_from(value).map_err(|error| Status::invalid_argument(error.to_string()))?;
                            crate::release_discovery::persist_readiness_snapshot(&pool, scope, application_scope, &snapshot).await.map_err(internal)?;
                        }
                        Some(agent_message::Message::OnboardingStatus(_)) if !capabilities.has(1 << 2) => return Err(Status::failed_precondition("onboarding status requires onboarding.status/v1 capability")),
                        Some(agent_message::Message::OnboardingStatus(value)) => {
                            persist_onboarding_status(&pool, application_scope, &hello.node_name, value).await?;
                        }
                        Some(agent_message::Message::Hello(_)) => return Err(Status::invalid_argument("hello can only be sent once")),
                        None => return Err(Status::invalid_argument("unknown or missing typed agent message")),
                    }
                    Ok::<(), Status>(())
                }.await;
                if let Err(status) = result {
                    let _ = sender.send(Err(status)).await;
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

async fn persist_resource_batch(
    pool: &PgPool,
    scope: SessionScope,
    application_scope: ApplicationCredentialScope,
    agent_id: Uuid,
    node_name: &str,
    batch: protocol::v1::ResourceSampleBatch,
) -> Result<ResourceBatchAcknowledgement, Status> {
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
) -> Result<ApplicationCredentialScope, Status> {
    authenticate(pool, credential)
        .await
        .map_err(|error| match error {
            crate::application_credentials::ApplicationCredentialError::InvalidToken(_) => {
                Status::unauthenticated("invalid or revoked application credential")
            }
            crate::application_credentials::ApplicationCredentialError::Database(error) => {
                internal(error)
            }
        })?
        .ok_or_else(|| Status::unauthenticated("invalid or revoked application credential"))
}

async fn resolve_session_scope(
    pool: &PgPool,
    application: ApplicationCredentialScope,
    hello: &AgentHello,
) -> Result<SessionScope, Status> {
    let cluster_uid = Uuid::parse_str(&hello.cluster_uid)
        .map_err(|_| Status::invalid_argument("cluster_uid must be a UUID"))?;
    let canonical_uid = cluster_uid.to_string();
    if canonical_uid != hello.cluster_uid {
        return Err(Status::invalid_argument("cluster_uid must be canonical"));
    }
    let cluster_name = cluster_display_name(&hello.cluster_name)?;
    let resolved_cluster_id: Uuid = sqlx::query_scalar(
        "INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,$3,COALESCE($4,$3)) ON CONFLICT(organization_id,external_id) DO UPDATE SET name=COALESCE($4,clusters.name) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(application.organization_id)
    .bind(canonical_uid)
    .bind(cluster_name)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    Ok(SessionScope {
        organization_id: application.organization_id,
        cluster_id: resolved_cluster_id,
    })
}

fn cluster_display_name(value: &str) -> Result<Option<&str>, Status> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.trim() != value || value.chars().count() > 64 || value.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "cluster_name must be a trimmed name of 1 to 64 characters",
        ));
    }
    Ok(Some(value))
}

fn bearer(metadata: &MetadataMap) -> Result<String, Status> {
    let value = metadata
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("authorization metadata is required"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("authorization metadata is invalid"))?;
    value
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Status::unauthenticated("Bearer credential is required"))
}

async fn register(
    pool: &PgPool,
    scope: SessionScope,
    hello: &AgentHello,
) -> Result<(Uuid, Uuid), sqlx::Error> {
    let architecture = platform_value(&hello.architecture, 64);
    let kernel_release = platform_value(&hello.kernel_release, 255);
    let agent_id: Uuid = sqlx::query_scalar("INSERT INTO agents (id, organization_id, cluster_id, node_name, agent_version, architecture, kernel_release, capabilities) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cluster_id, node_name) DO UPDATE SET agent_version=EXCLUDED.agent_version, architecture=EXCLUDED.architecture, kernel_release=EXCLUDED.kernel_release, capabilities=EXCLUDED.capabilities, last_seen_at=now() RETURNING id")
        .bind(Uuid::new_v4()).bind(scope.organization_id).bind(scope.cluster_id).bind(&hello.node_name).bind(&hello.agent_version).bind(architecture).bind(kernel_release).bind(serde_json::json!(hello.capabilities)).fetch_one(pool).await?;
    let session_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_sessions (id, organization_id, cluster_id, agent_id, protocol_version) VALUES ($1,$2,$3,$4,$5)")
        .bind(session_id).bind(scope.organization_id).bind(scope.cluster_id).bind(agent_id).bind(i32::try_from(event_model::PROTOCOL_VERSION).unwrap_or(i32::MAX)).execute(pool).await?;
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
    sqlx::query("UPDATE agents SET last_seen_at=now() WHERE id=$1")
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn internal(error: impl std::fmt::Display) -> Status {
    tracing::error!(%error, "agent session failure");
    Status::internal("internal server error")
}

async fn persist_onboarding_status(
    pool: &PgPool,
    scope: ApplicationCredentialScope,
    node_name: &str,
    value: protocol::v1::OnboardingStatus,
) -> Result<(), Status> {
    use protocol::v1::{OnboardingReason, OnboardingState};
    let state = match OnboardingState::try_from(value.state).ok() {
        Some(OnboardingState::AgentAuthenticated) => "agent_authenticated",
        Some(OnboardingState::WorkloadNotMatched) => "workload_not_matched",
        Some(OnboardingState::PermissionDenied) => "permission_denied",
        Some(OnboardingState::KernelUnsupported) => "kernel_unsupported",
        Some(OnboardingState::WaitingForEvent) => "waiting_for_event",
        _ => return Err(Status::invalid_argument("onboarding state is invalid")),
    };
    let reason = match OnboardingReason::try_from(value.reason).ok() {
        Some(OnboardingReason::Unspecified) => None,
        Some(OnboardingReason::SelectorNoMatch) => Some("selector_no_match"),
        Some(OnboardingReason::KubernetesWatchForbidden) => Some("kubernetes_watch_forbidden"),
        Some(OnboardingReason::EbpfUnavailable) => Some("ebpf_unavailable"),
        Some(OnboardingReason::BtfUnavailable) => Some("btf_unavailable"),
        Some(OnboardingReason::EventNotObserved) => Some("event_not_observed"),
        None => return Err(Status::invalid_argument("onboarding reason is invalid")),
    };
    let observed_at = chrono::DateTime::from_timestamp_nanos(value.observed_at_unix_nanos);
    if (chrono::Utc::now() - observed_at)
        .num_hours()
        .unsigned_abs()
        > 24
    {
        return Err(Status::invalid_argument(
            "onboarding timestamp is outside the accepted window",
        ));
    }
    sqlx::query("INSERT INTO application_installation_status(installation_id,node_name,state,reason,observed_at) SELECT i.id,$4,$5,$6,$7 FROM application_installations i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 ORDER BY i.created_at DESC LIMIT 1 ON CONFLICT(installation_id,node_name) DO UPDATE SET state=EXCLUDED.state,reason=EXCLUDED.reason,observed_at=EXCLUDED.observed_at,updated_at=now() WHERE application_installation_status.observed_at<=EXCLUDED.observed_at")
        .bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id)
        .bind(node_name).bind(state).bind(reason).bind(observed_at)
        .execute(pool).await.map_err(internal)?;
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
            assert_eq!(
                cluster_display_name(invalid).unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
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

        let (agent_id, _) = register(&pool, scope, &hello("node-a", " x86_64 ", "6.8.1"))
            .await
            .unwrap();
        let stored: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT architecture,kernel_release FROM agents WHERE id=$1")
                .bind(agent_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, (Some("x86_64".into()), Some("6.8.1".into())));

        let (same_agent_id, _) = register(&pool, scope, &hello("node-a", "unknown", "6.9.2"))
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
        assert_eq!(
            resolve_session_scope(&pool, application, &greeting)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
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
            register(&pool, first_scope, &first_hello),
            register(&pool, first_scope, &first_hello)
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
        assert_eq!(
            resolve_session_scope(&pool, application, &malformed)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
}
