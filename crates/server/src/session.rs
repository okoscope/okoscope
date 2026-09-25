use std::pin::Pin;

use futures::{Stream, StreamExt};
use protocol::{
    v1::{
        AgentHello, AgentMessage, BatchAcknowledgement, ServerMessage, SessionAccepted,
        agent_message, agent_service_server::AgentService, server_message,
    },
    validate_protocol,
};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming, metadata::MetadataMap};

use crate::service::agent_sessions::{AgentIntakeService, AgentSessionError};

#[derive(Clone, Debug)]
pub struct AgentSessionService {
    intake: AgentIntakeService,
}

impl AgentSessionService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            intake: AgentIntakeService::new(pool),
        }
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

/// The gRPC status for a failed session step.
fn status(error: AgentSessionError) -> Status {
    match error {
        AgentSessionError::Unauthenticated(message) => Status::unauthenticated(message),
        AgentSessionError::Invalid(message) => Status::invalid_argument(message),
        AgentSessionError::Internal(error) => {
            tracing::error!(%error, "agent session failure");
            Status::internal("internal server error")
        }
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
        let application_scope = self
            .intake
            .authenticate(&credential)
            .await
            .map_err(status)?;
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
        let session = self
            .intake
            .establish(application_scope, &hello)
            .await
            .map_err(status)?;
        let capabilities = agent_capabilities(&hello);
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(Ok(ServerMessage {
                protocol_version: event_model::PROTOCOL_VERSION,
                message: Some(server_message::Message::SessionAccepted(SessionAccepted {
                    organization_id: session.scope.organization_id.to_string(),
                    cluster_id: session.scope.cluster_id.to_string(),
                    agent_id: session.agent_id.to_string(),
                    negotiated_protocol_version: event_model::PROTOCOL_VERSION,
                    project_id: application_scope.project_id.to_string(),
                    application_id: application_scope.application_id.to_string(),
                })),
            }))
            .await
            .map_err(|_| Status::unavailable("session response channel closed"))?;
        let intake = self.intake.clone();
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
                            let (accepted, retention_expired_events) = intake.persist_events(session, application_scope, &mut events).await.map_err(status)?;
                            sender.send(Ok(ServerMessage { protocol_version: event_model::PROTOCOL_VERSION, message: Some(server_message::Message::BatchAcknowledgement(BatchAcknowledgement { sequence: batch.sequence, accepted_events: accepted, retention_expired_events })) })).await.map_err(|_| Status::unavailable("session response channel closed"))?;
                        }
                        Some(agent_message::Message::Heartbeat(heartbeat)) => {
                            intake.heartbeat(session, application_scope, &heartbeat).await.map_err(status)?;
                        }
                        Some(agent_message::Message::ResourceSampleBatch(_)) if !capabilities.has(1 << 3) => return Err(Status::failed_precondition("resource samples require resource.utilization/v1 capability")),
                        Some(agent_message::Message::ResourceSampleBatch(batch)) => {
                            if batch.aggregates.len() > event_model::MAX_RESOURCE_BATCH_AGGREGATES {
                                return Err(Status::invalid_argument("resource batch exceeds 256 aggregates"));
                            }
                            let acknowledgement = intake.persist_resources(
                                session, application_scope, &hello.node_name, batch,
                            ).await.map_err(status)?;
                            sender.send(Ok(ServerMessage {
                                protocol_version: event_model::PROTOCOL_VERSION,
                                message: Some(server_message::Message::ResourceBatchAcknowledgement(acknowledgement)),
                            })).await.map_err(|_| Status::unavailable("session response channel closed"))?;
                        }
                        Some(agent_message::Message::ControlResult(result)) => { tracing::info!(agent_id=%session.agent_id, request_id=%result.request_id, status=result.status, "agent control result"); }
                        Some(agent_message::Message::RevisionEvidence(_) | agent_message::Message::ReadinessSnapshot(_)) if !capabilities.has(1 << 1) => return Err(Status::failed_precondition("revision evidence requires kubernetes.release-discovery/v1 capability")),
                        Some(agent_message::Message::RevisionEvidence(value)) => {
                            let evidence = event_model::WorkloadRevisionEvidence::try_from(value).map_err(|error| Status::invalid_argument(error.to_string()))?;
                            intake.persist_revision_evidence(session, application_scope, &evidence).await.map_err(status)?;
                        }
                        Some(agent_message::Message::ReadinessSnapshot(value)) => {
                            let snapshot = event_model::RevisionReadinessSnapshot::try_from(value).map_err(|error| Status::invalid_argument(error.to_string()))?;
                            intake.persist_readiness_snapshot(session, application_scope, &snapshot).await.map_err(status)?;
                        }
                        Some(agent_message::Message::OnboardingStatus(_)) if !capabilities.has(1 << 2) => return Err(Status::failed_precondition("onboarding status requires onboarding.status/v1 capability")),
                        Some(agent_message::Message::OnboardingStatus(value)) => {
                            intake.persist_onboarding_status(application_scope, &hello.node_name, value).await.map_err(status)?;
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
            intake.end(session, application_scope).await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
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
