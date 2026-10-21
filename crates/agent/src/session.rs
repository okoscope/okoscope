use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use protocol::v1::{
    AgentHello, AgentMessage, ControlResult, ControlStatus, DropCounters, agent_message,
    agent_service_client::AgentServiceClient, control_message, server_message,
};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Streaming,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

use crate::{config::ServerConfig, counters::CounterSnapshot};

#[derive(Debug)]
pub struct SessionHandle {
    pub sender: mpsc::Sender<AgentMessage>,
    pub incoming: Streaming<protocol::v1::ServerMessage>,
}

/// Bounds connecting the channel and opening the session, so a server that
/// accepts TCP but never answers cannot hold a stream forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Reconnect delays: the ceiling doubles from 250 ms to 30 s, and each delay
/// is drawn from the upper half of the ceiling so a fleet that lost the server
/// at once does not reconnect in lockstep.
#[derive(Debug)]
pub struct Backoff {
    ceiling: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            ceiling: Self::INITIAL,
        }
    }
}

impl Backoff {
    pub const INITIAL: Duration = Duration::from_millis(250);
    pub const MAX: Duration = Duration::from_secs(30);

    /// The delay before the next attempt; the ceiling then doubles.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling;
        self.ceiling = (ceiling * 2).min(Self::MAX);
        let half = ceiling / 2;
        half + half.mul_f64(rand::random::<f64>())
    }

    /// Jumps to the longest delay, for failures that a retry soon cannot fix.
    pub fn exhaust(&mut self) -> Duration {
        self.ceiling = Self::MAX;
        self.next_delay()
    }

    pub fn reset(&mut self) {
        self.ceiling = Self::INITIAL;
    }

    /// The delay before reconnecting after a session that lasted `lasted`. A
    /// session that held for the longest delay reconnects at once with a fresh
    /// backoff; one that ended sooner, for example because the server accepted
    /// and then closed it, keeps backing off instead of looping.
    pub fn after_session(&mut self, lasted: Duration) -> Duration {
        if lasted >= Self::MAX {
            self.reset();
            Duration::ZERO
        } else {
            self.next_delay()
        }
    }
}

/// Opens a session, retrying with `backoff` until one opens. Returns `None`
/// once `shutdown` is signalled. Rejections such as a revoked credential or an
/// unsupported protocol version keep retrying at the longest delay, since a
/// rotated credential or an upgraded server can clear them.
pub async fn connect(
    config: &ServerConfig,
    credential: &str,
    hello: &AgentHello,
    backoff: &mut Backoff,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<SessionHandle> {
    loop {
        if *shutdown.borrow() {
            return None;
        }
        let attempt =
            tokio::time::timeout(OPEN_TIMEOUT, open_once(config, credential, hello.clone()))
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("opening the session timed out")));
        let error = match attempt {
            Ok(session) => return Some(session),
            Err(error) => error,
        };
        let delay = if is_rejection(&error) {
            let delay = backoff.exhaust();
            tracing::error!(error = ?error, ?delay, "server rejected the agent session; retrying");
            delay
        } else {
            let delay = backoff.next_delay();
            tracing::warn!(error = ?error, ?delay, "agent session connection failed; retrying");
            delay
        };
        if !sleep_unless_shutdown(delay, shutdown).await {
            return None;
        }
    }
}

/// Sleeps for `delay` unless `shutdown` is signalled first; returns whether
/// the caller should carry on.
pub async fn sleep_unless_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
    }
}

/// Whether the server refused the session for a reason a quick retry will not
/// change.
fn is_rejection(error: &anyhow::Error) -> bool {
    error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        matches!(
            status.code(),
            tonic::Code::Unauthenticated
                | tonic::Code::PermissionDenied
                | tonic::Code::FailedPrecondition
                | tonic::Code::InvalidArgument
        )
    })
}

async fn open_once(
    config: &ServerConfig,
    credential: &str,
    hello: AgentHello,
) -> Result<SessionHandle> {
    let channel = channel(config).await?;
    let mut client = AgentServiceClient::new(channel);
    let (sender, receiver) = mpsc::channel(32);
    sender
        .send(AgentMessage {
            protocol_version: event_model::PROTOCOL_VERSION,
            message: Some(agent_message::Message::Hello(hello)),
        })
        .await?;
    let mut request = Request::new(ReceiverStream::new(receiver));
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {credential}"))?,
    );
    let incoming = client.open_session(request).await?.into_inner();
    Ok(SessionHandle { sender, incoming })
}

async fn channel(config: &ServerConfig) -> Result<Channel> {
    let mut endpoint =
        Endpoint::from_shared(config.endpoint.clone())?.connect_timeout(CONNECT_TIMEOUT);
    if config.development_plaintext {
        return endpoint
            .connect()
            .await
            .context("connect plaintext development channel");
    }
    let tls = tls_config(config).await?;
    endpoint = endpoint.tls_config(tls)?;
    endpoint.connect().await.context("connect TLS channel")
}

async fn tls_config(config: &ServerConfig) -> Result<ClientTlsConfig> {
    let Some(ca_path) = config.ca_file.as_deref() else {
        return Ok(ClientTlsConfig::new().with_native_roots());
    };
    let ca = tokio::fs::read(Path::new(ca_path))
        .await
        .with_context(|| format!("read custom CA certificate from {ca_path}"))?;
    Ok(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))
}

#[must_use]
pub fn handle_control(control: protocol::v1::ControlMessage) -> ControlResult {
    let (status, detail) = match control.command {
        Some(control_message::Command::Ping(_)) => (ControlStatus::Applied, "pong"),
        None => (
            ControlStatus::Unsupported,
            "unsupported or missing typed command",
        ),
    };
    ControlResult {
        request_id: control.request_id,
        status: status.into(),
        detail: detail.into(),
    }
}

#[must_use]
pub fn server_message_kind(message: &protocol::v1::ServerMessage) -> &'static str {
    match message.message {
        Some(server_message::Message::SessionAccepted(_)) => "session_accepted",
        Some(server_message::Message::BatchAcknowledgement(_)) => "batch_acknowledgement",
        Some(server_message::Message::ResourceBatchAcknowledgement(_)) => {
            "resource_batch_acknowledgement"
        }
        Some(server_message::Message::Control(_)) => "control",
        None => "unknown",
    }
}

impl From<CounterSnapshot> for DropCounters {
    fn from(value: CounterSnapshot) -> Self {
        Self {
            filtered: value.filtered,
            unattributed: value.unattributed,
            unsupported: value.unsupported,
            decode_failed: value.decode_failed,
            capacity: value.capacity_dropped,
            kernel_lost: value.kernel_lost,
            connect_correlation_capacity: value.connect_correlation_capacity,
            connect_correlation_miss: value.connect_correlation_miss,
            connect_decode_failed: value.connect_decode_failed,
            connect_unsupported_family: value.connect_unsupported_family,
            connect_kernel_lost: value.connect_kernel_lost,
            dns_packet_decode_failed: value.dns_packet_decode_failed,
            dns_malformed_compression: value.dns_malformed_compression,
            dns_truncated: value.dns_truncated,
            dns_unsupported_record: value.dns_unsupported_record,
            dns_correlation_miss: value.dns_correlation_miss,
            dns_correlation_capacity: value.dns_correlation_capacity,
            dns_tcp_reassembly: value.dns_tcp_reassembly,
            dns_rate_limited: value.dns_rate_limited,
            dns_capacity: value.dns_capacity,
            dns_kernel_lost: value.dns_kernel_lost,
            dns_kernel_unsupported_framing: value.dns_kernel_unsupported_framing,
            dns_attribution_failed: value.dns_attribution_failed,
            dns_oversize: value.dns_oversize,
            inbound_decode_failed: value.inbound_decode_failed,
            inbound_attribution_failed: value.inbound_attribution_failed,
            inbound_unsupported_family: value.inbound_unsupported_family,
            inbound_kernel_lost: value.inbound_kernel_lost,
            inbound_rate_limited: value.inbound_rate_limited,
            inbound_correlation_miss: value.inbound_correlation_miss,
            file_correlation_capacity: value.file_correlation_capacity,
            file_correlation_miss: value.file_correlation_miss,
            file_path_read_failed: value.file_path_read_failed,
            file_path_relative: value.file_path_relative,
            file_path_invalid: value.file_path_invalid,
            file_path_oversize: value.file_path_oversize,
            file_fd_miss: value.file_fd_miss,
            file_filtered: value.file_filtered,
            file_kernel_lost: value.file_kernel_lost,
            file_aggregation_capacity: value.file_aggregation_capacity,
            file_decode_failed: value.file_decode_failed,
            file_attribution_failed: value.file_attribution_failed,
            file_rate_limited: value.file_rate_limited,
            file_unsupported_object: value.file_unsupported_object,
            exit_decode_failed: value.exit_decode_failed,
            exit_kernel_lost: value.exit_kernel_lost,
            exit_attribution_failed: value.exit_attribution_failed,
            exit_rate_limited: value.exit_rate_limited,
            exit_correlation_before_observation: value.exit_correlation_before_observation,
            exit_correlation_evicted: value.exit_correlation_evicted,
            exit_correlation_generation_mismatch: value.exit_correlation_generation_mismatch,
            exit_correlation_container_mismatch: value.exit_correlation_container_mismatch,
            lifecycle_capacity: value.lifecycle_capacity,
            lifecycle_invalid_status: value.lifecycle_invalid_status,
            lifecycle_deduplicated: value.lifecycle_deduplicated,
            lifecycle_attribution_failed: value.lifecycle_attribution_failed,
            release_evidence_complete: value.release_evidence_complete,
            release_evidence_incomplete: value.release_evidence_incomplete,
            release_evidence_duplicate: value.release_evidence_duplicate,
            release_evidence_conflict: value.release_evidence_conflict,
            release_evidence_sent: value.release_evidence_sent,
            release_evidence_replayed: value.release_evidence_replayed,
            release_evidence_dropped: value.release_evidence_dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_its_cap_with_jitter_and_resets() {
        let mut backoff = Backoff::default();
        let mut ceiling = Backoff::INITIAL;
        for _ in 0..12 {
            let delay = backoff.next_delay();
            assert!(
                delay >= ceiling / 2 && delay <= ceiling,
                "{delay:?} outside the upper half of {ceiling:?}"
            );
            ceiling = (ceiling * 2).min(Backoff::MAX);
        }
        assert_eq!(ceiling, Backoff::MAX, "the ceiling stops at the cap");
        backoff.reset();
        assert!(backoff.next_delay() <= Backoff::INITIAL);
        assert!(backoff.exhaust() >= Backoff::MAX / 2);
    }

    #[test]
    fn short_sessions_keep_backing_off() {
        let mut backoff = Backoff::default();
        for _ in 0..8 {
            backoff.after_session(Duration::from_secs(1));
        }
        assert!(
            backoff.after_session(Duration::from_secs(1)) >= Backoff::MAX / 2,
            "a server that keeps closing new sessions is retried at the longest delay"
        );
        assert_eq!(backoff.after_session(Backoff::MAX), Duration::ZERO);
        assert!(
            backoff.next_delay() <= Backoff::INITIAL,
            "a lasting session resets"
        );
    }

    #[test]
    fn rejections_are_told_apart_from_transport_failures() {
        let rejected = anyhow::Error::from(tonic::Status::unauthenticated("revoked credential"));
        let mismatched = anyhow::Error::from(tonic::Status::failed_precondition("protocol 3"));
        let unavailable = anyhow::Error::from(tonic::Status::unavailable("restarting"));
        assert!(is_rejection(&rejected));
        assert!(is_rejection(&mismatched));
        assert!(!is_rejection(&unavailable));
        assert!(!is_rejection(&anyhow::anyhow!("connection refused")));
    }

    #[tokio::test]
    async fn connecting_stops_at_shutdown() {
        let config = ServerConfig {
            // Nothing listens on port 1, so every attempt is refused at once.
            endpoint: "http://127.0.0.1:1".into(),
            development_plaintext: true,
            ca_file: None,
        };
        let (signal, mut shutdown) = watch::channel(false);
        let mut backoff = Backoff::default();
        let connecting = tokio::spawn(async move {
            connect(
                &config,
                "credential",
                &AgentHello::default(),
                &mut backoff,
                &mut shutdown,
            )
            .await
            .is_none()
        });
        signal.send(true).unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("shutdown interrupts the retry loop")
            .unwrap();
        assert!(stopped);
    }

    fn tls_server_config(ca_file: Option<&str>) -> ServerConfig {
        ServerConfig {
            endpoint: "https://okoscope.example.com:443".into(),
            development_plaintext: false,
            ca_file: ca_file.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn custom_ca_tls_does_not_require_native_roots() {
        let path = std::env::temp_dir().join(format!("okoscope-ca-{}.pem", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, b"custom CA fixture").await.unwrap();
        let config = tls_server_config(path.to_str());

        let result = tls_config(&config).await;

        tokio::fs::remove_file(path).await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn custom_ca_read_error_identifies_configured_file() {
        let path = format!("/missing/okoscope-ca-{}.pem", uuid::Uuid::new_v4());
        let error = tls_config(&tls_server_config(Some(&path)))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(&path));
    }

    #[tokio::test]
    async fn absent_custom_ca_keeps_system_roots_mode() {
        assert!(tls_config(&tls_server_config(None)).await.is_ok());
    }

    #[test]
    fn missing_control_variant_is_unsupported() {
        let result = handle_control(protocol::v1::ControlMessage {
            request_id: "1".into(),
            command: None,
        });
        assert_eq!(result.status, i32::from(ControlStatus::Unsupported));
    }

    #[test]
    fn network_drop_counters_are_transported_additively() {
        let wire = DropCounters::from(CounterSnapshot {
            connect_correlation_capacity: 1,
            connect_correlation_miss: 2,
            connect_decode_failed: 3,
            connect_unsupported_family: 4,
            connect_kernel_lost: 5,
            ..CounterSnapshot::default()
        });
        assert_eq!(wire.connect_correlation_capacity, 1);
        assert_eq!(wire.connect_correlation_miss, 2);
        assert_eq!(wire.connect_decode_failed, 3);
        assert_eq!(wire.connect_unsupported_family, 4);
        assert_eq!(wire.connect_kernel_lost, 5);
    }

    #[test]
    fn dns_drop_counters_are_transported_additively() {
        let wire = DropCounters::from(CounterSnapshot {
            dns_packet_decode_failed: 1,
            dns_malformed_compression: 2,
            dns_truncated: 3,
            dns_unsupported_record: 4,
            dns_correlation_miss: 5,
            dns_correlation_capacity: 6,
            dns_tcp_reassembly: 7,
            dns_rate_limited: 8,
            dns_capacity: 9,
            dns_kernel_lost: 10,
            ..CounterSnapshot::default()
        });
        assert_eq!(wire.dns_packet_decode_failed, 1);
        assert_eq!(wire.dns_malformed_compression, 2);
        assert_eq!(wire.dns_truncated, 3);
        assert_eq!(wire.dns_unsupported_record, 4);
        assert_eq!(wire.dns_correlation_miss, 5);
        assert_eq!(wire.dns_correlation_capacity, 6);
        assert_eq!(wire.dns_tcp_reassembly, 7);
        assert_eq!(wire.dns_rate_limited, 8);
        assert_eq!(wire.dns_capacity, 9);
        assert_eq!(wire.dns_kernel_lost, 10);
    }

    #[test]
    fn inbound_drop_counters_are_transported_additively() {
        let wire = DropCounters::from(CounterSnapshot {
            inbound_decode_failed: 1,
            inbound_attribution_failed: 2,
            inbound_unsupported_family: 3,
            inbound_kernel_lost: 4,
            inbound_rate_limited: 5,
            inbound_correlation_miss: 6,
            ..CounterSnapshot::default()
        });
        assert_eq!(wire.inbound_decode_failed, 1);
        assert_eq!(wire.inbound_attribution_failed, 2);
        assert_eq!(wire.inbound_unsupported_family, 3);
        assert_eq!(wire.inbound_kernel_lost, 4);
        assert_eq!(wire.inbound_rate_limited, 5);
        assert_eq!(wire.inbound_correlation_miss, 6);
    }

    #[test]
    fn file_drop_counters_are_transported_additively() {
        let wire = DropCounters::from(CounterSnapshot {
            file_correlation_capacity: 1,
            file_correlation_miss: 2,
            file_path_read_failed: 3,
            file_path_relative: 4,
            file_path_invalid: 5,
            file_path_oversize: 6,
            file_fd_miss: 7,
            file_filtered: 8,
            file_kernel_lost: 9,
            file_aggregation_capacity: 10,
            file_decode_failed: 11,
            file_attribution_failed: 12,
            file_rate_limited: 13,
            file_unsupported_object: 14,
            ..CounterSnapshot::default()
        });
        assert_eq!(wire.file_correlation_capacity, 1);
        assert_eq!(wire.file_correlation_miss, 2);
        assert_eq!(wire.file_path_read_failed, 3);
        assert_eq!(wire.file_path_relative, 4);
        assert_eq!(wire.file_path_invalid, 5);
        assert_eq!(wire.file_path_oversize, 6);
        assert_eq!(wire.file_fd_miss, 7);
        assert_eq!(wire.file_filtered, 8);
        assert_eq!(wire.file_kernel_lost, 9);
        assert_eq!(wire.file_aggregation_capacity, 10);
        assert_eq!(wire.file_decode_failed, 11);
        assert_eq!(wire.file_attribution_failed, 12);
        assert_eq!(wire.file_rate_limited, 13);
        assert_eq!(wire.file_unsupported_object, 14);
    }

    #[test]
    fn termination_drop_counters_are_transported_additively() {
        let wire = DropCounters::from(CounterSnapshot {
            exit_decode_failed: 1,
            exit_kernel_lost: 2,
            exit_attribution_failed: 3,
            exit_rate_limited: 4,
            exit_correlation_before_observation: 5,
            exit_correlation_evicted: 6,
            exit_correlation_generation_mismatch: 7,
            exit_correlation_container_mismatch: 8,
            lifecycle_capacity: 9,
            lifecycle_invalid_status: 10,
            lifecycle_deduplicated: 11,
            lifecycle_attribution_failed: 12,
            ..CounterSnapshot::default()
        });
        assert_eq!(wire.exit_decode_failed, 1);
        assert_eq!(wire.exit_kernel_lost, 2);
        assert_eq!(wire.exit_attribution_failed, 3);
        assert_eq!(wire.exit_rate_limited, 4);
        assert_eq!(wire.exit_correlation_before_observation, 5);
        assert_eq!(wire.exit_correlation_evicted, 6);
        assert_eq!(wire.exit_correlation_generation_mismatch, 7);
        assert_eq!(wire.exit_correlation_container_mismatch, 8);
        assert_eq!(wire.lifecycle_capacity, 9);
        assert_eq!(wire.lifecycle_invalid_status, 10);
        assert_eq!(wire.lifecycle_deduplicated, 11);
        assert_eq!(wire.lifecycle_attribution_failed, 12);
    }
}
