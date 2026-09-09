use std::fmt;

use event_model::{
    EventPayload, GenerationCorrelation, NetworkAddressFamily, ProcessTermination, RuntimeEvent,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

pub const CURRENT_INVENTORY_IDENTITY_VERSION: InventoryIdentityVersion =
    InventoryIdentityVersion::new_unchecked(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryIdentityVersion(i16);

impl InventoryIdentityVersion {
    const fn new_unchecked(value: i16) -> Self {
        Self(value)
    }

    pub fn new(value: i16) -> Result<Self, InventoryFingerprintError> {
        (value > 0)
            .then_some(Self(value))
            .ok_or(InventoryFingerprintError::InvalidIdentityVersion)
    }

    pub const fn get(self) -> i16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryKind {
    Process,
    Destination,
    Domain,
    Syscall,
    InboundEndpoint,
    FileActivity,
    Lifecycle,
}

impl InventoryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Destination => "destination",
            Self::Domain => "domain",
            Self::Syscall => "syscall",
            Self::InboundEndpoint => "inbound_endpoint",
            Self::FileActivity => "file_activity",
            Self::Lifecycle => "lifecycle",
        }
    }
}

impl fmt::Display for InventoryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedInventoryScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryFingerprint {
    pub version: InventoryIdentityVersion,
    pub kind: InventoryKind,
    pub digest: [u8; 32],
    pub semantic_summary: Value,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum InventoryFingerprintError {
    #[error("inventory identity version must be positive")]
    InvalidIdentityVersion,
    #[error("inventory fingerprint field {0} must not be empty")]
    EmptyField(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionOutcome {
    pub item_id: Uuid,
    pub item_created: bool,
    pub membership_created: bool,
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn project_event(
    tx: &mut Transaction<'_, Postgres>,
    raw_event_id: Uuid,
    group_id: Uuid,
    release_id: Option<Uuid>,
    cluster_id: Uuid,
    organization_id: Uuid,
    event: &RuntimeEvent,
) -> Result<ProjectionOutcome, sqlx::Error> {
    let started_at = std::time::Instant::now();
    let scope = TrustedInventoryScope {
        organization_id,
        project_id: event.attribution.project_id,
        application_id: event.attribution.application_id,
    };
    let fingerprint =
        fingerprint(scope, event).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let version = fingerprint.version.get();
    let candidate_id = Uuid::new_v4();
    let created_item_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1) ON CONFLICT (organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest) DO NOTHING RETURNING id",
    )
    .bind(candidate_id)
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(scope.application_id)
    .bind(fingerprint.kind.as_str())
    .bind(version)
    .bind(fingerprint.digest.as_slice())
    .bind(&fingerprint.semantic_summary)
    .bind(event.observed_at)
    .fetch_optional(&mut **tx)
    .await?;

    let item_created = created_item_id.is_some();
    let item_id = if let Some(item_id) = created_item_id {
        item_id
    } else {
        sqlx::query_scalar(
            "SELECT id FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND inventory_kind=$4 AND identity_version=$5 AND identity_digest=$6 FOR UPDATE",
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(fingerprint.kind.as_str())
        .bind(version)
        .bind(fingerprint.digest.as_slice())
        .fetch_one(&mut **tx)
        .await?
    };

    let membership_created = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO runtime_inventory_event_memberships(organization_id,project_id,application_id,event_id,item_id,identity_version) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id,identity_version) DO NOTHING RETURNING event_id",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(scope.application_id)
    .bind(raw_event_id)
    .bind(item_id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await?
    .is_some();

    if !membership_created {
        let outcome = ProjectionOutcome {
            item_id,
            item_created: false,
            membership_created: false,
        };
        crate::metrics::record_inventory_projection(
            u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
            false,
            false,
        );
        return Ok(outcome);
    }

    if !item_created {
        let inbound_evidence = match &event.payload {
            EventPayload::NetworkListen(_) => Some((true, false)),
            EventPayload::NetworkAccept(_) => Some((false, true)),
            _ => None,
        };
        if let Some((listener_observed, accept_observed)) = inbound_evidence {
            sqlx::query(
                "UPDATE runtime_inventory_items SET first_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE LEAST(first_seen_at,$2) END,last_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE GREATEST(last_seen_at,$2) END,occurrence_count=occurrence_count+1,semantic_summary=jsonb_set(jsonb_set(semantic_summary,'{listener_observed}',to_jsonb(COALESCE((semantic_summary->>'listener_observed')::boolean,false) OR $3)),'{accept_observed}',to_jsonb(COALESCE((semantic_summary->>'accept_observed')::boolean,false) OR $4)),updated_at=now() WHERE id=$1",
            )
            .bind(item_id)
            .bind(event.observed_at)
            .bind(listener_observed)
            .bind(accept_observed)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE runtime_inventory_items SET first_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE LEAST(first_seen_at,$2) END,last_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE GREATEST(last_seen_at,$2) END,occurrence_count=occurrence_count+1,updated_at=now() WHERE id=$1",
            )
            .bind(item_id)
            .bind(event.observed_at)
            .execute(&mut **tx)
            .await?;
        }
    }

    sqlx::query(
        "INSERT INTO runtime_inventory_group_links(organization_id,project_id,application_id,item_id,group_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT (item_id,group_id) DO NOTHING",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(scope.application_id)
    .bind(item_id)
    .bind(group_id)
    .execute(&mut **tx)
    .await?;

    if let Some(release_id) = release_id {
        sqlx::query(
            "INSERT INTO runtime_inventory_releases(organization_id,project_id,application_id,item_id,release_id,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,1,$6,$6) ON CONFLICT (item_id,release_id) DO UPDATE SET occurrence_count=runtime_inventory_releases.occurrence_count+1,first_seen_at=LEAST(runtime_inventory_releases.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(runtime_inventory_releases.last_seen_at,EXCLUDED.last_seen_at),updated_at=now()",
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(item_id)
        .bind(release_id)
        .bind(event.observed_at)
        .execute(&mut **tx)
        .await?;
    }

    sqlx::query(
        "INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$12) ON CONFLICT (item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name) DO UPDATE SET occurrence_count=runtime_inventory_sightings.occurrence_count+1,first_seen_at=LEAST(runtime_inventory_sightings.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(runtime_inventory_sightings.last_seen_at,EXCLUDED.last_seen_at),pod_name=EXCLUDED.pod_name,updated_at=now()",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(scope.application_id)
    .bind(item_id)
    .bind(cluster_id)
    .bind(&event.attribution.namespace)
    .bind(&event.attribution.workload_kind)
    .bind(&event.attribution.workload_name)
    .bind(&event.attribution.pod_uid)
    .bind(&event.attribution.pod_name)
    .bind(&event.attribution.container_name)
    .bind(event.observed_at)
    .execute(&mut **tx)
    .await?;

    tracing::debug!(
        item_id = %item_id,
        inventory_kind = %fingerprint.kind,
        item_created,
        "runtime inventory event projected"
    );
    let outcome = ProjectionOutcome {
        item_id,
        item_created,
        membership_created,
    };
    crate::metrics::record_inventory_projection(
        u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
        item_created,
        membership_created,
    );
    Ok(outcome)
}

pub fn fingerprint(
    scope: TrustedInventoryScope,
    event: &RuntimeEvent,
) -> Result<InventoryFingerprint, InventoryFingerprintError> {
    fingerprint_with_version(scope, event, CURRENT_INVENTORY_IDENTITY_VERSION)
}

#[expect(
    clippy::too_many_lines,
    reason = "the typed event dispatch is intentionally exhaustive"
)]
fn fingerprint_with_version(
    scope: TrustedInventoryScope,
    event: &RuntimeEvent,
    version: InventoryIdentityVersion,
) -> Result<InventoryFingerprint, InventoryFingerprintError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.field(b"okoscope.application-runtime-inventory");
    encoder.field(&version.get().to_be_bytes());
    encoder.field(scope.organization_id.as_bytes());
    encoder.field(scope.project_id.as_bytes());
    encoder.field(scope.application_id.as_bytes());

    let (kind, semantic_summary) = match &event.payload {
        EventPayload::ProcessExec(process) => {
            let executable = required("executable", &process.executable)?;
            encoder.field(InventoryKind::Process.as_str().as_bytes());
            encoder.field(executable.as_bytes());
            (InventoryKind::Process, json!({"executable": executable}))
        }
        EventPayload::Syscall(syscall) => {
            let command = required("process_command", &event.process.command)?;
            let syscall = required("syscall_name", &syscall.name)?.to_ascii_lowercase();
            encoder.field(InventoryKind::Syscall.as_str().as_bytes());
            encoder.field(command.as_bytes());
            encoder.field(syscall.as_bytes());
            (
                InventoryKind::Syscall,
                json!({"process_command": command, "syscall": syscall}),
            )
        }
        EventPayload::NetworkConnect(connect) => {
            let command = required("process_command", &event.process.command)?;
            let family = match connect.address_family {
                NetworkAddressFamily::Ipv4 => "ipv4",
                NetworkAddressFamily::Ipv6 => "ipv6",
            };
            encoder.field(InventoryKind::Destination.as_str().as_bytes());
            encoder.field(command.as_bytes());
            encoder.field(family.as_bytes());
            match connect.destination_address {
                std::net::IpAddr::V4(address) => encoder.field(&address.octets()),
                std::net::IpAddr::V6(address) => encoder.field(&address.octets()),
            }
            encoder.field(&connect.destination_port.to_be_bytes());
            (
                InventoryKind::Destination,
                json!({
                    "process_command": command,
                    "address_family": family,
                    "destination_address": connect.destination_address,
                    "destination_port": connect.destination_port
                }),
            )
        }
        EventPayload::NetworkListen(network) => inbound_endpoint_fingerprint(
            &mut encoder,
            network.address_family,
            network.local_address,
            network.local_port,
            true,
        ),
        EventPayload::NetworkAccept(network) => inbound_endpoint_fingerprint(
            &mut encoder,
            network.address_family,
            network.local_address,
            network.local_port,
            false,
        ),
        EventPayload::NetworkDnsQuery(query) => {
            let command = required("process_command", &event.process.command)?;
            let query_type = dns_query_type(query.query_type);
            encoder.field(InventoryKind::Domain.as_str().as_bytes());
            encoder.field(command.as_bytes());
            encoder.field(query.name.as_str().as_bytes());
            encoder.field(query_type.as_bytes());
            (
                InventoryKind::Domain,
                json!({
                    "process_command": command,
                    "name": query.name,
                    "query_type": query.query_type
                }),
            )
        }
        EventPayload::NetworkDnsResponse(response) => {
            let command = required("process_command", &event.process.command)?;
            let query_type = dns_query_type(response.query_type);
            encoder.field(InventoryKind::Domain.as_str().as_bytes());
            encoder.field(command.as_bytes());
            encoder.field(response.name.as_str().as_bytes());
            encoder.field(query_type.as_bytes());
            (
                InventoryKind::Domain,
                json!({
                    "process_command": command,
                    "name": response.name,
                    "query_type": response.query_type
                }),
            )
        }
        EventPayload::FileCreate(value) => file_activity_fingerprint(
            &mut encoder,
            &event.process.command,
            "create",
            value.path.as_str(),
            None,
            None,
        )?,
        EventPayload::FileModify(value) => file_activity_fingerprint(
            &mut encoder,
            &event.process.command,
            "modify",
            value.path.as_str(),
            None,
            None,
        )?,
        EventPayload::FileDelete(value) => file_activity_fingerprint(
            &mut encoder,
            &event.process.command,
            "delete",
            value.path.as_str(),
            None,
            None,
        )?,
        EventPayload::FileRename(value) => file_activity_fingerprint(
            &mut encoder,
            &event.process.command,
            "rename",
            value.old_path.as_str(),
            Some(value.new_path.as_str()),
            value.replaced,
        )?,
        EventPayload::ProcessExit(value) => {
            let identity = match &value.correlation {
                GenerationCorrelation::Observed { executable, .. } => {
                    required("executable", executable)?
                }
                GenerationCorrelation::Unresolved { .. } => {
                    required("process_command", &event.process.command)?
                }
            };
            encoder.field(InventoryKind::Lifecycle.as_str().as_bytes());
            encoder.field(b"process.exit");
            encoder.field(identity.as_bytes());
            let termination = match &value.termination {
                ProcessTermination::Exited { status } => {
                    encoder.field(b"exited");
                    encoder.field(&[*status]);
                    json!({"type":"exited","status":status})
                }
                ProcessTermination::Signaled {
                    signal,
                    signal_name,
                    ..
                } => {
                    encoder.field(b"signaled");
                    encoder.field(&[*signal]);
                    json!({"type":"signaled","signal":signal,"signal_name":signal_name})
                }
            };
            (
                InventoryKind::Lifecycle,
                json!({"event_kind":"process.exit","identity":identity,"termination":termination,"evidence_source":value.source}),
            )
        }
        EventPayload::ContainerTermination(value) => {
            let container = required("container_name", &event.attribution.container_name)?;
            let reason = required("termination_reason", &value.reason)?;
            encoder.field(InventoryKind::Lifecycle.as_str().as_bytes());
            encoder.field(b"container.terminated");
            encoder.field(container.as_bytes());
            encoder.field(reason.as_bytes());
            encoder.field(&value.exit_code.to_be_bytes());
            (
                InventoryKind::Lifecycle,
                json!({"event_kind":"container.terminated","container_name":container,"reason":reason,"exit_code":value.exit_code,"evidence_source":value.source}),
            )
        }
        EventPayload::ContainerRestart(value) => {
            let container = required("container_name", &event.attribution.container_name)?;
            encoder.field(InventoryKind::Lifecycle.as_str().as_bytes());
            encoder.field(b"container.restart");
            encoder.field(container.as_bytes());
            (
                InventoryKind::Lifecycle,
                json!({"event_kind":"container.restart","container_name":container,"evidence_source":value.source,"restart_count":value.restart_count,"restart_delta":value.restart_delta,"observation_gap":value.observation_gap}),
            )
        }
    };

    Ok(InventoryFingerprint {
        version,
        kind,
        digest: encoder.finish(),
        semantic_summary,
    })
}

fn file_activity_fingerprint(
    encoder: &mut CanonicalEncoder,
    command: &str,
    operation: &str,
    path: &str,
    new_path: Option<&str>,
    replaced: Option<bool>,
) -> Result<(InventoryKind, Value), InventoryFingerprintError> {
    let command = required("process_command", command)?;
    encoder.field(InventoryKind::FileActivity.as_str().as_bytes());
    encoder.field(command.as_bytes());
    encoder.field(operation.as_bytes());
    encoder.field(path.as_bytes());
    if let Some(new_path) = new_path {
        encoder.field(new_path.as_bytes());
    }
    if let Some(replaced) = replaced {
        encoder.field(&[u8::from(replaced)]);
    }
    Ok((
        InventoryKind::FileActivity,
        json!({
            "process_command": command,
            "operation": operation,
            "path": path,
            "new_path": new_path,
            "replaced": replaced,
        }),
    ))
}

fn inbound_endpoint_fingerprint(
    encoder: &mut CanonicalEncoder,
    address_family: NetworkAddressFamily,
    local_address: std::net::IpAddr,
    local_port: u16,
    listener_observed: bool,
) -> (InventoryKind, serde_json::Value) {
    let family = match address_family {
        NetworkAddressFamily::Ipv4 => "ipv4",
        NetworkAddressFamily::Ipv6 => "ipv6",
    };
    encoder.field(InventoryKind::InboundEndpoint.as_str().as_bytes());
    encoder.field(b"tcp");
    encoder.field(family.as_bytes());
    match local_address {
        std::net::IpAddr::V4(address) => encoder.field(&address.octets()),
        std::net::IpAddr::V6(address) => encoder.field(&address.octets()),
    }
    encoder.field(&local_port.to_be_bytes());
    (
        InventoryKind::InboundEndpoint,
        json!({
            "transport": "tcp",
            "address_family": family,
            "local_address": local_address,
            "local_port": local_port,
            "listener_observed": listener_observed,
            "accept_observed": !listener_observed
        }),
    )
}

const fn dns_query_type(query_type: event_model::DnsQueryType) -> &'static str {
    match query_type {
        event_model::DnsQueryType::A => "A",
        event_model::DnsQueryType::Aaaa => "AAAA",
    }
}

fn required<'a>(field: &'static str, value: &'a str) -> Result<&'a str, InventoryFingerprintError> {
    let normalized =
        value.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if normalized.is_empty() {
        Err(InventoryFingerprintError::EmptyField(field))
    } else {
        Ok(normalized)
    }
}

#[derive(Debug)]
struct CanonicalEncoder(Sha256);

impl CanonicalEncoder {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn field(&mut self, bytes: &[u8]) {
        self.0
            .update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.0.update(bytes);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use event_model::{
        ContainerRestart, ContainerTermination, DnsAddressAnswer, DnsDirection, DnsName,
        DnsQueryType, DnsResponseCode, DnsTransport, EventPayload, FileActivityPath, FileModify,
        FileRename, GenerationCorrelation, KubernetesAttribution, NetworkAccept,
        NetworkAddressFamily, NetworkConnect, NetworkConnectOutcome, NetworkDnsQuery,
        NetworkDnsResponse, NetworkListen, ProcessExec, ProcessExit, ProcessIdentity,
        ProcessTermination, RuntimeEvent, SyscallEvent, UnresolvedGenerationReason,
    };

    use super::*;

    fn event(payload: EventPayload) -> RuntimeEvent {
        RuntimeEvent {
            id: Uuid::from_u128(10),
            observed_at: Utc::now(),
            schema_version: event_model::EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::from_u128(2),
                application_id: Uuid::from_u128(3),
                node_name: "node-a".into(),
                namespace: "payments".into(),
                pod_uid: "pod-a".into(),
                pod_name: "payments-a".into(),
                container_id: "container-a".into(),
                container_name: "api".into(),
                workload_uid: "workload-a".into(),
                workload_kind: "Deployment".into(),
                workload_name: "payments".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 10,
                tgid: 10,
                command: "curl".into(),
            },
            payload,
        }
    }

    fn scope(event: &RuntimeEvent) -> TrustedInventoryScope {
        TrustedInventoryScope {
            organization_id: Uuid::from_u128(1),
            project_id: event.attribution.project_id,
            application_id: event.attribution.application_id,
        }
    }

    fn dns_events() -> (RuntimeEvent, RuntimeEvent) {
        let name = DnsName::new("api.example.com").unwrap();
        let query = event(EventPayload::NetworkDnsQuery(NetworkDnsQuery {
            transaction_id: 1,
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: name.clone(),
            query_type: DnsQueryType::A,
        }));
        let response = event(EventPayload::NetworkDnsResponse(NetworkDnsResponse {
            transaction_id: 99,
            direction: DnsDirection::Ingress,
            transport: DnsTransport::Tcp,
            resolver_address: "10.96.0.11".parse().unwrap(),
            name: name.clone(),
            query_type: DnsQueryType::A,
            response_code: DnsResponseCode::NoError,
            truncated: false,
            answers: vec![DnsAddressAnswer::new(name, "203.0.113.9".parse().unwrap(), 60).unwrap()],
            cname_chain: vec![],
            effective_ttl_seconds: Some(60),
        }));
        (query, response)
    }

    #[test]
    fn process_identity_ignores_rollout_scope() {
        let first = event(EventPayload::ProcessExec(ProcessExec {
            executable: "/app/payments".into(),
            parent_command: None,
        }));
        let mut rolled = first.clone();
        rolled.attribution.namespace = "payments-canary".into();
        rolled.attribution.workload_name = "payments-canary".into();
        rolled.attribution.pod_uid = "pod-b".into();
        rolled.attribution.container_name = "canary".into();
        assert_eq!(
            fingerprint(scope(&first), &first).unwrap().digest,
            fingerprint(scope(&rolled), &rolled).unwrap().digest
        );
    }

    #[test]
    fn inbound_inventory_identity_excludes_process_scope_and_remote_clients() {
        let listener = event(EventPayload::NetworkListen(
            NetworkListen::new(NetworkAddressFamily::Ipv4, "0.0.0.0".parse().unwrap(), 8080)
                .unwrap(),
        ));
        let mut accepted = event(EventPayload::NetworkAccept(
            NetworkAccept::new(
                NetworkAddressFamily::Ipv4,
                "0.0.0.0".parse().unwrap(),
                8080,
                "203.0.113.8".parse().unwrap(),
                50_000,
            )
            .unwrap(),
        ));
        accepted.process.command = "another-worker".into();
        accepted.attribution.namespace = "canary".into();
        let listener_fingerprint = fingerprint(scope(&listener), &listener).unwrap();
        let accepted_fingerprint = fingerprint(scope(&accepted), &accepted).unwrap();
        assert_eq!(listener_fingerprint.kind, InventoryKind::InboundEndpoint);
        assert_eq!(listener_fingerprint.digest, accepted_fingerprint.digest);
        assert_eq!(
            listener_fingerprint.semantic_summary["listener_observed"],
            true
        );
        assert_eq!(
            accepted_fingerprint.semantic_summary["accept_observed"],
            true
        );
        assert!(
            accepted_fingerprint
                .semantic_summary
                .get("remote_address")
                .is_none()
        );
    }

    #[test]
    fn application_scope_and_identity_version_are_isolated() {
        let event = event(EventPayload::Syscall(SyscallEvent {
            name: "PTRACE".into(),
        }));
        let first = fingerprint(scope(&event), &event).unwrap();
        let mut other_scope = scope(&event);
        other_scope.application_id = Uuid::from_u128(99);
        let second_version = InventoryIdentityVersion::new(2).unwrap();
        assert_ne!(
            first.digest,
            fingerprint(other_scope, &event).unwrap().digest
        );
        assert_ne!(
            first.digest,
            fingerprint_with_version(scope(&event), &event, second_version)
                .unwrap()
                .digest
        );
    }

    #[test]
    fn dns_query_and_response_share_identity_and_exclude_volatile_evidence() {
        let (query, mut response) = dns_events();
        let first = fingerprint(scope(&query), &query).unwrap();
        let EventPayload::NetworkDnsResponse(value) = &mut response.payload else {
            unreachable!()
        };
        value.response_code = DnsResponseCode::ServFail;
        value.answers.clear();
        value.effective_ttl_seconds = None;
        let second = fingerprint(scope(&response), &response).unwrap();
        assert_eq!(first.kind, InventoryKind::Domain);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.semantic_summary, second.semantic_summary);
    }

    #[test]
    fn destination_excludes_outcome_and_dns_context() {
        let succeeded = event(EventPayload::NetworkConnect(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv4,
                "203.0.113.7".parse().unwrap(),
                443,
                NetworkConnectOutcome::Succeeded,
                None,
            )
            .unwrap(),
        ));
        let failed = event(EventPayload::NetworkConnect(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv4,
                "203.0.113.7".parse().unwrap(),
                443,
                NetworkConnectOutcome::Failed,
                Some(111),
            )
            .unwrap(),
        ));
        let first = fingerprint(scope(&succeeded), &succeeded).unwrap();
        let second = fingerprint(scope(&failed), &failed).unwrap();
        assert_eq!(first.digest, second.digest);
        assert!(first.semantic_summary.get("outcome").is_none());
        assert!(first.semantic_summary.get("dns_context").is_none());
    }

    #[test]
    fn empty_identity_fields_are_rejected_and_names_are_normalized() {
        let invalid = event(EventPayload::Syscall(SyscallEvent { name: " \0".into() }));
        assert_eq!(
            fingerprint(scope(&invalid), &invalid),
            Err(InventoryFingerprintError::EmptyField("syscall_name"))
        );

        let upper = event(EventPayload::Syscall(SyscallEvent {
            name: "PTRACE".into(),
        }));
        let lower = event(EventPayload::Syscall(SyscallEvent {
            name: "ptrace".into(),
        }));
        assert_eq!(
            fingerprint(scope(&upper), &upper).unwrap().digest,
            fingerprint(scope(&lower), &lower).unwrap().digest
        );
    }

    #[test]
    fn file_inventory_identity_is_path_based_and_safe() {
        let modified = event(EventPayload::FileModify(FileModify {
            path: FileActivityPath::new("/app/data/report").unwrap(),
        }));
        let item = fingerprint(scope(&modified), &modified).unwrap();
        assert_eq!(item.kind, InventoryKind::FileActivity);
        assert_eq!(item.semantic_summary["operation"], "modify");
        assert_eq!(item.semantic_summary["path"], "/app/data/report");

        let renamed = event(EventPayload::FileRename(
            FileRename::new(
                FileActivityPath::new("/app/data/report").unwrap(),
                FileActivityPath::new("/app/data/report.done").unwrap(),
                Some(false),
            )
            .unwrap(),
        ));
        let renamed_item = fingerprint(scope(&renamed), &renamed).unwrap();
        assert_ne!(item.digest, renamed_item.digest);
        assert_eq!(renamed_item.semantic_summary["replaced"], false);
        assert!(renamed_item.semantic_summary.get("inode").is_none());
        assert!(renamed_item.semantic_summary.get("mount_id").is_none());
    }

    #[test]
    fn lifecycle_events_share_inventory_kind_but_keep_distinct_event_identity() {
        let events = [
            event(EventPayload::ProcessExit(ProcessExit::new(
                0,
                ProcessTermination::exited(0),
                GenerationCorrelation::Unresolved {
                    reason: UnresolvedGenerationReason::BeforeObservation,
                },
            ))),
            event(EventPayload::ContainerTermination(
                ContainerTermination::new("container-a", "Completed", 0, None, None).unwrap(),
            )),
            event(EventPayload::ContainerRestart(
                ContainerRestart::new("container-a", 3, 1, None, None).unwrap(),
            )),
        ];
        let fingerprints = events
            .iter()
            .map(|event| fingerprint(scope(event), event).unwrap())
            .collect::<Vec<_>>();

        assert!(
            fingerprints
                .iter()
                .all(|fingerprint| fingerprint.kind == InventoryKind::Lifecycle)
        );
        assert_eq!(
            fingerprints
                .iter()
                .map(|fingerprint| fingerprint.semantic_summary["event_kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["process.exit", "container.terminated", "container.restart"]
        );
        assert_ne!(fingerprints[0].digest, fingerprints[1].digest);
        assert_ne!(fingerprints[1].digest, fingerprints[2].digest);
    }
}
