//! Transport-independent runtime event domain model.

mod release;
mod resource;
mod termination;

pub use release::*;
pub use resource::*;
pub use termination::*;

use std::{
    net::IpAddr,
    path::{Component, Path},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u32 = 1;
pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_FILE_PATH_BYTES: usize = 1024;
pub const FILE_MODIFY_AGGREGATION_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub schema_version: u32,
    pub attribution: KubernetesAttribution,
    pub process: ProcessIdentity,
    pub payload: EventPayload,
}

impl RuntimeEvent {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.payload {
            EventPayload::ProcessExec(_) => "process.exec",
            EventPayload::Syscall(_) => "syscall",
            EventPayload::NetworkConnect(_) => "network.connect",
            EventPayload::NetworkListen(_) => "network.listen",
            EventPayload::NetworkAccept(_) => "network.accept",
            EventPayload::NetworkDnsQuery(_) => "network.dns.query",
            EventPayload::NetworkDnsResponse(_) => "network.dns.response",
            EventPayload::FileCreate(_) => "file.create",
            EventPayload::FileModify(_) => "file.modify",
            EventPayload::FileDelete(_) => "file.delete",
            EventPayload::FileRename(_) => "file.rename",
            EventPayload::ProcessExit(_) => "process.exit",
            EventPayload::ContainerTermination(_) => "container.terminated",
            EventPayload::ContainerRestart(_) => "container.restart",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesAttribution {
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub node_name: String,
    pub namespace: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub container_id: String,
    pub container_name: String,
    pub workload_uid: String,
    pub workload_kind: String,
    pub workload_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_identity: Option<ReleaseIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub command: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventPayload {
    ProcessExec(ProcessExec),
    Syscall(SyscallEvent),
    NetworkConnect(NetworkConnect),
    NetworkListen(NetworkListen),
    NetworkAccept(NetworkAccept),
    NetworkDnsQuery(NetworkDnsQuery),
    NetworkDnsResponse(NetworkDnsResponse),
    FileCreate(FileCreate),
    FileModify(FileModify),
    FileDelete(FileDelete),
    FileRename(FileRename),
    ProcessExit(ProcessExit),
    ContainerTermination(ContainerTermination),
    ContainerRestart(ContainerRestart),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExec {
    pub executable: String,
    pub parent_command: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub name: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FileActivityError {
    #[error("file path must be an absolute normalized path")]
    InvalidPath,
    #[error("file path exceeds {MAX_FILE_PATH_BYTES} bytes")]
    PathTooLong,
    #[error("rename paths must differ")]
    SameRenamePath,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct FileActivityPath(String);

impl<'de> Deserialize<'de> for FileActivityPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl FileActivityPath {
    pub fn new(value: impl Into<String>) -> Result<Self, FileActivityError> {
        let value = value.into();
        if value.len() > MAX_FILE_PATH_BYTES {
            return Err(FileActivityError::PathTooLong);
        }
        if !is_normalized_absolute_path(&value) {
            return Err(FileActivityError::InvalidPath);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_equal_or_descendant_of(&self, prefix: &Self) -> bool {
        self == prefix
            || self
                .0
                .strip_prefix(prefix.as_str())
                .is_some_and(|suffix| prefix.as_str() == "/" || suffix.starts_with('/'))
    }
}

impl From<FileActivityPath> for String {
    fn from(value: FileActivityPath) -> Self {
        value.0
    }
}

fn is_normalized_absolute_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') || !value.starts_with('/') {
        return false;
    }
    if value != "/"
        && value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return false;
    }
    let mut components = Path::new(value).components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return false;
    }
    if components.any(|component| !matches!(component, Component::Normal(_))) {
        return false;
    }
    value == "/" || !value.ends_with('/')
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCreate {
    pub path: FileActivityPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileModify {
    pub path: FileActivityPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDelete {
    pub path: FileActivityPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRename {
    pub old_path: FileActivityPath,
    pub new_path: FileActivityPath,
    pub replaced: Option<bool>,
}

impl FileRename {
    pub fn new(
        old_path: FileActivityPath,
        new_path: FileActivityPath,
        replaced: Option<bool>,
    ) -> Result<Self, FileActivityError> {
        if old_path == new_path {
            return Err(FileActivityError::SameRenamePath);
        }
        Ok(Self {
            old_path,
            new_path,
            replaced,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTransport {
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkListen {
    pub transport: NetworkTransport,
    pub address_family: NetworkAddressFamily,
    pub local_address: IpAddr,
    pub local_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAccept {
    pub transport: NetworkTransport,
    pub address_family: NetworkAddressFamily,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum InboundNetworkError {
    #[error("local port must be non-zero")]
    ZeroLocalPort,
    #[error("remote port must be non-zero")]
    ZeroRemotePort,
    #[error("address family does not match endpoint address")]
    AddressFamilyMismatch,
}

impl NetworkListen {
    /// Constructs a validated TCP listener observation.
    pub fn new(
        address_family: NetworkAddressFamily,
        local_address: IpAddr,
        local_port: u16,
    ) -> Result<Self, InboundNetworkError> {
        validate_endpoint(address_family, local_address, local_port, true)?;
        Ok(Self {
            transport: NetworkTransport::Tcp,
            address_family,
            local_address,
            local_port,
        })
    }
}

impl NetworkAccept {
    /// Constructs a validated accepted TCP connection observation.
    pub fn new(
        address_family: NetworkAddressFamily,
        local_address: IpAddr,
        local_port: u16,
        remote_address: IpAddr,
        remote_port: u16,
    ) -> Result<Self, InboundNetworkError> {
        validate_endpoint(address_family, local_address, local_port, true)?;
        validate_endpoint(address_family, remote_address, remote_port, false)?;
        Ok(Self {
            transport: NetworkTransport::Tcp,
            address_family,
            local_address,
            local_port,
            remote_address,
            remote_port,
        })
    }
}

fn validate_endpoint(
    family: NetworkAddressFamily,
    address: IpAddr,
    port: u16,
    local: bool,
) -> Result<(), InboundNetworkError> {
    if port == 0 {
        return Err(if local {
            InboundNetworkError::ZeroLocalPort
        } else {
            InboundNetworkError::ZeroRemotePort
        });
    }
    if !matches!(
        (family, address),
        (NetworkAddressFamily::Ipv4, IpAddr::V4(_)) | (NetworkAddressFamily::Ipv6, IpAddr::V6(_))
    ) {
        return Err(InboundNetworkError::AddressFamilyMismatch);
    }
    Ok(())
}

pub const LINUX_EINPROGRESS: u16 = 115;
pub const MAX_LINUX_ERRNO: u16 = 4095;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConnectOutcome {
    Succeeded,
    InProgress,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnect {
    pub address_family: NetworkAddressFamily,
    pub destination_address: IpAddr,
    pub destination_port: u16,
    pub outcome: NetworkConnectOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_context: Option<DnsContext>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum NetworkConnectError {
    #[error("destination port must be non-zero")]
    ZeroDestinationPort,
    #[error("address family does not match destination address")]
    AddressFamilyMismatch,
    #[error("connect outcome and errno are inconsistent")]
    InconsistentOutcome,
    #[error("errno must be in 1..={MAX_LINUX_ERRNO}")]
    InvalidErrno,
}

impl NetworkConnect {
    /// Constructs a validated outbound connection attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero port, a mismatched address family, or an
    /// inconsistent outcome/errno pair.
    pub fn new(
        address_family: NetworkAddressFamily,
        destination_address: IpAddr,
        destination_port: u16,
        outcome: NetworkConnectOutcome,
        errno: Option<u16>,
    ) -> Result<Self, NetworkConnectError> {
        if destination_port == 0 {
            return Err(NetworkConnectError::ZeroDestinationPort);
        }
        if !matches!(
            (address_family, destination_address),
            (NetworkAddressFamily::Ipv4, IpAddr::V4(_))
                | (NetworkAddressFamily::Ipv6, IpAddr::V6(_))
        ) {
            return Err(NetworkConnectError::AddressFamilyMismatch);
        }
        if errno.is_some_and(|value| value == 0 || value > MAX_LINUX_ERRNO) {
            return Err(NetworkConnectError::InvalidErrno);
        }
        let consistent = matches!(
            (outcome, errno),
            (NetworkConnectOutcome::Succeeded, None)
                | (NetworkConnectOutcome::InProgress, Some(LINUX_EINPROGRESS))
                | (NetworkConnectOutcome::Failed, Some(1..=MAX_LINUX_ERRNO))
        ) && !(outcome == NetworkConnectOutcome::Failed
            && errno == Some(LINUX_EINPROGRESS));
        if !consistent {
            return Err(NetworkConnectError::InconsistentOutcome);
        }
        Ok(Self {
            address_family,
            destination_address,
            destination_port,
            outcome,
            errno,
            dns_context: None,
        })
    }

    #[must_use]
    pub fn with_dns_context(mut self, context: DnsContext) -> Self {
        self.dns_context = Some(context);
        self
    }
}

pub const MAX_DNS_NAME_LEN: usize = 253;
pub const MAX_DNS_CONTEXT_NAMES: usize = 8;
pub const MAX_DNS_ANSWERS: usize = 16;
pub const MAX_DNS_CNAME_CHAIN: usize = 8;
pub const MAX_DNS_TTL_SECONDS: u32 = 86_400;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl DnsName {
    pub fn new(value: impl Into<String>) -> Result<Self, DnsValidationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_DNS_NAME_LEN || value.ends_with('.') {
            return Err(DnsValidationError::InvalidName);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii())
        {
            return Err(DnsValidationError::InvalidName);
        }
        let valid = value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
        valid
            .then_some(Self(value))
            .ok_or(DnsValidationError::InvalidName)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DnsName {
    type Error = DnsValidationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DnsName> for String {
    fn from(value: DnsName) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Aaaa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsDirection {
    Egress,
    Ingress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsConfidence {
    ObservedRecently,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAddressAnswer {
    pub name: DnsName,
    pub address: IpAddr,
    pub ttl_seconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCname {
    pub alias: DnsName,
    pub canonical: DnsName,
    pub ttl_seconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDnsQuery {
    pub transaction_id: u16,
    pub direction: DnsDirection,
    pub transport: DnsTransport,
    pub resolver_address: IpAddr,
    pub name: DnsName,
    pub query_type: DnsQueryType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDnsResponse {
    pub transaction_id: u16,
    pub direction: DnsDirection,
    pub transport: DnsTransport,
    pub resolver_address: IpAddr,
    pub name: DnsName,
    pub query_type: DnsQueryType,
    pub response_code: DnsResponseCode,
    pub truncated: bool,
    pub answers: Vec<DnsAddressAnswer>,
    pub cname_chain: Vec<DnsCname>,
    pub effective_ttl_seconds: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsContext {
    pub names: Vec<DnsName>,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub confidence: DnsConfidence,
    pub ambiguous: bool,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DnsValidationError {
    #[error("DNS name is not canonical or exceeds bounds")]
    InvalidName,
    #[error("DNS collection exceeds bounds")]
    TooManyValues,
    #[error("DNS TTL is zero or exceeds the platform clamp")]
    InvalidTtl,
    #[error("DNS context timestamps or ambiguity are inconsistent")]
    InvalidContext,
}

impl DnsAddressAnswer {
    pub fn new(
        name: DnsName,
        address: IpAddr,
        ttl_seconds: u32,
    ) -> Result<Self, DnsValidationError> {
        validate_ttl(ttl_seconds)?;
        Ok(Self {
            name,
            address,
            ttl_seconds,
        })
    }
}

impl DnsCname {
    pub fn new(
        alias: DnsName,
        canonical: DnsName,
        ttl_seconds: u32,
    ) -> Result<Self, DnsValidationError> {
        validate_ttl(ttl_seconds)?;
        Ok(Self {
            alias,
            canonical,
            ttl_seconds,
        })
    }
}

impl NetworkDnsResponse {
    pub fn validate(&self) -> Result<(), DnsValidationError> {
        if self.answers.len() > MAX_DNS_ANSWERS || self.cname_chain.len() > MAX_DNS_CNAME_CHAIN {
            return Err(DnsValidationError::TooManyValues);
        }
        for answer in &self.answers {
            validate_ttl(answer.ttl_seconds)?;
        }
        for cname in &self.cname_chain {
            validate_ttl(cname.ttl_seconds)?;
        }
        if let Some(ttl) = self.effective_ttl_seconds {
            validate_ttl(ttl)?;
        }
        Ok(())
    }
}

impl DnsContext {
    pub fn new(
        names: Vec<DnsName>,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DnsValidationError> {
        if names.is_empty() || names.len() > MAX_DNS_CONTEXT_NAMES || expires_at <= observed_at {
            return Err(DnsValidationError::InvalidContext);
        }
        let ambiguous = names.len() > 1;
        Ok(Self {
            names,
            observed_at,
            expires_at,
            confidence: DnsConfidence::ObservedRecently,
            ambiguous,
        })
    }

    pub fn validate(&self) -> Result<(), DnsValidationError> {
        if self.names.is_empty()
            || self.names.len() > MAX_DNS_CONTEXT_NAMES
            || self.expires_at <= self.observed_at
            || self.ambiguous != (self.names.len() > 1)
            || self.confidence != DnsConfidence::ObservedRecently
        {
            return Err(DnsValidationError::InvalidContext);
        }
        Ok(())
    }
}

fn validate_ttl(ttl_seconds: u32) -> Result<(), DnsValidationError> {
    (1..=MAX_DNS_TTL_SECONDS)
        .contains(&ttl_seconds)
        .then_some(())
        .ok_or(DnsValidationError::InvalidTtl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn network_connect_validates_family_port_and_outcome() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let event = NetworkConnect::new(
            NetworkAddressFamily::Ipv4,
            ipv4,
            443,
            NetworkConnectOutcome::Succeeded,
            None,
        )
        .unwrap();
        assert_eq!(event.destination_address, ipv4);
        assert_eq!(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv6,
                ipv4,
                443,
                NetworkConnectOutcome::Succeeded,
                None,
            ),
            Err(NetworkConnectError::AddressFamilyMismatch)
        );
        assert_eq!(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv4,
                ipv4,
                0,
                NetworkConnectOutcome::Succeeded,
                None,
            ),
            Err(NetworkConnectError::ZeroDestinationPort)
        );
        assert_eq!(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv4,
                ipv4,
                443,
                NetworkConnectOutcome::Failed,
                None,
            ),
            Err(NetworkConnectError::InconsistentOutcome)
        );
        assert!(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv6,
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                443,
                NetworkConnectOutcome::InProgress,
                Some(LINUX_EINPROGRESS),
            )
            .is_ok()
        );
    }

    #[test]
    fn network_connect_serializes_canonical_safe_fields() {
        let event = NetworkConnect::new(
            NetworkAddressFamily::Ipv6,
            "2001:0db8:0:0:0:0:0:1".parse().unwrap(),
            8443,
            NetworkConnectOutcome::Failed,
            Some(111),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::json!({
                "address_family": "ipv6",
                "destination_address": "2001:db8::1",
                "destination_port": 8443,
                "outcome": "failed",
                "errno": 111
            })
        );
    }

    #[test]
    fn dns_name_requires_canonical_bounded_ascii_labels() {
        assert_eq!(
            DnsName::new("api.example.com").unwrap().as_str(),
            "api.example.com"
        );
        for invalid in [
            "",
            "API.example.com",
            "api.example.com.",
            "-api.example",
            "api..example",
            "пример.рф",
        ] {
            assert_eq!(DnsName::new(invalid), Err(DnsValidationError::InvalidName));
        }
        assert_eq!(
            DnsName::new(format!("{}.example", "a".repeat(64))),
            Err(DnsValidationError::InvalidName)
        );
    }

    #[test]
    fn dns_ttl_and_context_are_strictly_bounded() {
        let name = DnsName::new("api.example.com").unwrap();
        assert_eq!(
            DnsAddressAnswer::new(name.clone(), "203.0.113.4".parse().unwrap(), 0),
            Err(DnsValidationError::InvalidTtl)
        );
        let observed_at = Utc::now();
        let context = DnsContext::new(
            vec![name.clone(), DnsName::new("cdn.example.com").unwrap()],
            observed_at,
            observed_at + chrono::Duration::seconds(60),
        )
        .unwrap();
        assert!(context.ambiguous);
        assert_eq!(context.confidence, DnsConfidence::ObservedRecently);
        assert_eq!(
            DnsContext::new(vec![name], observed_at, observed_at),
            Err(DnsValidationError::InvalidContext)
        );
    }

    #[test]
    fn dns_payload_kinds_are_typed() {
        let query = NetworkDnsQuery {
            transaction_id: 7,
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: DnsName::new("api.example.com").unwrap(),
            query_type: DnsQueryType::A,
        };
        let mut event = RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::new_v4(),
                application_id: Uuid::new_v4(),
                node_name: "node".into(),
                namespace: "default".into(),
                pod_uid: "pod".into(),
                pod_name: "pod".into(),
                container_id: "container".into(),
                container_name: "container".into(),
                workload_uid: "workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "api".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 2,
                tgid: 2,
                command: "api".into(),
            },
            payload: EventPayload::NetworkDnsQuery(query.clone()),
        };
        assert_eq!(event.kind(), "network.dns.query");
        event.payload = EventPayload::NetworkDnsResponse(NetworkDnsResponse {
            transaction_id: query.transaction_id,
            direction: DnsDirection::Ingress,
            transport: query.transport,
            resolver_address: query.resolver_address,
            name: query.name,
            query_type: query.query_type,
            response_code: DnsResponseCode::NxDomain,
            truncated: false,
            answers: vec![],
            cname_chain: vec![],
            effective_ttl_seconds: None,
        });
        assert_eq!(event.kind(), "network.dns.response");
    }

    #[test]
    fn inbound_tcp_endpoints_are_validated() {
        let listen =
            NetworkListen::new(NetworkAddressFamily::Ipv4, "0.0.0.0".parse().unwrap(), 8080)
                .unwrap();
        assert_eq!(listen.transport, NetworkTransport::Tcp);
        assert_eq!(listen.local_port, 8080);

        let accepted = NetworkAccept::new(
            NetworkAddressFamily::Ipv6,
            "::".parse().unwrap(),
            8443,
            "2001:db8::1".parse().unwrap(),
            51_234,
        )
        .unwrap();
        assert_eq!(accepted.remote_port, 51_234);
        assert_eq!(
            NetworkListen::new(NetworkAddressFamily::Ipv4, "0.0.0.0".parse().unwrap(), 0,),
            Err(InboundNetworkError::ZeroLocalPort)
        );
        assert_eq!(
            NetworkAccept::new(
                NetworkAddressFamily::Ipv4,
                "0.0.0.0".parse().unwrap(),
                8080,
                "::1".parse().unwrap(),
                50_000,
            ),
            Err(InboundNetworkError::AddressFamilyMismatch)
        );
        assert_eq!(
            NetworkAccept::new(
                NetworkAddressFamily::Ipv4,
                "0.0.0.0".parse().unwrap(),
                8080,
                "127.0.0.1".parse().unwrap(),
                0,
            ),
            Err(InboundNetworkError::ZeroRemotePort)
        );
    }

    #[test]
    fn file_paths_are_absolute_normalized_bounded_and_component_aware() {
        let root = FileActivityPath::new("/").unwrap();
        let included = FileActivityPath::new("/app/data").unwrap();
        let child = FileActivityPath::new("/app/data/report.csv").unwrap();
        let textual_prefix = FileActivityPath::new("/app/database/report.csv").unwrap();
        assert!(child.is_equal_or_descendant_of(&included));
        assert!(child.is_equal_or_descendant_of(&root));
        assert!(!textual_prefix.is_equal_or_descendant_of(&included));
        for invalid in [
            "",
            "relative",
            "/app/../secret",
            "/app//data",
            "/app/data/",
            "/bad\0path",
        ] {
            assert!(
                FileActivityPath::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(matches!(
            FileActivityPath::new(format!("/{}", "x".repeat(MAX_FILE_PATH_BYTES))),
            Err(FileActivityError::PathTooLong)
        ));
        assert_eq!(FILE_MODIFY_AGGREGATION_WINDOW, Duration::from_secs(5));
    }

    #[test]
    fn rename_requires_distinct_valid_paths() {
        let old_path = FileActivityPath::new("/app/old").unwrap();
        let new_path = FileActivityPath::new("/app/new").unwrap();
        assert!(FileRename::new(old_path.clone(), new_path, Some(true)).is_ok());
        assert_eq!(
            FileRename::new(old_path.clone(), old_path, Some(false)),
            Err(FileActivityError::SameRenamePath)
        );
    }
}
