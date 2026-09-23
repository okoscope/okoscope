use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

use crate::syscall::{self, Architecture};

pub const API_VERSION: &str = "okoscope.io/v1alpha1";
pub const KIND: &str = "AgentConfiguration";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentConfig {
    pub api_version: String,
    pub kind: String,
    pub server: ServerConfig,
    pub identity: IdentityConfig,
    pub scope: ScopeConfig,
    pub observation: ObservationConfig,
    #[serde(default)]
    pub safety: SafetyLimits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerConfig {
    pub endpoint: String,
    #[serde(default)]
    pub development_plaintext: bool,
    pub ca_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityConfig {
    pub node_name: String,
    pub cluster_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScopeConfig {
    pub workloads: Vec<WorkloadSelector>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkloadSelector {
    pub application_credential_file: String,
    #[serde(skip)]
    pub route_id: Uuid,
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub release: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl WorkloadSelector {
    #[must_use]
    pub fn matches(&self, workload: &WorkloadMetadata) -> bool {
        self.namespace == workload.namespace
            && self.kind == workload.kind
            && (self.name == "*" || self.name == workload.name)
            && self
                .labels
                .iter()
                .all(|(key, value)| workload.labels.get(key) == Some(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadMetadata {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationConfig {
    pub process_exec: bool,
    #[serde(default)]
    pub process_exit: bool,
    #[serde(default)]
    pub syscalls: Vec<String>,
    #[serde(default)]
    pub network: NetworkObservationConfig,
    #[serde(default)]
    pub files: FileObservationConfig,
    #[serde(default)]
    pub resources: ResourceObservationConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceObservationConfig {
    pub enabled: bool,
    pub sample_interval_seconds: u64,
    pub aggregation_interval_seconds: u64,
    pub max_cgroup_states: usize,
    pub max_open_aggregates: usize,
    pub queue_capacity: usize,
    pub batch_size: usize,
}

impl Default for ResourceObservationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_interval_seconds: 15,
            aggregation_interval_seconds: 60,
            max_cgroup_states: 4_096,
            max_open_aggregates: 1_024,
            queue_capacity: 256,
            batch_size: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Create,
    Modify,
    Delete,
    Rename,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct FileObservationConfig {
    pub enabled: bool,
    pub operations: BTreeSet<FileOperation>,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
}

impl FileObservationConfig {
    #[must_use]
    pub fn observes(&self, path: &event_model::FileActivityPath) -> bool {
        let parse = |value: &String| event_model::FileActivityPath::new(value.clone()).ok();
        self.enabled
            && self
                .include_paths
                .iter()
                .filter_map(parse)
                .any(|prefix| path.is_equal_or_descendant_of(&prefix))
            && !self
                .exclude_paths
                .iter()
                .filter_map(parse)
                .any(|prefix| path.is_equal_or_descendant_of(&prefix))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkObservationConfig {
    pub connect: bool,
    pub listen: bool,
    pub accept: bool,
    pub max_accepted_events_per_second: u32,
    pub dns: DnsObservationConfig,
}

impl Default for NetworkObservationConfig {
    fn default() -> Self {
        Self {
            connect: false,
            listen: false,
            accept: false,
            max_accepted_events_per_second: 1_000,
            dns: DnsObservationConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsObservationConfig {
    pub enabled: bool,
    pub udp: bool,
    pub tcp: bool,
    pub max_captured_bytes: usize,
    pub max_pending_transactions: usize,
    pub max_tcp_streams: usize,
    pub max_answers_per_response: usize,
    pub max_names_per_address: usize,
    pub max_ttl_seconds: u32,
    pub max_events_per_second: u32,
}

impl Default for DnsObservationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            udp: true,
            tcp: true,
            max_captured_bytes: 1232,
            max_pending_transactions: 4096,
            max_tcp_streams: 1024,
            max_answers_per_response: event_model::MAX_DNS_ANSWERS,
            max_names_per_address: event_model::MAX_DNS_CONTEXT_NAMES,
            max_ttl_seconds: event_model::MAX_DNS_TTL_SECONDS,
            max_events_per_second: 1000,
        }
    }
}

impl ObservationConfig {
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        let mut capabilities = Vec::new();
        if self.process_exec {
            capabilities.push("process.exec/v1".into());
        }
        capabilities.extend(
            self.syscalls
                .iter()
                .map(|name| format!("syscall.{name}/v1")),
        );
        if self.network.connect {
            capabilities.push(protocol::NETWORK_CONNECT_CAPABILITY.into());
        }
        if self.network.listen {
            capabilities.push(protocol::NETWORK_LISTEN_CAPABILITY.into());
        }
        if self.network.accept {
            capabilities.push(protocol::NETWORK_ACCEPT_CAPABILITY.into());
        }
        if self.network.dns.enabled && self.network.dns.udp {
            capabilities.push(protocol::NETWORK_DNS_UDP_CAPABILITY.into());
        }
        if self.network.dns.enabled && self.network.dns.tcp {
            capabilities.push(protocol::NETWORK_DNS_TCP_CAPABILITY.into());
        }
        if self.files.enabled {
            capabilities.push(protocol::FILE_ACTIVITY_CAPABILITY.into());
        }
        capabilities
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct SafetyLimits {
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub max_events_per_second: u32,
    pub max_application_streams: usize,
}

pub const MAX_QUEUE_CAPACITY: usize = 4096;
pub const MAX_APPLICATION_STREAMS: usize = 32;

impl Default for SafetyLimits {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            batch_size: 256,
            max_events_per_second: 10_000,
            max_application_streams: 32,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported apiVersion {0:?}")]
    ApiVersion(String),
    #[error("unsupported kind {0:?}")]
    Kind(String),
    #[error("at least one workload selector is required")]
    MissingWorkload,
    #[error("at least one observation capability is required")]
    MissingObservation,
    #[error("invalid workload selector: {0}")]
    InvalidSelector(String),
    #[error("TLS is required unless developmentPlaintext is explicitly enabled")]
    TlsRequired,
    #[error(transparent)]
    Syscall(#[from] syscall::SyscallError),
}

impl AgentConfig {
    pub fn from_yaml(input: &str, architecture: Architecture) -> Result<Self, ConfigError> {
        let mut config: Self = serde_yaml::from_str(input)?;
        for selector in &mut config.scope.workloads {
            if let Some(release) = &mut selector.release {
                *release = release.trim().to_owned();
            }
        }
        let mut routes = BTreeMap::<String, Uuid>::new();
        for selector in &mut config.scope.workloads {
            selector.route_id = *routes
                .entry(selector.application_credential_file.clone())
                .or_insert_with(Uuid::new_v4);
        }
        config.validate(architecture)?;
        Ok(config)
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self, architecture: Architecture) -> Result<(), ConfigError> {
        if self.api_version != API_VERSION {
            return Err(ConfigError::ApiVersion(self.api_version.clone()));
        }
        if self.kind != KIND {
            return Err(ConfigError::Kind(self.kind.clone()));
        }
        if self.scope.workloads.is_empty() {
            return Err(ConfigError::MissingWorkload);
        }
        if !self.observation.process_exec
            && self.observation.syscalls.is_empty()
            && !self.observation.network.connect
            && !self.observation.network.listen
            && !self.observation.network.accept
            && !self.observation.network.dns.enabled
            && !self.observation.files.enabled
            && !self.observation.resources.enabled
        {
            return Err(ConfigError::MissingObservation);
        }
        if !self.server.development_plaintext && !self.server.endpoint.starts_with("https://") {
            return Err(ConfigError::TlsRequired);
        }
        if self.safety.queue_capacity == 0
            || self.safety.batch_size == 0
            || self.safety.batch_size > self.safety.queue_capacity
            || self.safety.max_application_streams == 0
            || self.safety.queue_capacity > MAX_QUEUE_CAPACITY
            || self.safety.max_application_streams > MAX_APPLICATION_STREAMS
        {
            return Err(ConfigError::InvalidSelector(format!(
                "safety limits must be non-zero, batchSize must not exceed queueCapacity, queueCapacity must not exceed {MAX_QUEUE_CAPACITY}, and maxApplicationStreams must not exceed {MAX_APPLICATION_STREAMS}"
            )));
        }
        let dns = &self.observation.network.dns;
        let files = &self.observation.files;
        let resources = &self.observation.resources;
        if resources.enabled
            && (!(10..=60).contains(&resources.sample_interval_seconds)
                || resources.aggregation_interval_seconds != 60
                || resources.max_cgroup_states == 0
                || resources.max_cgroup_states > 65_536
                || resources.max_open_aggregates == 0
                || resources.max_open_aggregates > 16_384
                || resources.queue_capacity == 0
                || resources.queue_capacity > 4_096
                || resources.batch_size == 0
                || resources.batch_size > resources.queue_capacity
                || resources.batch_size > event_model::MAX_RESOURCE_BATCH_AGGREGATES)
        {
            return Err(ConfigError::InvalidSelector(
                "resource observation bounds are invalid".into(),
            ));
        }
        if files.enabled {
            if files.operations.is_empty() || files.include_paths.is_empty() {
                return Err(ConfigError::InvalidSelector(
                    "file observation requires operations and includePaths".into(),
                ));
            }
            for path in files.include_paths.iter().chain(&files.exclude_paths) {
                event_model::FileActivityPath::new(path.clone()).map_err(|_| {
                    ConfigError::InvalidSelector(
                        "file paths must be absolute, normalized, bounded, and NUL-free".into(),
                    )
                })?;
            }
        }
        if self.observation.network.accept
            && !(1..=100_000).contains(&self.observation.network.max_accepted_events_per_second)
        {
            return Err(ConfigError::InvalidSelector(
                "maxAcceptedEventsPerSecond must be in 1..=100000".into(),
            ));
        }
        if dns.enabled
            && (!dns.udp && !dns.tcp
                || !(512..=4096).contains(&dns.max_captured_bytes)
                || dns.max_pending_transactions == 0
                || dns.max_tcp_streams == 0
                || !(1..=event_model::MAX_DNS_ANSWERS).contains(&dns.max_answers_per_response)
                || !(1..=event_model::MAX_DNS_CONTEXT_NAMES).contains(&dns.max_names_per_address)
                || !(1..=event_model::MAX_DNS_TTL_SECONDS).contains(&dns.max_ttl_seconds)
                || dns.max_events_per_second == 0)
        {
            return Err(ConfigError::InvalidSelector(
                "DNS limits or transports are outside platform bounds".into(),
            ));
        }
        for selector in &self.scope.workloads {
            if selector.namespace.is_empty() || selector.kind.is_empty() || selector.name.is_empty()
            {
                return Err(ConfigError::InvalidSelector(
                    "namespace, kind, and name are required".into(),
                ));
            }
            if let Some(release) = &selector.release
                && (release.is_empty() || release.len() > 200)
            {
                return Err(ConfigError::InvalidSelector(
                    "release must be trimmed and contain 1..=200 bytes".into(),
                ));
            }
            let credential_path = Path::new(&selector.application_credential_file);
            if !credential_path.is_absolute() || selector.application_credential_file.contains('\0')
            {
                return Err(ConfigError::InvalidSelector(
                    "applicationCredentialFile must be an absolute NUL-free path".into(),
                ));
            }
        }
        let distinct_streams = self
            .scope
            .workloads
            .iter()
            .map(|selector| selector.route_id)
            .collect::<BTreeSet<_>>()
            .len();
        if distinct_streams > self.safety.max_application_streams {
            return Err(ConfigError::InvalidSelector(format!(
                "configured Application stream count exceeds maxApplicationStreams ({})",
                self.safety.max_application_streams
            )));
        }
        for name in &self.observation.syscalls {
            syscall::resolve(name, architecture)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct LoadedApplicationCredential {
    pub route_id: Uuid,
    pub canonical_path: String,
    pub token: String,
}

impl std::fmt::Debug for LoadedApplicationCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedApplicationCredential")
            .field("route_id", &self.route_id)
            .field("canonical_path", &self.canonical_path)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

pub async fn load_application_credentials(
    config: &AgentConfig,
) -> Result<Vec<LoadedApplicationCredential>, ConfigError> {
    let mut paths = BTreeMap::<Uuid, &str>::new();
    for selector in &config.scope.workloads {
        paths
            .entry(selector.route_id)
            .or_insert(&selector.application_credential_file);
    }
    let mut loaded = Vec::with_capacity(paths.len());
    for (route_id, path) in paths {
        let canonical = tokio::fs::canonicalize(path).await.map_err(|_| {
            ConfigError::InvalidSelector(format!("cannot read credential file {path}"))
        })?;
        let canonical_path = canonical.to_string_lossy().into_owned();
        let token = tokio::fs::read_to_string(&canonical).await.map_err(|_| {
            ConfigError::InvalidSelector(format!("cannot read credential file {path}"))
        })?;
        let token = token.trim().to_owned();
        validate_application_token(&token).map_err(|()| {
            ConfigError::InvalidSelector(format!("credential file {path} has an invalid token"))
        })?;
        loaded.push(LoadedApplicationCredential {
            route_id,
            canonical_path,
            token,
        });
    }
    Ok(loaded)
}

fn validate_application_token(token: &str) -> Result<(), ()> {
    let encoded = token.strip_prefix("oko_app_v1_").ok_or(())?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    (decoded.len() == 32).then_some(()).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
apiVersion: okoscope.io/v1alpha1
kind: AgentConfiguration
server:
  endpoint: http://server:4317
  developmentPlaintext: true
identity:
  nodeName: node-1
  clusterName: local
scope:
  workloads:
    - applicationCredentialFile: /secrets/payment-api
      namespace: production
      kind: Deployment
      name: payment-api
      labels:
        app.kubernetes.io/name: payment-api
observation:
  processExec: true
  syscalls: [ptrace, setns]
"#;

    #[test]
    fn parses_strict_valid_configuration() {
        let config = AgentConfig::from_yaml(VALID, Architecture::X86_64).unwrap();
        assert_eq!(config.scope.workloads.len(), 1);
        assert!(!config.observation.network.connect);
    }

    #[test]
    fn resource_observation_is_opt_in_and_bounds_delivery() {
        let enabled = VALID.replace(
            "  processExec: true\n",
            "  processExec: false\n  resources:\n    enabled: true\n",
        );
        let config = AgentConfig::from_yaml(&enabled, Architecture::X86_64).unwrap();
        assert!(config.observation.resources.enabled);
        assert_eq!(config.observation.resources.sample_interval_seconds, 15);

        let invalid = enabled.replace(
            "    enabled: true\n",
            "    enabled: true\n    sampleIntervalSeconds: 9\n",
        );
        assert!(AgentConfig::from_yaml(&invalid, Architecture::X86_64).is_err());
    }

    #[test]
    fn accepts_tls_with_system_trust_and_label_only_selector() {
        let yaml = VALID
            .replace(
                "http://server:4317\n  developmentPlaintext: true",
                "https://server:443",
            )
            .replace("      name: payment-api\n", "      name: \"*\"\n");
        let config = AgentConfig::from_yaml(&yaml, Architecture::X86_64).unwrap();
        let workload = WorkloadMetadata {
            namespace: "production".into(),
            kind: "Deployment".into(),
            name: "any-name".into(),
            labels: BTreeMap::from([("app.kubernetes.io/name".into(), "payment-api".into())]),
        };
        assert!(config.scope.workloads[0].matches(&workload));
    }

    #[test]
    fn deduplicates_stream_routes_and_enforces_stream_limit() {
        let duplicate = VALID.replace(
            "observation:\n",
            "    - applicationCredentialFile: /secrets/payment-api\n      namespace: staging\n      kind: Deployment\n      name: payment-api\nobservation:\n",
        );
        let config = AgentConfig::from_yaml(&duplicate, Architecture::X86_64).unwrap();
        assert_eq!(config.scope.workloads.len(), 2);
        assert_eq!(
            config.scope.workloads[0].route_id,
            config.scope.workloads[1].route_id
        );

        let distinct = duplicate.replace(
            "/secrets/payment-api\n      namespace: staging",
            "/secrets/order-api\n      namespace: staging",
        );
        let limited = distinct.replace(
            "observation:\n",
            "safety:\n  maxApplicationStreams: 1\nobservation:\n",
        );
        assert!(AgentConfig::from_yaml(&limited, Architecture::X86_64).is_err());
    }

    #[test]
    fn rejects_safety_limits_above_benchmarked_maxima() {
        for limits in [
            format!("queueCapacity: {}", MAX_QUEUE_CAPACITY + 1),
            format!("maxApplicationStreams: {}", MAX_APPLICATION_STREAMS + 1),
        ] {
            let yaml = VALID.replace(
                "observation:\n",
                &format!("safety:\n  {limits}\nobservation:\n"),
            );
            assert!(AgentConfig::from_yaml(&yaml, Architecture::X86_64).is_err());
        }
    }

    #[tokio::test]
    async fn loads_valid_token_from_canonical_file_without_debug_exposure() {
        let directory = std::env::temp_dir().join(format!("okoscope-config-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let credential_path = directory.join("application-token");
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let token = format!("oko_app_v1_{encoded}");
        tokio::fs::write(&credential_path, format!("{token}\n"))
            .await
            .unwrap();
        let yaml = VALID.replace("/secrets/payment-api", credential_path.to_str().unwrap());
        let config = AgentConfig::from_yaml(&yaml, Architecture::X86_64).unwrap();
        let loaded = load_application_credentials(&config).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].token, token);
        assert!(!format!("{:?}", loaded[0]).contains(&token));
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[test]
    fn release_is_optional_bounded_and_trimmed() {
        let with_release = VALID.replace(
            "      name: payment-api",
            "      name: payment-api\n      release: 1.7.2",
        );
        let config = AgentConfig::from_yaml(&with_release, Architecture::X86_64).unwrap();
        assert_eq!(config.scope.workloads[0].release.as_deref(), Some("1.7.2"));
        let normalized = AgentConfig::from_yaml(
            &with_release.replace("1.7.2", "\" 1.7.2 \""),
            Architecture::X86_64,
        )
        .unwrap();
        assert_eq!(
            normalized.scope.workloads[0].release.as_deref(),
            Some("1.7.2")
        );
        assert!(
            AgentConfig::from_yaml(
                &with_release.replace("1.7.2", &"x".repeat(201)),
                Architecture::X86_64
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_fields_and_syscalls() {
        assert!(
            AgentConfig::from_yaml(
                &VALID.replace("processExec: true", "processExec: true\n  typo: true"),
                Architecture::X86_64
            )
            .is_err()
        );
        assert!(
            AgentConfig::from_yaml(&VALID.replace("ptrace", "101"), Architecture::X86_64).is_err()
        );
        assert!(
            AgentConfig::from_yaml(
                &VALID.replace(
                    "  syscalls: [ptrace, setns]",
                    "  syscalls: [ptrace, setns]\n  network:\n    connect: true\n    payloads: true"
                ),
                Architecture::X86_64
            )
            .is_err()
        );
    }

    #[test]
    fn network_connect_is_strict_opt_in_and_counts_as_observation() {
        let enabled = VALID.replace(
            "  syscalls: [ptrace, setns]",
            "  syscalls: []\n  network:\n    connect: true",
        );
        let config = AgentConfig::from_yaml(&enabled, Architecture::X86_64).unwrap();
        assert!(config.observation.network.connect);
        assert!(
            config
                .observation
                .capabilities()
                .contains(&protocol::NETWORK_CONNECT_CAPABILITY.to_owned())
        );

        let network_only = enabled.replace("  processExec: true", "  processExec: false");
        assert!(AgentConfig::from_yaml(&network_only, Architecture::X86_64).is_ok());

        let disabled = network_only.replace("    connect: true", "    connect: false");
        assert!(matches!(
            AgentConfig::from_yaml(&disabled, Architecture::X86_64),
            Err(ConfigError::MissingObservation)
        ));
        let defaulted = AgentConfig::from_yaml(VALID, Architecture::X86_64).unwrap();
        assert!(
            !defaulted
                .observation
                .capabilities()
                .contains(&protocol::NETWORK_CONNECT_CAPABILITY.to_owned())
        );
    }

    #[test]
    fn inbound_network_is_independently_opt_in_and_bounded() {
        let defaulted = AgentConfig::from_yaml(VALID, Architecture::X86_64).unwrap();
        assert!(!defaulted.observation.network.listen);
        assert!(!defaulted.observation.network.accept);

        let enabled = VALID.replace(
            "  syscalls: [ptrace, setns]",
            "  syscalls: []\n  network:\n    listen: true\n    accept: true\n    maxAcceptedEventsPerSecond: 250",
        );
        let config = AgentConfig::from_yaml(&enabled, Architecture::X86_64).unwrap();
        let capabilities = config.observation.capabilities();
        assert!(capabilities.contains(&protocol::NETWORK_LISTEN_CAPABILITY.to_owned()));
        assert!(capabilities.contains(&protocol::NETWORK_ACCEPT_CAPABILITY.to_owned()));
        assert_eq!(
            config.observation.network.max_accepted_events_per_second,
            250
        );

        let invalid = enabled.replace(
            "    maxAcceptedEventsPerSecond: 250",
            "    maxAcceptedEventsPerSecond: 0",
        );
        assert!(AgentConfig::from_yaml(&invalid, Architecture::X86_64).is_err());
        let unknown = enabled.replace("    accept: true", "    accept: true\n    payloads: true");
        assert!(AgentConfig::from_yaml(&unknown, Architecture::X86_64).is_err());
    }

    #[test]
    fn dns_is_default_disabled_strict_and_capability_versioned() {
        let defaulted = AgentConfig::from_yaml(VALID, Architecture::X86_64).unwrap();
        assert!(!defaulted.observation.network.dns.enabled);
        assert!(
            !defaulted
                .observation
                .capabilities()
                .iter()
                .any(|value| value.starts_with("network.dns."))
        );

        let enabled = VALID.replace(
            "  syscalls: [ptrace, setns]",
            "  syscalls: [ptrace, setns]\n  network:\n    dns:\n      enabled: true\n      udp: true\n      tcp: true",
        );
        let config = AgentConfig::from_yaml(&enabled, Architecture::X86_64).unwrap();
        let capabilities = config.observation.capabilities();
        assert!(capabilities.contains(&protocol::NETWORK_DNS_UDP_CAPABILITY.to_owned()));
        assert!(capabilities.contains(&protocol::NETWORK_DNS_TCP_CAPABILITY.to_owned()));

        let invalid = enabled.replace(
            "      tcp: true",
            "      tcp: true\n      maxCapturedBytes: 10",
        );
        assert!(AgentConfig::from_yaml(&invalid, Architecture::X86_64).is_err());
        let unknown = enabled.replace(
            "      tcp: true",
            "      tcp: true\n      packetPayloads: true",
        );
        assert!(AgentConfig::from_yaml(&unknown, Architecture::X86_64).is_err());
    }

    #[test]
    fn labels_are_and_and_selectors_can_be_or() {
        let selector = &AgentConfig::from_yaml(VALID, Architecture::X86_64)
            .unwrap()
            .scope
            .workloads[0];
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".into(), "payment-api".into());
        assert!(selector.matches(&WorkloadMetadata {
            namespace: "production".into(),
            kind: "Deployment".into(),
            name: "payment-api".into(),
            labels
        }));
    }

    #[test]
    fn files_are_strict_opt_in_with_component_filters() {
        let defaulted = AgentConfig::from_yaml(VALID, Architecture::X86_64).unwrap();
        assert!(!defaulted.observation.files.enabled);
        let enabled = VALID.replace(
            "  syscalls: [ptrace, setns]",
            "  syscalls: []\n  files:\n    enabled: true\n    operations: [create, modify, delete, rename]\n    includePaths: [/app/data]\n    excludePaths: [/app/data/cache]",
        );
        let config = AgentConfig::from_yaml(&enabled, Architecture::X86_64).unwrap();
        assert!(
            config
                .observation
                .capabilities()
                .contains(&protocol::FILE_ACTIVITY_CAPABILITY.to_owned())
        );
        assert!(
            config
                .observation
                .files
                .observes(&event_model::FileActivityPath::new("/app/data/report").unwrap())
        );
        assert!(
            !config
                .observation
                .files
                .observes(&event_model::FileActivityPath::new("/app/database/report").unwrap())
        );
        assert!(
            !config
                .observation
                .files
                .observes(&event_model::FileActivityPath::new("/app/data/cache/item").unwrap())
        );

        for replacement in [
            "    operations: []\n    includePaths: [/app/data]",
            "    operations: [create]\n    includePaths: []",
            "    operations: [create]\n    includePaths: [relative]",
            "    operations: [create]\n    includePaths: [/app/../secret]",
            "    operations: [unknown]\n    includePaths: [/app/data]",
        ] {
            let invalid = VALID.replace(
                "  syscalls: [ptrace, setns]",
                &format!("  syscalls: []\n  files:\n    enabled: true\n{replacement}"),
            );
            assert!(AgentConfig::from_yaml(&invalid, Architecture::X86_64).is_err());
        }
    }
}
