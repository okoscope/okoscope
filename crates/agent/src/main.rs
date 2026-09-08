#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("okoscope-agent requires Linux; userspace libraries and tests support this host");
}

#[cfg(any(target_os = "linux", test))]
mod handshake {
    use agent::config::AgentConfig;
    #[cfg(test)]
    use agent::counters::Counters;
    use protocol::v1::AgentHello;
    #[cfg(test)]
    use uuid::Uuid;

    pub(super) fn hello(
        config: &AgentConfig,
        snapshot: &agent::counters::CounterSnapshot,
        process_exit_ready: bool,
        container_lifecycle_ready: bool,
        resource_ready: bool,
        cluster_uid: String,
    ) -> AgentHello {
        let mut capabilities = config.observation.capabilities();
        if process_exit_ready {
            capabilities.push(protocol::PROCESS_EXIT_CAPABILITY.into());
        }
        if container_lifecycle_ready {
            capabilities.push(protocol::CONTAINER_LIFECYCLE_CAPABILITY.into());
        }
        capabilities.push(protocol::KUBERNETES_RELEASE_DISCOVERY_CAPABILITY.into());
        capabilities.push(protocol::ONBOARDING_STATUS_CAPABILITY.into());
        if resource_ready {
            capabilities.push(protocol::RESOURCE_UTILIZATION_CAPABILITY.into());
        }
        AgentHello {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            node_name: config.identity.node_name.clone(),
            architecture: std::env::consts::ARCH.into(),
            kernel_release: kernel_release(),
            capabilities,
            drop_counters: Some((*snapshot).into()),
            cluster_uid,
            cluster_name: config.identity.cluster_name.clone(),
            resource_counters: Some(protocol::v1::ResourceCounters::default()),
        }
    }

    #[test]
    fn hello_transmits_configured_cluster_display_name() {
        let config: AgentConfig = serde_yaml::from_str(
            r#"
apiVersion: okoscope.io/v1alpha1
kind: AgentConfiguration
server:
  endpoint: https://grpc.example.com:443
identity:
  nodeName: worker-1
  clusterName: Production Europe
scope:
  workloads: []
observation:
  processExec: true
"#,
        )
        .unwrap();
        let uid = Uuid::new_v4().to_string();
        let greeting = hello(
            &config,
            &Counters::default().snapshot(),
            false,
            false,
            false,
            uid.clone(),
        );
        assert_eq!(greeting.cluster_name, "Production Europe");
        assert_eq!(greeting.cluster_uid, uid);
    }

    #[test]
    fn resource_capability_is_omitted_when_profile_is_not_ready() {
        let config: AgentConfig = serde_yaml::from_str(
            r#"
apiVersion: okoscope.io/v1alpha1
kind: AgentConfiguration
server: { endpoint: https://grpc.example.com:443 }
identity: { nodeName: worker-1, clusterName: test }
scope: { workloads: [] }
observation: { processExec: true }
"#,
        )
        .unwrap();
        let greeting = hello(
            &config,
            &Counters::default().snapshot(),
            false,
            false,
            false,
            Uuid::new_v4().to_string(),
        );
        assert!(
            !greeting
                .capabilities
                .iter()
                .any(|value| value == protocol::RESOURCE_UTILIZATION_CAPABILITY)
        );
    }

    fn kernel_release() -> String {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|_| "unknown".into(), |value| value.trim().into())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        path::PathBuf,
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };

    use super::handshake::hello;
    use agent::{
        attribution::{AttributionCache, resolve_and_count, run_watches},
        cgroup, cluster_identity,
        config::{AgentConfig, load_application_credentials},
        counters::Counters,
        delivery::EventRateLimiter,
        dns_runtime::DnsProcessor,
        file_runtime::{FileModifyAggregator, translate_rename_scope},
        multi_stream::ApplicationStreams,
        observer::Observer,
        process_runtime::ProcessGenerationStore,
        resource::ResourceSampler,
        syscall::{self, Architecture},
    };
    use agent_ebpf_common::KernelEvent;
    use anyhow::{Context, Result};
    use chrono::Utc;
    use clap::Parser;
    use event_model::{
        EVENT_SCHEMA_VERSION, EventPayload, GenerationCorrelation, ProcessExec, ProcessExit,
        ProcessIdentity, RuntimeEvent, SyscallEvent, UnresolvedGenerationReason,
    };
    use tracing_subscriber::EnvFilter;
    use uuid::Uuid;

    #[derive(Debug, Parser)]
    struct Args {
        #[arg(
            long,
            env = "OKOSCOPE_CONFIG",
            default_value = "/etc/okoscope/agent.yaml"
        )]
        config: PathBuf,
        #[arg(
            long,
            env = "OKOSCOPE_EBPF_OBJECT",
            default_value = "/opt/okoscope/agent-ebpf"
        )]
        ebpf_object: PathBuf,
        #[arg(
            long,
            env = "OKOSCOPE_PROCESS_EXIT_EBPF_OBJECT",
            default_value = "/opt/okoscope/process-exit.bpf.o"
        )]
        process_exit_ebpf_object: PathBuf,
    }

    #[allow(clippy::too_many_lines)]
    pub async fn main() -> Result<()> {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
        let args = Args::parse();
        let architecture = Architecture::current().context("unsupported CPU architecture")?;
        let config = load_config(&args, architecture).await?;
        if config
            .scope
            .workloads
            .iter()
            .any(|selector| selector.release.is_some())
        {
            tracing::warn!(
                "scope.workloads[].release is deprecated; observed Kubernetes image digests take precedence"
            );
        }
        let credentials = load_application_credentials(&config).await?;
        let cluster_uid = cluster_identity::discover(kube::Client::try_default().await?)
            .await
            .context("discover Kubernetes cluster identity")?;
        let counters = Arc::new(Counters::default());
        let (cache, mut lifecycle_receiver, mut lifecycle_readiness, mut release_receiver) =
            start_attribution_cache(counters.clone(), config.scope.workloads.clone()).await?;
        let mut observer = load_observer(&args, &config, architecture)?;
        let process_exit_ready = if config.observation.process_exit {
            match observer.enable_process_exit(&args.process_exit_ebpf_object) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(%error, "process exit observation unavailable; capability withheld");
                    counters.unsupported.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        } else {
            false
        };
        let mut cgroup_resolver =
            cgroup::CgroupResolver::new("/sys/fs/cgroup").context("index host cgroup hierarchy")?;
        let mut resource_sampler = config
            .observation
            .resources
            .enabled
            .then(|| ResourceSampler::new(&config.observation.resources));
        let mut rate_limiter = EventRateLimiter::new(config.safety.max_events_per_second);
        let mut dns_rate_limiter =
            EventRateLimiter::new(config.observation.network.dns.max_events_per_second);
        let mut inbound_rate_limiter =
            EventRateLimiter::new(config.observation.network.max_accepted_events_per_second);
        let mut dns_processor = DnsProcessor::new(&config.observation.network.dns);
        let mut file_aggregator = FileModifyAggregator::default();
        let mut process_generations = ProcessGenerationStore::new(8192);
        let hello = hello(
            &config,
            &counters.snapshot(),
            process_exit_ready,
            *lifecycle_readiness.borrow() == agent::attribution::KubernetesWatchState::Ready,
            config.observation.resources.enabled
                && std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            cluster_uid,
        );
        let streams = ApplicationStreams::start(
            &config.server,
            credentials,
            &hello,
            &config.safety,
            &config.observation.resources,
            counters.clone(),
            &lifecycle_readiness,
            config.observation.process_exit && !process_exit_ready,
        );
        tracing::info!(
            application_streams = streams.route_count(),
            "Application stream runtimes started"
        );
        let mut poll = tokio::time::interval(Duration::from_millis(10));
        let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
        let mut resource_poll = tokio::time::interval(Duration::from_secs(
            config.observation.resources.sample_interval_seconds,
        ));
        let mut lifecycle_readiness_open = true;
        loop {
            tokio::select! {
                _ = resource_poll.tick(), if resource_sampler.is_some() => {
                    if let Some(sampler) = resource_sampler.as_mut() {
                        for (route_id, aggregate) in sampler.sample(
                            &mut cgroup_resolver, &cache, &config.identity.node_name,
                            &config.scope.workloads, Utc::now(), &counters,
                        ) {
                            streams.route_resource(route_id, aggregate);
                        }
                    }
                }
                _ = poll.tick() => {
                    while let Ok(observation) = release_receiver.try_recv() {
                        streams.route_release_observation(observation);
                    }
                    while let Ok(observation) = lifecycle_receiver.try_recv() {
                        let Some(attribution) = resolve_and_count(
                            &cache, &counters, Some(&observation.container_id),
                            &config.identity.node_name, &config.scope.workloads,
                        ) else {
                            counters.lifecycle_attribution_failed.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let command = attribution.container_name.clone();
                        let event = RuntimeEvent {
                            id: Uuid::new_v4(), observed_at: Utc::now(),
                            schema_version: EVENT_SCHEMA_VERSION, attribution,
                            process: ProcessIdentity { cgroup_id: 0, pid: 0, tgid: 0, command },
                            payload: observation.payload,
                        };
                        if rate_limiter.allow() { streams.route(event); }
                        else { counters.capacity_dropped.fetch_add(1, Ordering::Relaxed); }
                    }
                    while let Some(decoded) = observer.next_file_event() {
                        let Ok(decoded) = decoded else {
                            counters.decode_failed.fetch_add(1, Ordering::Relaxed);
                            counters.file_decode_failed.fetch_add(1, Ordering::Relaxed);
                            counters.file_path_invalid.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let fd = decoded.kernel.fd;
                        let generation = decoded.kernel.descriptor_generation;
                        let Some(event) = runtime_file_event(
                            decoded, &mut cgroup_resolver, &cache, &counters, &config,
                        ) else { continue };
                        let (ready, dropped) = file_aggregator.observe(event, fd, generation, Instant::now());
                        if dropped {
                            counters.file_aggregation_capacity.fetch_add(1, Ordering::Relaxed);
                        }
                        for event in ready {
                            if rate_limiter.allow() { streams.route(event); }
                            else {
                                counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
                                counters.file_rate_limited.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    for event in file_aggregator.drain_expired(Instant::now()) {
                        if rate_limiter.allow() { streams.route(event); }
                        else {
                            counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
                            counters.file_rate_limited.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    while let Some(packet) = observer.next_dns_packet()? {
                        let Some((process, payload)) = dns_processor.process(&packet, &counters) else { continue };
                        let container = cgroup_resolver.resolve(process.pid, process.cgroup_id).ok();
                        let Some(attribution) = resolve_and_count(
                            &cache, &counters, container.as_deref(), &config.identity.node_name,
                            &config.scope.workloads,
                        ) else { continue };
                        let event = RuntimeEvent {
                            id: Uuid::new_v4(), observed_at: Utc::now(),
                            schema_version: EVENT_SCHEMA_VERSION, attribution, process, payload,
                        };
                        if dns_rate_limiter.allow() && rate_limiter.allow() {
                            streams.route(event);
                        } else {
                            counters.dns_rate_limited.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    while let Some(kernel) = observer.next_inbound_event()? {
                        let is_accept = kernel.event_kind == agent_ebpf_common::EVENT_KIND_NETWORK_ACCEPT;
                        let Some(event) = runtime_inbound_event(
                            &kernel, &mut cgroup_resolver, &cache, &counters, &config,
                        ) else { continue };
                        if (!is_accept || inbound_rate_limiter.allow()) && rate_limiter.allow() {
                            streams.route(event);
                        } else {
                            counters.inbound_rate_limited.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    while let Some(kernel) = observer.next_event()? {
                        let Some(event) = runtime_event(&kernel, architecture, &mut cgroup_resolver, &cache, &counters, &config, &mut dns_processor) else { continue };
                        if let EventPayload::ProcessExec(exec) = &event.payload {
                            process_generations.observe_exec(
                                kernel.pid_tgid, kernel.cgroup_id, kernel.timestamp_ns,
                                event.id, exec.executable.clone(),
                            );
                        }
                        if rate_limiter.allow() {
                            streams.route(event);
                        } else {
                            counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    while let Some(decoded) = observer.next_exit_event() {
                        let Ok(decoded) = decoded else {
                            counters.decode_failed.fetch_add(1, Ordering::Relaxed);
                            counters.exit_decode_failed.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let Some(event) = runtime_exit_event(
                            decoded, &mut process_generations, &mut cgroup_resolver,
                            &cache, &counters, &config,
                        ) else { continue };
                        if rate_limiter.allow() {
                            streams.route(event);
                        } else {
                            counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
                            counters.exit_rate_limited.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    counters.update_network_kernel(observer.network_counters()?);
                    counters.update_inbound_kernel(observer.inbound_kernel_counters()?);
                    counters.update_dns_kernel(observer.dns_kernel_counters()?);
                    counters.update_file_kernel(observer.file_kernel_counters()?);
                    counters.update_exit_kernel(observer.exit_kernel_counters()?);
                    let snapshot = counters.snapshot();
                    tracing::info!(?snapshot, "agent status");
                }
                readiness = lifecycle_readiness.changed(), if lifecycle_readiness_open => {
                    if readiness.is_err() {
                        lifecycle_readiness_open = false;
                        tracing::warn!("Kubernetes lifecycle readiness channel closed");
                    } else {
                        tracing::info!(state = ?*lifecycle_readiness.borrow(), "Kubernetes lifecycle readiness changed");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    for event in file_aggregator.drain_all() {
                        if rate_limiter.allow() { streams.route(event); }
                        else {
                            counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
                            counters.file_rate_limited.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    streams.shutdown().await;
                    return Ok(());
                },
            }
        }
    }

    async fn start_attribution_cache(
        counters: Arc<Counters>,
        selectors: Vec<agent::config::WorkloadSelector>,
    ) -> Result<(
        Arc<AttributionCache>,
        tokio::sync::mpsc::Receiver<agent::lifecycle::LifecycleObservation>,
        tokio::sync::watch::Receiver<agent::attribution::KubernetesWatchState>,
        tokio::sync::mpsc::Receiver<agent::attribution::ReleaseObservation>,
    )> {
        let cache = Arc::new(AttributionCache::new(Duration::from_secs(30)));
        let watch_cache = cache.clone();
        let watch_client = kube::Client::try_default().await?;
        let (lifecycle_sender, lifecycle_receiver) = tokio::sync::mpsc::channel(4096);
        let (readiness_sender, readiness_receiver) =
            tokio::sync::watch::channel(agent::attribution::KubernetesWatchState::Starting);
        let (release_sender, release_receiver) = tokio::sync::mpsc::channel(4096);
        tokio::spawn(async move {
            if let Err(error) = run_watches(
                watch_client,
                watch_cache,
                lifecycle_sender,
                counters,
                readiness_sender,
                release_sender,
                Arc::new(selectors),
            )
            .await
            {
                tracing::error!(%error, "Kubernetes attribution watch stopped");
            }
        });
        Ok((
            cache,
            lifecycle_receiver,
            readiness_receiver,
            release_receiver,
        ))
    }

    fn load_observer(
        args: &Args,
        config: &AgentConfig,
        architecture: Architecture,
    ) -> Result<Observer> {
        Observer::load(
            &args.ebpf_object,
            &config.observation.syscalls,
            agent::observer::ObservationPrograms {
                network_connect: config.observation.network.connect.into(),
                network_listen: config.observation.network.listen.into(),
                network_accept: config.observation.network.accept.into(),
                dns: config.observation.network.dns.enabled.into(),
                files: config.observation.files.enabled.into(),
            },
            architecture,
        )
    }

    async fn load_config(args: &Args, architecture: Architecture) -> Result<AgentConfig> {
        let yaml = tokio::fs::read_to_string(&args.config)
            .await
            .context("read agent configuration")?;
        let mut config = AgentConfig::from_yaml(&yaml, architecture)?;
        if let Ok(node_name) = std::env::var("OKOSCOPE_NODE_NAME") {
            config.identity.node_name = node_name;
        }
        Ok(config)
    }

    fn runtime_event(
        kernel: &KernelEvent,
        architecture: Architecture,
        cgroup_resolver: &mut cgroup::CgroupResolver,
        cache: &AttributionCache,
        counters: &Counters,
        config: &AgentConfig,
        dns_processor: &mut DnsProcessor,
    ) -> Option<RuntimeEvent> {
        let pid = u32::try_from(kernel.pid_tgid & u64::from(u32::MAX))
            .expect("PID is encoded in the low 32 bits");
        let tgid =
            u32::try_from(kernel.pid_tgid >> 32).expect("TGID is encoded in the high 32 bits");
        let container = match cgroup_resolver.resolve(pid, kernel.cgroup_id) {
            Ok(container) => Some(container),
            Err(error) => {
                tracing::debug!(pid, cgroup_id = kernel.cgroup_id, %error, "kernel event cgroup resolution failed");
                None
            }
        };
        let attribution = resolve_and_count(
            cache,
            counters,
            container.as_deref(),
            &config.identity.node_name,
            &config.scope.workloads,
        )?;
        let command = command(&kernel.command);
        let mut payload = if kernel.event_kind == agent_ebpf_common::EVENT_KIND_EXEC {
            let executable = std::fs::read_link(format!("/proc/{pid}/exe")).map_or_else(
                |_| command.clone(),
                |path| path.to_string_lossy().into_owned(),
            );
            EventPayload::ProcessExec(ProcessExec {
                executable,
                parent_command: None,
            })
        } else if kernel.event_kind == agent_ebpf_common::EVENT_KIND_SYSCALL {
            let Some(name) = syscall::name_for_number(kernel.syscall_id, architecture) else {
                counters.unsupported.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            EventPayload::Syscall(SyscallEvent { name: name.into() })
        } else if kernel.event_kind == agent_ebpf_common::EVENT_KIND_NETWORK_CONNECT {
            let Ok(network) = agent::kernel_event::network_connect(kernel) else {
                counters
                    .connect_decode_failed
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            };
            EventPayload::NetworkConnect(network)
        } else {
            counters.unsupported.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        dns_processor.attach_context(kernel.cgroup_id, &mut payload);
        Some(RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution,
            process: ProcessIdentity {
                cgroup_id: kernel.cgroup_id,
                pid,
                tgid,
                command,
            },
            payload,
        })
    }

    fn runtime_inbound_event(
        kernel: &agent_ebpf_common::InboundKernelEvent,
        cgroup_resolver: &mut cgroup::CgroupResolver,
        cache: &AttributionCache,
        counters: &Counters,
        config: &AgentConfig,
    ) -> Option<RuntimeEvent> {
        let pid = u32::try_from(kernel.pid_tgid & u64::from(u32::MAX))
            .expect("PID is encoded in the low 32 bits");
        let tgid =
            u32::try_from(kernel.pid_tgid >> 32).expect("TGID is encoded in the high 32 bits");
        let container = cgroup_resolver.resolve(pid, kernel.cgroup_id).ok();
        let attribution = resolve_and_count(
            cache,
            counters,
            container.as_deref(),
            &config.identity.node_name,
            &config.scope.workloads,
        )?;
        let Ok(payload) = agent::kernel_event::inbound_payload(kernel) else {
            counters
                .inbound_decode_failed
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution,
            process: ProcessIdentity {
                cgroup_id: kernel.cgroup_id,
                pid,
                tgid,
                command: command(&kernel.command),
            },
            payload,
        })
    }

    fn runtime_file_event(
        decoded: agent::kernel_event::DecodedFileEvent,
        cgroup_resolver: &mut cgroup::CgroupResolver,
        cache: &AttributionCache,
        counters: &Counters,
        config: &AgentConfig,
    ) -> Option<RuntimeEvent> {
        let kernel = decoded.kernel;
        let pid = u32::try_from(kernel.pid_tgid & u64::from(u32::MAX)).ok()?;
        let tgid = u32::try_from(kernel.pid_tgid >> 32).ok()?;
        let container = cgroup_resolver.resolve(pid, kernel.cgroup_id).ok();
        let attribution = resolve_and_count(
            cache,
            counters,
            container.as_deref(),
            &config.identity.node_name,
            &config.scope.workloads,
        );
        let Some(attribution) = attribution else {
            counters
                .file_attribution_failed
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let payload = match decoded.payload {
            EventPayload::FileCreate(value) if config.observation.files.observes(&value.path) => {
                EventPayload::FileCreate(value)
            }
            EventPayload::FileModify(value) if config.observation.files.observes(&value.path) => {
                EventPayload::FileModify(value)
            }
            EventPayload::FileDelete(value) if config.observation.files.observes(&value.path) => {
                EventPayload::FileDelete(value)
            }
            EventPayload::FileRename(value) => {
                let old_observed = config.observation.files.observes(&value.old_path);
                let new_observed = config.observation.files.observes(&value.new_path);
                let Some(payload) = translate_rename_scope(value, old_observed, new_observed)
                else {
                    counters.filtered.fetch_add(1, Ordering::Relaxed);
                    counters.file_filtered.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                payload
            }
            EventPayload::FileCreate(_)
            | EventPayload::FileModify(_)
            | EventPayload::FileDelete(_) => {
                counters.filtered.fetch_add(1, Ordering::Relaxed);
                counters.file_filtered.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            _ => return None,
        };
        Some(RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution,
            process: ProcessIdentity {
                cgroup_id: kernel.cgroup_id,
                pid,
                tgid,
                command: command(&kernel.command),
            },
            payload,
        })
    }

    fn runtime_exit_event(
        decoded: agent::kernel_event::DecodedExitEvent,
        process_generations: &mut ProcessGenerationStore,
        cgroup_resolver: &mut cgroup::CgroupResolver,
        cache: &AttributionCache,
        counters: &Counters,
        config: &AgentConfig,
    ) -> Option<RuntimeEvent> {
        let kernel = decoded.kernel;
        let pid = u32::try_from(kernel.pid_tgid & u64::from(u32::MAX)).ok()?;
        let tgid = u32::try_from(kernel.pid_tgid >> 32).ok()?;
        let container = cgroup_resolver.resolve(pid, kernel.cgroup_id).ok();
        let Some(attribution) = resolve_and_count(
            cache,
            counters,
            container.as_deref(),
            &config.identity.node_name,
            &config.scope.workloads,
        ) else {
            counters
                .exit_attribution_failed
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let correlation = process_generations.consume_exit(
            kernel.pid_tgid,
            kernel.cgroup_id,
            kernel.timestamp_ns,
        );
        if let GenerationCorrelation::Unresolved { reason } = &correlation {
            match reason {
                UnresolvedGenerationReason::BeforeObservation => counters
                    .exit_correlation_before_observation
                    .fetch_add(1, Ordering::Relaxed),
                UnresolvedGenerationReason::Evicted => counters
                    .exit_correlation_evicted
                    .fetch_add(1, Ordering::Relaxed),
                UnresolvedGenerationReason::GenerationMismatch => counters
                    .exit_correlation_generation_mismatch
                    .fetch_add(1, Ordering::Relaxed),
                UnresolvedGenerationReason::ContainerLifetimeMismatch => counters
                    .exit_correlation_container_mismatch
                    .fetch_add(1, Ordering::Relaxed),
            };
        }
        Some(RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution,
            process: ProcessIdentity {
                cgroup_id: kernel.cgroup_id,
                pid,
                tgid,
                command: command(&kernel.command),
            },
            payload: EventPayload::ProcessExit(ProcessExit::new(
                kernel.raw_wait_status,
                decoded.termination,
                correlation,
            )),
        })
    }

    fn command(bytes: &[u8; 16]) -> String {
        String::from_utf8_lossy(
            &bytes[..bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len())],
        )
        .into_owned()
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    linux::main().await
}
