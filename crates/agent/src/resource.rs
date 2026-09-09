#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeMap;

#[cfg(any(target_os = "linux", test))]
use std::collections::{HashMap, HashSet};

#[cfg(any(target_os = "linux", test))]
use chrono::{DateTime, TimeZone, Utc};
#[cfg(any(target_os = "linux", test))]
use event_model::ResourceValues;
#[cfg(any(target_os = "linux", test))]
use event_model::{KubernetesAttribution, RESOURCE_SCHEMA_VERSION, ResourceAggregate};
#[cfg(any(target_os = "linux", test))]
use thiserror::Error;
#[cfg(any(target_os = "linux", test))]
use uuid::Uuid;

#[cfg(any(target_os = "linux", test))]
use crate::{
    attribution::AttributionCache,
    cgroup::{CgroupResolver, ContainerCgroup},
    config::{ResourceObservationConfig, WorkloadSelector},
    counters::Counters,
};

pub const SOURCE_CPU: u64 = 1 << 0;
pub const SOURCE_MEMORY: u64 = 1 << 1;
pub const SOURCE_CPU_PSI: u64 = 1 << 2;
pub const SOURCE_MEMORY_PSI: u64 = 1 << 3;
pub const SOURCE_IO: u64 = 1 << 4;
pub const SOURCE_IO_PSI: u64 = 1 << 5;
pub const SOURCE_PIDS: u64 = 1 << 6;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Snapshot {
    cpu_usage: Option<u64>,
    cpu_periods: Option<u64>,
    cpu_throttled: Option<u64>,
    cpu_throttled_usec: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
    memory_current: Option<u64>,
    memory_anon: Option<u64>,
    memory_file: Option<u64>,
    memory_limit: Option<u64>,
    memory_high: Option<u64>,
    memory_max: Option<u64>,
    memory_oom: Option<u64>,
    memory_oom_kill: Option<u64>,
    cpu_psi_some: Option<u64>,
    cpu_psi_full: Option<u64>,
    memory_psi_some: Option<u64>,
    memory_psi_full: Option<u64>,
    io_psi_some: Option<u64>,
    io_psi_full: Option<u64>,
    io_read_bytes: Option<u64>,
    io_write_bytes: Option<u64>,
    io_read_ops: Option<u64>,
    io_write_ops: Option<u64>,
    pids_current: Option<u64>,
    pids_limit: Option<u64>,
    pids_max: Option<u64>,
    unavailable: u64,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Error, Eq, PartialEq)]
enum ParseError {
    #[error("required key {0} is absent")]
    Missing(&'static str),
    #[error("invalid unsigned value")]
    Unsigned,
    #[error("counter moved backwards")]
    Reset,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LifetimeKey {
    inode: u64,
    container_id: String,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AggregateKey {
    route_id: Uuid,
    bucket_start: DateTime<Utc>,
    namespace: String,
    workload_uid: String,
    workload_kind: String,
    workload_name: String,
    container_name: String,
    release_digest: Option<[u8; 32]>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
struct Previous {
    observed_at: DateTime<Utc>,
    snapshot: Snapshot,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
struct OpenAggregate {
    attribution: KubernetesAttribution,
    covered_usec: u64,
    sample_count: u32,
    contributors: HashSet<LifetimeKey>,
    ready_containers: HashSet<LifetimeKey>,
    unavailable: u64,
    values: ResourceValues,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub struct ResourceSampler {
    state_limit: usize,
    aggregate_limit: usize,
    previous: HashMap<LifetimeKey, Previous>,
    open: BTreeMap<AggregateKey, OpenAggregate>,
}

#[cfg(any(target_os = "linux", test))]
impl ResourceSampler {
    #[must_use]
    pub fn new(config: &ResourceObservationConfig) -> Self {
        Self {
            state_limit: config.max_cgroup_states,
            aggregate_limit: config.max_open_aggregates,
            previous: HashMap::new(),
            open: BTreeMap::new(),
        }
    }

    pub fn sample(
        &mut self,
        resolver: &mut CgroupResolver,
        cache: &AttributionCache,
        node_name: &str,
        selectors: &[WorkloadSelector],
        now: DateTime<Utc>,
        counters: &Counters,
    ) -> Vec<(Uuid, ResourceAggregate)> {
        let mut completed = self.flush_before(bucket_start(now));
        let Ok(cgroups) = resolver.container_cgroups() else {
            counters
                .resource_parse_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return completed;
        };
        let mut seen = HashSet::with_capacity(cgroups.len());
        for cgroup in cgroups {
            self.sample_cgroup(
                &cgroup, cache, node_name, selectors, now, counters, &mut seen,
            );
        }
        self.previous.retain(|key, _| seen.contains(key));
        completed.shrink_to_fit();
        completed
    }

    #[allow(clippy::too_many_arguments)]
    fn sample_cgroup(
        &mut self,
        cgroup: &ContainerCgroup,
        cache: &AttributionCache,
        node_name: &str,
        selectors: &[WorkloadSelector],
        now: DateTime<Utc>,
        counters: &Counters,
        seen: &mut HashSet<LifetimeKey>,
    ) {
        let Ok(attribution) = cache.resolve(&cgroup.container_id, node_name, selectors) else {
            return;
        };
        counters
            .resource_discovered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = LifetimeKey {
            inode: cgroup.inode,
            container_id: cgroup.container_id.clone(),
        };
        seen.insert(key.clone());
        let snapshot = read_snapshot(&cgroup.path);
        counters.resource_unsupported_sources.fetch_add(
            snapshot.unavailable.count_ones().into(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let Some(previous) = self.previous.get(&key) else {
            if self.previous.len() < self.state_limit {
                self.previous.insert(
                    key,
                    Previous {
                        observed_at: now,
                        snapshot,
                    },
                );
            } else {
                counters
                    .resource_state_capacity_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        };
        let elapsed = (now - previous.observed_at)
            .num_microseconds()
            .and_then(|value| u64::try_from(value).ok());
        let values = elapsed.and_then(|covered| {
            delta(&snapshot, &previous.snapshot, covered)
                .ok()
                .map(|values| (covered, values))
        });
        if values.is_none() {
            counters
                .resource_counter_reset
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.previous.insert(
            key.clone(),
            Previous {
                observed_at: now,
                snapshot: snapshot.clone(),
            },
        );
        if let Some((covered, values)) = values {
            self.add(
                attribution,
                key,
                now,
                covered,
                snapshot.unavailable,
                &values,
                counters,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        attribution: KubernetesAttribution,
        lifetime: LifetimeKey,
        now: DateTime<Utc>,
        covered: u64,
        unavailable: u64,
        values: &ResourceValues,
        counters: &Counters,
    ) {
        let key = AggregateKey {
            route_id: attribution.application_id,
            bucket_start: bucket_start(now),
            namespace: attribution.namespace.clone(),
            workload_uid: attribution.workload_uid.clone(),
            workload_kind: attribution.workload_kind.clone(),
            workload_name: attribution.workload_name.clone(),
            container_name: attribution.container_name.clone(),
            release_digest: attribution
                .release_identity
                .as_ref()
                .map(|value| value.digest),
        };
        if !self.open.contains_key(&key) && self.open.len() >= self.aggregate_limit {
            counters
                .resource_aggregate_capacity_dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let bucket = self.open.entry(key).or_insert_with(|| OpenAggregate {
            attribution,
            covered_usec: 0,
            sample_count: 0,
            contributors: HashSet::new(),
            ready_containers: HashSet::new(),
            unavailable: 0,
            values: ResourceValues::default(),
        });
        bucket.covered_usec = bucket.covered_usec.saturating_add(covered);
        bucket.sample_count = bucket.sample_count.saturating_add(1);
        bucket.contributors.insert(lifetime.clone());
        bucket.ready_containers.insert(lifetime);
        bucket.unavailable |= unavailable;
        merge_values(&mut bucket.values, values);
    }

    fn flush_before(&mut self, boundary: DateTime<Utc>) -> Vec<(Uuid, ResourceAggregate)> {
        let keys = self
            .open
            .keys()
            .take_while(|key| key.bucket_start < boundary)
            .cloned()
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| {
                self.open.remove(&key).map(|bucket| {
                    let interval_end = key.bucket_start + chrono::Duration::minutes(1);
                    let aggregate = ResourceAggregate {
                        id: Uuid::new_v4(),
                        schema_version: RESOURCE_SCHEMA_VERSION,
                        interval_start: key.bucket_start,
                        interval_end,
                        covered_usec: bucket.covered_usec,
                        sample_count: bucket.sample_count,
                        contributing_containers: u32::try_from(bucket.contributors.len())
                            .unwrap_or(u32::MAX),
                        ready_containers: u32::try_from(bucket.ready_containers.len())
                            .unwrap_or(u32::MAX),
                        namespace: key.namespace,
                        workload_uid: key.workload_uid,
                        workload_kind: key.workload_kind,
                        workload_name: key.workload_name,
                        container_name: key.container_name,
                        node_name: bucket.attribution.node_name,
                        release_identity: bucket.attribution.release_identity,
                        unavailable_sources: bucket.unavailable,
                        values: bucket.values,
                    };
                    (key.route_id, aggregate)
                })
            })
            .collect()
    }
}

#[cfg(any(target_os = "linux", test))]
fn bucket_start(now: DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_opt(now.timestamp() - now.timestamp().rem_euclid(60), 0)
        .single()
        .unwrap_or(now)
}

#[cfg(any(target_os = "linux", test))]
fn read_snapshot(path: &std::path::Path) -> Snapshot {
    let mut value = Snapshot::default();
    if let Some(map) = read_key_values(path.join("cpu.stat")) {
        value.cpu_usage = map.get("usage_usec").copied();
        value.cpu_periods = map.get("nr_periods").copied();
        value.cpu_throttled = map.get("nr_throttled").copied();
        value.cpu_throttled_usec = map.get("throttled_usec").copied();
    } else {
        value.unavailable |= SOURCE_CPU;
    }
    if let Some((quota, period)) = read_limit_pair(path.join("cpu.max")) {
        value.cpu_quota = quota;
        value.cpu_period = Some(period);
    }
    value.memory_current = read_single(path.join("memory.current"));
    let mut memory_supported = value.memory_current.is_some();
    value.memory_limit = read_limit(path.join("memory.max"));
    if let Some(map) = read_key_values(path.join("memory.stat")) {
        value.memory_anon = map.get("anon").copied();
        value.memory_file = map.get("file").copied();
        memory_supported &= value.memory_anon.is_some() && value.memory_file.is_some();
    } else {
        memory_supported = false;
    }
    if let Some(map) = read_key_values(path.join("memory.events.local")) {
        value.memory_high = map.get("high").copied();
        value.memory_max = map.get("max").copied();
        value.memory_oom = map.get("oom").copied();
        value.memory_oom_kill = map.get("oom_kill").copied();
    } else {
        memory_supported = false;
    }
    if !memory_supported {
        value.unavailable |= SOURCE_MEMORY;
    }
    (value.cpu_psi_some, value.cpu_psi_full) =
        read_psi(path.join("cpu.pressure")).unwrap_or_else(|| {
            value.unavailable |= SOURCE_CPU_PSI;
            (None, None)
        });
    (value.memory_psi_some, value.memory_psi_full) = read_psi(path.join("memory.pressure"))
        .unwrap_or_else(|| {
            value.unavailable |= SOURCE_MEMORY_PSI;
            (None, None)
        });
    (value.io_psi_some, value.io_psi_full) =
        read_psi(path.join("io.pressure")).unwrap_or_else(|| {
            value.unavailable |= SOURCE_IO_PSI;
            (None, None)
        });
    if let Some(io) = std::fs::read_to_string(path.join("io.stat"))
        .ok()
        .and_then(|text| parse_io(&text).ok())
    {
        value.io_read_bytes = Some(io.0);
        value.io_write_bytes = Some(io.1);
        value.io_read_ops = Some(io.2);
        value.io_write_ops = Some(io.3);
    } else {
        value.unavailable |= SOURCE_IO;
    }
    value.pids_current = read_single(path.join("pids.current"));
    value.pids_limit = read_limit(path.join("pids.max"));
    value.pids_max =
        read_key_values(path.join("pids.events")).and_then(|map| map.get("max").copied());
    if value.pids_current.is_none() || value.pids_max.is_none() {
        value.unavailable |= SOURCE_PIDS;
    }
    value
}

#[cfg(any(target_os = "linux", test))]
fn read_key_values(path: std::path::PathBuf) -> Option<BTreeMap<String, u64>> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| parse_key_values(&text).ok())
}
#[cfg(any(target_os = "linux", test))]
fn read_single(path: std::path::PathBuf) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}
#[cfg(any(target_os = "linux", test))]
fn read_limit(path: std::path::PathBuf) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_limit(text.trim()).ok().flatten()
}
#[cfg(any(target_os = "linux", test))]
fn read_limit_pair(path: std::path::PathBuf) -> Option<(Option<u64>, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_limit_pair(&text).ok()
}
#[cfg(any(target_os = "linux", test))]
fn read_psi(path: std::path::PathBuf) -> Option<(Option<u64>, Option<u64>)> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_psi(&text).ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_key_values(text: &str) -> Result<BTreeMap<String, u64>, ParseError> {
    text.lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next().ok_or(ParseError::Unsigned)?;
            let value = fields
                .next()
                .ok_or(ParseError::Unsigned)?
                .parse()
                .map_err(|_| ParseError::Unsigned)?;
            Ok((key.to_owned(), value))
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_limit(text: &str) -> Result<Option<u64>, ParseError> {
    if text == "max" {
        Ok(None)
    } else {
        text.parse().map(Some).map_err(|_| ParseError::Unsigned)
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_limit_pair(text: &str) -> Result<(Option<u64>, u64), ParseError> {
    let mut fields = text.split_whitespace();
    let quota = parse_limit(fields.next().ok_or(ParseError::Unsigned)?)?;
    let period = fields
        .next()
        .ok_or(ParseError::Unsigned)?
        .parse()
        .map_err(|_| ParseError::Unsigned)?;
    if period == 0 {
        return Err(ParseError::Unsigned);
    }
    Ok((quota, period))
}

#[cfg(any(target_os = "linux", test))]
fn parse_psi(text: &str) -> Result<(Option<u64>, Option<u64>), ParseError> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().ok_or(ParseError::Unsigned)?;
        let total = fields
            .find_map(|field| field.strip_prefix("total="))
            .map(str::parse)
            .transpose()
            .map_err(|_| ParseError::Unsigned)?;
        match kind {
            "some" => some = total,
            "full" => full = total,
            _ => {}
        }
    }
    if some.is_none() && full.is_none() {
        Err(ParseError::Missing("total"))
    } else {
        Ok((some, full))
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_io(text: &str) -> Result<(u64, u64, u64, u64), ParseError> {
    let mut totals = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut devices = 0_u64;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let device = fields.next().ok_or(ParseError::Unsigned)?;
        if !device.contains(':') {
            return Err(ParseError::Unsigned);
        }
        devices += 1;
        for field in fields {
            let Some((key, raw)) = field.split_once('=') else {
                continue;
            };
            let value = raw.parse::<u64>().map_err(|_| ParseError::Unsigned)?;
            match key {
                "rbytes" => totals.0 = totals.0.checked_add(value).ok_or(ParseError::Unsigned)?,
                "wbytes" => totals.1 = totals.1.checked_add(value).ok_or(ParseError::Unsigned)?,
                "rios" => totals.2 = totals.2.checked_add(value).ok_or(ParseError::Unsigned)?,
                "wios" => totals.3 = totals.3.checked_add(value).ok_or(ParseError::Unsigned)?,
                _ => {}
            }
        }
    }
    if devices == 0 {
        Err(ParseError::Missing("device"))
    } else {
        Ok(totals)
    }
}

#[cfg(any(target_os = "linux", test))]
fn delta(
    current: &Snapshot,
    previous: &Snapshot,
    _covered: u64,
) -> Result<ResourceValues, ParseError> {
    Ok(ResourceValues {
        cpu_usage_usec: counter(current.cpu_usage, previous.cpu_usage)?,
        cpu_nr_periods: counter(current.cpu_periods, previous.cpu_periods)?,
        cpu_nr_throttled: counter(current.cpu_throttled, previous.cpu_throttled)?,
        cpu_throttled_usec: counter(current.cpu_throttled_usec, previous.cpu_throttled_usec)?,
        cpu_quota_usec: current.cpu_quota,
        cpu_period_usec: current.cpu_period,
        memory_current_sum_bytes: current.memory_current,
        memory_current_min_bytes: current.memory_current,
        memory_current_max_bytes: current.memory_current,
        memory_anon_sum_bytes: current.memory_anon,
        memory_file_sum_bytes: current.memory_file,
        memory_limit_bytes: current.memory_limit,
        memory_high_events: counter(current.memory_high, previous.memory_high)?,
        memory_max_events: counter(current.memory_max, previous.memory_max)?,
        memory_oom_events: counter(current.memory_oom, previous.memory_oom)?,
        memory_oom_kill_events: counter(current.memory_oom_kill, previous.memory_oom_kill)?,
        cpu_psi_some_usec: counter(current.cpu_psi_some, previous.cpu_psi_some)?,
        cpu_psi_full_usec: counter(current.cpu_psi_full, previous.cpu_psi_full)?,
        memory_psi_some_usec: counter(current.memory_psi_some, previous.memory_psi_some)?,
        memory_psi_full_usec: counter(current.memory_psi_full, previous.memory_psi_full)?,
        io_psi_some_usec: counter(current.io_psi_some, previous.io_psi_some)?,
        io_psi_full_usec: counter(current.io_psi_full, previous.io_psi_full)?,
        io_read_bytes: counter(current.io_read_bytes, previous.io_read_bytes)?,
        io_write_bytes: counter(current.io_write_bytes, previous.io_write_bytes)?,
        io_read_operations: counter(current.io_read_ops, previous.io_read_ops)?,
        io_write_operations: counter(current.io_write_ops, previous.io_write_ops)?,
        pids_current_sum: current.pids_current,
        pids_current_max: current.pids_current,
        pids_limit: current.pids_limit,
        pids_max_events: counter(current.pids_max, previous.pids_max)?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn counter(current: Option<u64>, previous: Option<u64>) -> Result<Option<u64>, ParseError> {
    current
        .zip(previous)
        .map(|(current, previous)| current.checked_sub(previous).ok_or(ParseError::Reset))
        .transpose()
}

#[cfg(any(target_os = "linux", test))]
fn merge_values(target: &mut ResourceValues, value: &ResourceValues) {
    macro_rules! sum { ($($field:ident),+) => { $(target.$field = sum_option(target.$field, value.$field);)+ }; }
    sum!(
        cpu_usage_usec,
        cpu_nr_periods,
        cpu_nr_throttled,
        cpu_throttled_usec,
        memory_current_sum_bytes,
        memory_anon_sum_bytes,
        memory_file_sum_bytes,
        memory_high_events,
        memory_max_events,
        memory_oom_events,
        memory_oom_kill_events,
        cpu_psi_some_usec,
        cpu_psi_full_usec,
        memory_psi_some_usec,
        memory_psi_full_usec,
        io_psi_some_usec,
        io_psi_full_usec,
        io_read_bytes,
        io_write_bytes,
        io_read_operations,
        io_write_operations,
        pids_current_sum,
        pids_max_events
    );
    target.memory_current_min_bytes = min_option(
        target.memory_current_min_bytes,
        value.memory_current_min_bytes,
    );
    target.memory_current_max_bytes = max_option(
        target.memory_current_max_bytes,
        value.memory_current_max_bytes,
    );
    target.pids_current_max = max_option(target.pids_current_max, value.pids_current_max);
    target.cpu_quota_usec = value.cpu_quota_usec.or(target.cpu_quota_usec);
    target.cpu_period_usec = value.cpu_period_usec.or(target.cpu_period_usec);
    target.memory_limit_bytes = value.memory_limit_bytes.or(target.memory_limit_bytes);
    target.pids_limit = value.pids_limit.or(target.pids_limit);
}

#[cfg(any(target_os = "linux", test))]
fn sum_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (value, None) | (None, value) => value,
    }
}
#[cfg(any(target_os = "linux", test))]
fn min_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    left.zip(right).map(|(a, b)| a.min(b)).or(left).or(right)
}
#[cfg(any(target_os = "linux", test))]
fn max_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    left.zip(right).map(|(a, b)| a.max(b)).or(left).or(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribution(
        route_id: Uuid,
        container: &str,
        release: Option<[u8; 32]>,
    ) -> KubernetesAttribution {
        KubernetesAttribution {
            project_id: Uuid::new_v4(),
            application_id: route_id,
            node_name: "node-a".into(),
            namespace: "production".into(),
            pod_uid: format!("pod-{container}"),
            pod_name: format!("api-{container}"),
            container_id: container.into(),
            container_name: "api".into(),
            workload_uid: "deployment-api".into(),
            workload_kind: "Deployment".into(),
            workload_name: "api".into(),
            release: None,
            release_identity: release.map(|digest| event_model::ReleaseIdentity {
                version: 1,
                digest,
                containers: Vec::new(),
            }),
        }
    }

    fn sampler(state_limit: usize, aggregate_limit: usize) -> ResourceSampler {
        ResourceSampler::new(&ResourceObservationConfig {
            max_cgroup_states: state_limit,
            max_open_aggregates: aggregate_limit,
            ..ResourceObservationConfig::default()
        })
    }

    #[test]
    fn parsers_accept_unknown_keys_and_unlimited_values() {
        let values = parse_key_values("usage_usec 42\nnew_key 9\n").unwrap();
        assert_eq!(values["usage_usec"], 42);
        assert_eq!(parse_limit_pair("max 100000\n"), Ok((None, 100_000)));
        assert_eq!(
            parse_psi("some avg10=0.10 total=120\nfull avg10=0.00 total=2\n"),
            Ok((Some(120), Some(2)))
        );
        assert_eq!(
            parse_io("8:0 rbytes=10 wbytes=20 rios=2 wios=3 dbytes=99\n"),
            Ok((10, 20, 2, 3))
        );
    }

    #[test]
    fn reset_is_rejected_while_missing_sources_remain_missing() {
        let current = Snapshot {
            cpu_usage: Some(9),
            ..Snapshot::default()
        };
        let previous = Snapshot {
            cpu_usage: Some(10),
            ..Snapshot::default()
        };
        assert_eq!(delta(&current, &previous, 1), Err(ParseError::Reset));
        assert_eq!(counter(None, Some(10)), Ok(None));
    }

    #[test]
    fn parsers_cover_missing_added_overflow_and_unlimited_sources() {
        assert_eq!(parse_limit("max"), Ok(None));
        assert_eq!(
            parse_limit("18446744073709551616"),
            Err(ParseError::Unsigned)
        );
        assert_eq!(parse_limit_pair("10000 0"), Err(ParseError::Unsigned));
        assert_eq!(
            parse_psi("some avg10=0.1"),
            Err(ParseError::Missing("total"))
        );
        assert_eq!(parse_io(""), Err(ParseError::Missing("device")));
        assert_eq!(
            parse_io("8:0 rbytes=18446744073709551615\n8:1 rbytes=1\n"),
            Err(ParseError::Unsigned)
        );
        assert_eq!(parse_io("8:0 rbytes=1 future=99\n"), Ok((1, 0, 0, 0)));
    }

    #[test]
    fn aggregation_separates_routes_releases_and_counts_replicas() {
        let mut sampler = sampler(8, 8);
        let counters = Counters::default();
        let now = Utc.timestamp_opt(1_800_000_010, 0).single().unwrap();
        let values = ResourceValues {
            cpu_usage_usec: Some(10),
            ..ResourceValues::default()
        };
        let route_a = Uuid::new_v4();
        let route_b = Uuid::new_v4();
        for (index, (route, container, release)) in [
            (route_a, "container-1", Some([1; 32])),
            (route_a, "container-2", Some([1; 32])),
            (route_a, "container-3", Some([2; 32])),
            (route_b, "container-4", Some([1; 32])),
        ]
        .into_iter()
        .enumerate()
        {
            sampler.add(
                attribution(route, container, release),
                LifetimeKey {
                    inode: u64::try_from(index).unwrap(),
                    container_id: container.into(),
                },
                now,
                10_000_000,
                0,
                &values,
                &counters,
            );
        }
        let flushed = sampler.flush_before(now + chrono::Duration::minutes(1));
        assert_eq!(flushed.len(), 3);
        assert!(flushed.iter().any(|(route, aggregate)| {
            *route == route_a && aggregate.contributing_containers == 2
        }));
        assert!(flushed.iter().any(|(route, _)| *route == route_b));
    }

    #[test]
    fn lifetime_and_capacity_bound_state_without_cross_lifetime_deltas() {
        let mut sampler = sampler(1, 1);
        sampler.previous.insert(
            LifetimeKey {
                inode: 7,
                container_id: "old".into(),
            },
            Previous {
                observed_at: Utc::now(),
                snapshot: Snapshot::default(),
            },
        );
        let reused = LifetimeKey {
            inode: 7,
            container_id: "new".into(),
        };
        assert!(!sampler.previous.contains_key(&reused));

        let counters = Counters::default();
        let now = Utc.timestamp_opt(1_800_000_010, 0).single().unwrap();
        let values = ResourceValues {
            cpu_usage_usec: Some(1),
            ..ResourceValues::default()
        };
        for (index, name) in ["one", "two"].into_iter().enumerate() {
            sampler.add(
                attribution(Uuid::new_v4(), name, None),
                LifetimeKey {
                    inode: u64::try_from(index).unwrap(),
                    container_id: name.into(),
                },
                now,
                1,
                0,
                &values,
                &counters,
            );
        }
        assert_eq!(sampler.open.len(), 1);
        assert_eq!(
            counters
                .resource_aggregate_capacity_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn short_lived_containers_are_pruned_and_restart_has_no_baseline() {
        let mut running = sampler(4, 4);
        let surviving = LifetimeKey {
            inode: 1,
            container_id: "surviving".into(),
        };
        let disappeared = LifetimeKey {
            inode: 2,
            container_id: "disappeared".into(),
        };
        let previous = Previous {
            observed_at: Utc::now(),
            snapshot: Snapshot::default(),
        };
        running.previous.insert(surviving.clone(), previous.clone());
        running.previous.insert(disappeared, previous);
        let seen = HashSet::from([surviving.clone()]);
        running.previous.retain(|key, _| seen.contains(key));
        assert_eq!(running.previous.len(), 1);
        assert!(running.previous.contains_key(&surviving));

        let restarted = sampler(4, 4);
        assert!(restarted.previous.is_empty());
        assert!(restarted.open.is_empty());
    }

    #[test]
    fn unsupported_files_mark_sources_independently() {
        let root = std::env::temp_dir().join(format!("okoscope-resource-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("cpu.stat"),
            "usage_usec 10\nnr_periods 2\nnr_throttled 1\nthrottled_usec 3\n",
        )
        .unwrap();
        std::fs::write(root.join("cpu.max"), "max 100000\n").unwrap();
        std::fs::write(root.join("pids.current"), "3\n").unwrap();
        std::fs::write(root.join("pids.max"), "max\n").unwrap();
        std::fs::write(root.join("pids.events"), "max 0\n").unwrap();
        let snapshot = read_snapshot(&root);
        assert_eq!(snapshot.unavailable & SOURCE_CPU, 0);
        assert_eq!(snapshot.unavailable & SOURCE_PIDS, 0);
        assert_eq!(snapshot.pids_current, Some(3));
        assert_eq!(snapshot.pids_max, Some(0));
        assert_ne!(snapshot.unavailable & SOURCE_MEMORY, 0);
        assert_ne!(snapshot.unavailable & SOURCE_IO, 0);
        std::fs::remove_dir_all(root).unwrap();
    }
}
