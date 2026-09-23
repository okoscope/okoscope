use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::ReleaseIdentity;

pub const RESOURCE_SCHEMA_VERSION: u16 = 1;
pub const MAX_RESOURCE_BATCH_AGGREGATES: usize = 256;
pub const MAX_RESOURCE_INTERVAL_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAvailability {
    Available,
    Unsupported,
    NoLimit,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ResourceValues {
    pub cpu_usage_usec: Option<u64>,
    pub cpu_nr_periods: Option<u64>,
    pub cpu_nr_throttled: Option<u64>,
    pub cpu_throttled_usec: Option<u64>,
    pub cpu_quota_usec: Option<u64>,
    pub cpu_period_usec: Option<u64>,
    pub memory_current_sum_bytes: Option<u64>,
    pub memory_current_min_bytes: Option<u64>,
    pub memory_current_max_bytes: Option<u64>,
    pub memory_anon_sum_bytes: Option<u64>,
    pub memory_file_sum_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_high_events: Option<u64>,
    pub memory_max_events: Option<u64>,
    pub memory_oom_events: Option<u64>,
    pub memory_oom_kill_events: Option<u64>,
    pub cpu_psi_some_usec: Option<u64>,
    pub cpu_psi_full_usec: Option<u64>,
    pub memory_psi_some_usec: Option<u64>,
    pub memory_psi_full_usec: Option<u64>,
    pub io_psi_some_usec: Option<u64>,
    pub io_psi_full_usec: Option<u64>,
    pub io_read_bytes: Option<u64>,
    pub io_write_bytes: Option<u64>,
    pub io_read_operations: Option<u64>,
    pub io_write_operations: Option<u64>,
    pub pids_current_sum: Option<u64>,
    pub pids_current_max: Option<u64>,
    pub pids_limit: Option<u64>,
    pub pids_max_events: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResourceAggregate {
    pub id: Uuid,
    pub schema_version: u16,
    pub interval_start: DateTime<Utc>,
    pub interval_end: DateTime<Utc>,
    pub covered_usec: u64,
    pub sample_count: u32,
    pub contributing_containers: u32,
    pub ready_containers: u32,
    pub namespace: String,
    pub workload_uid: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub container_name: String,
    pub node_name: String,
    pub release_identity: Option<ReleaseIdentity>,
    pub unavailable_sources: u64,
    pub values: ResourceValues,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ResourceValidationError {
    #[error("unsupported resource schema version")]
    SchemaVersion,
    #[error("resource interval is invalid or outside bounds")]
    Interval,
    #[error("resource coverage exceeds the aggregate interval")]
    Coverage,
    #[error("resource aggregate contains no samples")]
    Empty,
    #[error("resource identity field {0} is invalid")]
    Identity(&'static str),
    #[error("resource limit pair is incomplete")]
    CpuLimit,
}

impl ResourceAggregate {
    pub fn validate(&self) -> Result<(), ResourceValidationError> {
        if self.schema_version != RESOURCE_SCHEMA_VERSION {
            return Err(ResourceValidationError::SchemaVersion);
        }
        let duration = self.interval_end - self.interval_start;
        if duration.num_seconds() <= 0 || duration.num_seconds() > MAX_RESOURCE_INTERVAL_SECONDS {
            return Err(ResourceValidationError::Interval);
        }
        let interval_usec =
            u64::try_from(duration.num_microseconds().unwrap_or(i64::MAX)).unwrap_or(u64::MAX);
        if self.covered_usec > interval_usec.saturating_mul(u64::from(self.contributing_containers))
        {
            return Err(ResourceValidationError::Coverage);
        }
        if self.sample_count == 0 || self.contributing_containers == 0 {
            return Err(ResourceValidationError::Empty);
        }
        if self.ready_containers > self.contributing_containers {
            return Err(ResourceValidationError::Coverage);
        }
        validate_identity("namespace", &self.namespace, 253)?;
        validate_identity("workload_uid", &self.workload_uid, 253)?;
        validate_identity("workload_kind", &self.workload_kind, 64)?;
        validate_identity("workload_name", &self.workload_name, 253)?;
        validate_identity("container_name", &self.container_name, 256)?;
        validate_identity("node_name", &self.node_name, 253)?;
        if self.values.cpu_quota_usec.is_some() != self.values.cpu_period_usec.is_some() {
            return Err(ResourceValidationError::CpuLimit);
        }
        Ok(())
    }
}

fn validate_identity(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ResourceValidationError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(ResourceValidationError::Identity(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_rejects_impossible_coverage_and_partial_cpu_limit() {
        let now = Utc::now();
        let mut value = ResourceAggregate {
            id: Uuid::new_v4(),
            schema_version: RESOURCE_SCHEMA_VERSION,
            interval_start: now,
            interval_end: now + chrono::Duration::minutes(1),
            covered_usec: 60_000_000,
            sample_count: 4,
            contributing_containers: 1,
            ready_containers: 1,
            namespace: "default".into(),
            workload_uid: "deployment-1".into(),
            workload_kind: "Deployment".into(),
            workload_name: "api".into(),
            container_name: "api".into(),
            node_name: "node-1".into(),
            release_identity: None,
            unavailable_sources: 0,
            values: ResourceValues::default(),
        };
        assert_eq!(value.validate(), Ok(()));
        value.covered_usec += 1;
        assert_eq!(value.validate(), Err(ResourceValidationError::Coverage));
        value.covered_usec -= 1;
        value.values.cpu_quota_usec = Some(50_000);
        assert_eq!(value.validate(), Err(ResourceValidationError::CpuLimit));
    }
}
