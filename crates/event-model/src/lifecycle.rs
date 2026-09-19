//! Bounded process-start and named-thread lifecycle evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_THREAD_NAME_BYTES: usize = 15;
pub const MAX_THREAD_NAMES: usize = 64;
pub const THREAD_WINDOW_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineProvenance {
    Observed,
    Snapshot,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadGapReason {
    KernelLoss,
    DecodeFailure,
    AttributionFailure,
    StateCapacity,
    SnapshotRace,
    SnapshotPermission,
    SnapshotTruncated,
    DeliveryGap,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessGenerationIdentity {
    pub generation: u64,
    pub observation_epoch: Uuid,
    pub start_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStart {
    pub generation: ProcessGenerationIdentity,
    pub parent_pid: u32,
    pub parent_tgid: u32,
    pub parent_command: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadNameAggregate {
    pub name: String,
    pub created: u64,
    pub exited: u64,
    pub active: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadActivityWindow {
    pub id: Uuid,
    pub process: super::ProcessIdentity,
    pub generation: ProcessGenerationIdentity,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub created: u64,
    pub exited: u64,
    pub active_at_start: u64,
    pub active_at_end: u64,
    pub peak_active: u64,
    pub names: Vec<ThreadNameAggregate>,
    pub baseline_provenance: BaselineProvenance,
    pub baseline_complete: bool,
    pub name_overflow: u64,
    pub gaps: Vec<ThreadGapReason>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LifecycleValidationError {
    #[error("lifecycle identifier is invalid")]
    InvalidIdentifier,
    #[error("thread window bounds are invalid")]
    InvalidBounds,
    #[error("thread counters are inconsistent")]
    InvalidCounters,
    #[error("thread name is invalid or duplicated")]
    InvalidName,
    #[error("thread name capacity is exceeded")]
    NameCapacity,
    #[error("gap reasons are duplicated")]
    DuplicateGap,
}

impl ProcessGenerationIdentity {
    pub fn validate(&self) -> Result<(), LifecycleValidationError> {
        if self.generation == 0 || self.observation_epoch.is_nil() {
            return Err(LifecycleValidationError::InvalidIdentifier);
        }
        Ok(())
    }
}

impl ProcessStart {
    pub fn validate(&self) -> Result<(), LifecycleValidationError> {
        self.generation.validate()?;
        if !self.generation.start_observed
            || self.parent_pid == 0
            || self.parent_tgid == 0
            || !valid_name(&self.parent_command)
        {
            return Err(LifecycleValidationError::InvalidIdentifier);
        }
        Ok(())
    }
}

impl ThreadActivityWindow {
    pub fn validate(&self) -> Result<(), LifecycleValidationError> {
        self.generation.validate()?;
        if self.id.is_nil()
            || self.process.cgroup_id == 0
            || self.process.pid == 0
            || self.process.pid != self.process.tgid
        {
            return Err(LifecycleValidationError::InvalidIdentifier);
        }
        let duration = self.window_ended_at - self.window_started_at;
        if duration.num_seconds() != THREAD_WINDOW_SECONDS {
            return Err(LifecycleValidationError::InvalidBounds);
        }
        let expected_end = self.active_at_start.saturating_add(self.created);
        if expected_end < self.exited
            || expected_end - self.exited != self.active_at_end
            || self.peak_active < self.active_at_start.max(self.active_at_end)
            || self.peak_active > self.active_at_start.saturating_add(self.created)
        {
            return Err(LifecycleValidationError::InvalidCounters);
        }
        self.validate_names()?;
        let name_created = self.names.iter().map(|entry| entry.created).sum::<u64>();
        let name_exited = self.names.iter().map(|entry| entry.exited).sum::<u64>();
        let name_active = self.names.iter().map(|entry| entry.active).sum::<u64>();
        if name_created != self.created
            || name_exited != self.exited
            || name_active != self.active_at_end
            || (self.baseline_complete
                && (self.baseline_provenance == BaselineProvenance::Unavailable
                    || !self.gaps.is_empty()))
        {
            return Err(LifecycleValidationError::InvalidCounters);
        }
        let mut gaps = self.gaps.clone();
        gaps.sort_by_key(|value| *value as u8);
        gaps.dedup();
        if gaps.len() != self.gaps.len() {
            return Err(LifecycleValidationError::DuplicateGap);
        }
        Ok(())
    }

    fn validate_names(&self) -> Result<(), LifecycleValidationError> {
        if self.names.len() > MAX_THREAD_NAMES + 2 {
            return Err(LifecycleValidationError::NameCapacity);
        }
        let mut names = std::collections::HashSet::with_capacity(self.names.len());
        for entry in &self.names {
            if !valid_name(&entry.name) || !names.insert(entry.name.as_str()) {
                return Err(LifecycleValidationError::InvalidName);
            }
        }
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_THREAD_NAME_BYTES
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> ThreadActivityWindow {
        let start = Utc::now();
        ThreadActivityWindow {
            id: Uuid::new_v4(),
            process: super::super::ProcessIdentity {
                cgroup_id: 1,
                pid: 2,
                tgid: 2,
                command: "app".into(),
            },
            generation: ProcessGenerationIdentity {
                generation: 1,
                observation_epoch: Uuid::new_v4(),
                start_observed: true,
            },
            window_started_at: start,
            window_ended_at: start + chrono::Duration::seconds(60),
            created: 3,
            exited: 2,
            active_at_start: 1,
            active_at_end: 2,
            peak_active: 3,
            names: vec![ThreadNameAggregate {
                name: "worker".into(),
                created: 3,
                exited: 2,
                active: 2,
            }],
            baseline_provenance: BaselineProvenance::Observed,
            baseline_complete: true,
            name_overflow: 0,
            gaps: Vec::new(),
        }
    }

    #[test]
    fn validates_window_counter_invariants() {
        assert_eq!(window().validate(), Ok(()));
        let mut invalid = window();
        invalid.active_at_end = 99;
        assert_eq!(
            invalid.validate(),
            Err(LifecycleValidationError::InvalidCounters)
        );
    }

    #[test]
    fn rejects_duplicate_names_and_gaps() {
        let mut invalid = window();
        invalid.names.push(invalid.names[0].clone());
        assert_eq!(
            invalid.validate(),
            Err(LifecycleValidationError::InvalidName)
        );
        let mut invalid = window();
        invalid.baseline_complete = false;
        invalid.gaps = vec![ThreadGapReason::KernelLoss, ThreadGapReason::KernelLoss];
        assert_eq!(
            invalid.validate(),
            Err(LifecycleValidationError::DuplicateGap)
        );
    }

    #[test]
    fn rejects_name_totals_and_complete_baseline_with_gaps() {
        let mut invalid = window();
        invalid.names[0].created += 1;
        assert_eq!(
            invalid.validate(),
            Err(LifecycleValidationError::InvalidCounters)
        );

        let mut invalid = window();
        invalid.gaps.push(ThreadGapReason::KernelLoss);
        assert_eq!(
            invalid.validate(),
            Err(LifecycleValidationError::InvalidCounters)
        );
    }
}
