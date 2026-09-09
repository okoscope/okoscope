//! Closed, bounded process-termination and container-lifecycle evidence models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_TERMINATION_TEXT_BYTES: usize = 256;
pub const MAX_LINUX_SIGNAL: u8 = 64;
pub const MAX_NATIVE_EXIT_STATUS: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Kernel,
    Kubernetes,
    Derived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProcessTermination {
    Exited {
        status: u8,
    },
    Signaled {
        signal: u8,
        signal_name: String,
        core_dump_flag: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedGenerationReason {
    BeforeObservation,
    Evicted,
    GenerationMismatch,
    ContainerLifetimeMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GenerationCorrelation {
    Observed {
        generation: u64,
        exec_event_id: Uuid,
        executable: String,
    },
    Unresolved {
        reason: UnresolvedGenerationReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExit {
    pub source: EvidenceSource,
    pub raw_wait_status: i32,
    pub termination: ProcessTermination,
    pub correlation: GenerationCorrelation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerTermination {
    pub source: EvidenceSource,
    pub runtime_container_id: String,
    pub reason: String,
    pub exit_code: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRestart {
    pub source: EvidenceSource,
    pub runtime_container_id: String,
    pub restart_count: u32,
    pub restart_delta: u32,
    pub observation_gap: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_termination: Option<ContainerTermination>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartLoopSummary {
    pub source: EvidenceSource,
    pub projection_version: u16,
    pub threshold: u32,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub observed_restart_count: u32,
    pub container_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_termination: Option<ContainerTermination>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TerminationValidationError {
    #[error("evidence source is inconsistent with the event family")]
    InvalidSource,
    #[error("signal or canonical signal name is invalid")]
    InvalidSignal,
    #[error("a bounded text field is empty or too long")]
    InvalidText,
    #[error("container exit code must be non-negative")]
    InvalidContainerExitCode,
    #[error("termination timestamps are inconsistent")]
    InvalidTimestamps,
    #[error("restart count and delta are inconsistent")]
    InvalidRestartDelta,
    #[error("restart-loop projection fields are inconsistent")]
    InvalidRestartLoop,
}

impl ProcessTermination {
    pub fn exited(status: u8) -> Self {
        Self::Exited { status }
    }

    pub fn signaled(
        signal: u8,
        signal_name: impl Into<String>,
        core_dump_flag: bool,
    ) -> Result<Self, TerminationValidationError> {
        let signal_name = signal_name.into();
        if !(1..=MAX_LINUX_SIGNAL).contains(&signal) || !valid_signal_name(&signal_name) {
            return Err(TerminationValidationError::InvalidSignal);
        }
        Ok(Self::Signaled {
            signal,
            signal_name,
            core_dump_flag,
        })
    }

    #[must_use]
    pub fn conventional_exit_code(&self) -> Option<u16> {
        match self {
            Self::Exited { .. } => None,
            Self::Signaled { signal, .. } => Some(128 + u16::from(*signal)),
        }
    }
}

impl GenerationCorrelation {
    pub fn observed(
        generation: u64,
        exec_event_id: Uuid,
        executable: impl Into<String>,
    ) -> Result<Self, TerminationValidationError> {
        let executable = executable.into();
        if generation == 0 || !valid_text(&executable) {
            return Err(TerminationValidationError::InvalidText);
        }
        Ok(Self::Observed {
            generation,
            exec_event_id,
            executable,
        })
    }
}

impl ProcessExit {
    pub fn new(
        raw_wait_status: i32,
        termination: ProcessTermination,
        correlation: GenerationCorrelation,
    ) -> Self {
        Self {
            source: EvidenceSource::Kernel,
            raw_wait_status,
            termination,
            correlation,
        }
    }
}

impl ContainerTermination {
    pub fn new(
        runtime_container_id: impl Into<String>,
        reason: impl Into<String>,
        exit_code: i32,
        started_at: Option<DateTime<Utc>>,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<Self, TerminationValidationError> {
        let runtime_container_id = runtime_container_id.into();
        let reason = reason.into();
        if !valid_text(&runtime_container_id) || !valid_text(&reason) {
            return Err(TerminationValidationError::InvalidText);
        }
        if exit_code < 0 {
            return Err(TerminationValidationError::InvalidContainerExitCode);
        }
        if matches!((started_at, finished_at), (Some(start), Some(finish)) if finish < start) {
            return Err(TerminationValidationError::InvalidTimestamps);
        }
        Ok(Self {
            source: EvidenceSource::Kubernetes,
            runtime_container_id,
            reason,
            exit_code,
            started_at,
            finished_at,
        })
    }
}

impl ContainerRestart {
    pub fn new(
        runtime_container_id: impl Into<String>,
        restart_count: u32,
        restart_delta: u32,
        previous_termination: Option<ContainerTermination>,
        waiting_reason: Option<String>,
    ) -> Result<Self, TerminationValidationError> {
        let runtime_container_id = runtime_container_id.into();
        if !valid_text(&runtime_container_id)
            || waiting_reason
                .as_deref()
                .is_some_and(|value| !valid_text(value))
        {
            return Err(TerminationValidationError::InvalidText);
        }
        if restart_delta == 0 || restart_delta > restart_count {
            return Err(TerminationValidationError::InvalidRestartDelta);
        }
        if previous_termination
            .as_ref()
            .is_some_and(|value| value.source != EvidenceSource::Kubernetes)
        {
            return Err(TerminationValidationError::InvalidSource);
        }
        Ok(Self {
            source: EvidenceSource::Kubernetes,
            runtime_container_id,
            restart_count,
            restart_delta,
            observation_gap: restart_delta > 1,
            previous_termination,
            waiting_reason,
        })
    }
}

impl RestartLoopSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        projection_version: u16,
        threshold: u32,
        window_started_at: DateTime<Utc>,
        window_ended_at: DateTime<Utc>,
        observed_restart_count: u32,
        container_name: impl Into<String>,
        latest_termination: Option<ContainerTermination>,
        waiting_reason: Option<String>,
    ) -> Result<Self, TerminationValidationError> {
        let container_name = container_name.into();
        if !valid_text(&container_name)
            || waiting_reason
                .as_deref()
                .is_some_and(|value| !valid_text(value))
        {
            return Err(TerminationValidationError::InvalidText);
        }
        if projection_version == 0
            || threshold == 0
            || observed_restart_count < threshold
            || window_ended_at <= window_started_at
        {
            return Err(TerminationValidationError::InvalidRestartLoop);
        }
        Ok(Self {
            source: EvidenceSource::Derived,
            projection_version,
            threshold,
            window_started_at,
            window_ended_at,
            observed_restart_count,
            container_name,
            latest_termination,
            waiting_reason,
        })
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TERMINATION_TEXT_BYTES && !value.contains('\0')
}

fn valid_signal_name(value: &str) -> bool {
    valid_text(value)
        && value.starts_with("SIG")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'+')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_union_is_closed_and_conventional_code_is_derived() {
        assert_eq!(ProcessTermination::exited(7).conventional_exit_code(), None);
        let killed = ProcessTermination::signaled(9, "SIGKILL", false).unwrap();
        assert_eq!(killed.conventional_exit_code(), Some(137));
        assert_eq!(
            ProcessTermination::signaled(0, "SIGKILL", false),
            Err(TerminationValidationError::InvalidSignal)
        );
        assert_eq!(
            ProcessTermination::signaled(11, "segv", true),
            Err(TerminationValidationError::InvalidSignal)
        );
    }

    #[test]
    fn generation_correlation_never_resolves_a_reused_pid_by_itself() {
        let stale = GenerationCorrelation::Unresolved {
            reason: UnresolvedGenerationReason::GenerationMismatch,
        };
        assert!(matches!(
            stale,
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::GenerationMismatch
            }
        ));
        assert!(GenerationCorrelation::observed(0, Uuid::new_v4(), "/bin/worker").is_err());
        assert!(GenerationCorrelation::observed(2, Uuid::new_v4(), "/bin/worker").is_ok());
    }

    #[test]
    fn kubernetes_lifecycle_models_enforce_bounds_and_gap_semantics() {
        let now = Utc::now();
        let terminated =
            ContainerTermination::new("containerd://abc", "OOMKilled", 137, Some(now), Some(now))
                .unwrap();
        let restart = ContainerRestart::new(
            "containerd://abc",
            7,
            3,
            Some(terminated.clone()),
            Some("CrashLoopBackOff".into()),
        )
        .unwrap();
        assert!(restart.observation_gap);
        assert_eq!(
            ContainerRestart::new("containerd://abc", 7, 0, None, None),
            Err(TerminationValidationError::InvalidRestartDelta)
        );
        assert!(
            RestartLoopSummary::new(
                1,
                3,
                now,
                now + chrono::Duration::minutes(10),
                3,
                "worker",
                Some(terminated),
                Some("CrashLoopBackOff".into()),
            )
            .is_ok()
        );
    }

    #[test]
    fn lifecycle_text_and_timestamps_are_bounded() {
        let now = Utc::now();
        assert_eq!(
            ContainerTermination::new(
                "containerd://abc",
                "OOMKilled",
                137,
                Some(now),
                Some(now - chrono::Duration::seconds(1)),
            ),
            Err(TerminationValidationError::InvalidTimestamps)
        );
        assert_eq!(
            ContainerTermination::new(
                "x".repeat(MAX_TERMINATION_TEXT_BYTES + 1),
                "Error",
                1,
                None,
                None,
            ),
            Err(TerminationValidationError::InvalidText)
        );
    }
}
