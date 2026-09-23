use std::time::Duration;

use clap::Args;
use thiserror::Error;

#[derive(Clone, Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct NotificationArgs {
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_DELIVERY_ENABLED",
        default_value_t = false
    )]
    pub enabled: bool,
    #[arg(long, env = "OKOSCOPE_WEBHOOK_ENCRYPTION_KEY")]
    pub encryption_key: Option<String>,
    #[arg(long, env = "OKOSCOPE_NOTIFICATION_POLL_MS", default_value_t = 1000)]
    pub poll_ms: u64,
    #[arg(long, env = "OKOSCOPE_NOTIFICATION_CLAIM_SIZE", default_value_t = 50)]
    pub claim_size: u32,
    #[arg(long, env = "OKOSCOPE_NOTIFICATION_CONCURRENCY", default_value_t = 8)]
    pub concurrency: u32,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_LEASE_SECONDS",
        default_value_t = 30
    )]
    pub lease_seconds: u64,
    #[arg(long, env = "OKOSCOPE_WEBHOOK_TIMEOUT_SECONDS", default_value_t = 10)]
    pub request_timeout_seconds: u64,
    #[arg(long, env = "OKOSCOPE_WEBHOOK_MAX_ATTEMPTS", default_value_t = 8)]
    pub max_attempts: u32,
    #[arg(
        long,
        env = "OKOSCOPE_WEBHOOK_BACKOFF_MIN_SECONDS",
        default_value_t = 5
    )]
    pub backoff_min_seconds: u64,
    #[arg(
        long,
        env = "OKOSCOPE_WEBHOOK_BACKOFF_MAX_SECONDS",
        default_value_t = 3600
    )]
    pub backoff_max_seconds: u64,
    #[arg(
        long,
        env = "OKOSCOPE_WEBHOOK_MAX_RESPONSE_BYTES",
        default_value_t = 4096
    )]
    pub max_response_bytes: usize,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_DRAIN_SECONDS",
        default_value_t = 15
    )]
    pub shutdown_drain_seconds: u64,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_RETENTION_ENABLED",
        default_value_t = false
    )]
    pub retention_enabled: bool,
    /// Pause maintenance independently of tenant policies (legacy import is unaffected).
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_RETENTION_PAUSED",
        default_value_t = false
    )]
    pub retention_paused: bool,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_TERMINAL_RETENTION_DAYS",
        default_value_t = 90
    )]
    pub terminal_retention_days: u64,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_RECOVERY_RETENTION_DAYS",
        default_value_t = 365
    )]
    pub recovery_retention_days: u64,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_RETENTION_BATCH_SIZE",
        default_value_t = 1000
    )]
    pub retention_batch_size: i64,
    #[arg(
        long,
        env = "OKOSCOPE_NOTIFICATION_RETENTION_POLL_SECONDS",
        default_value_t = 3600
    )]
    pub retention_poll_seconds: u64,
    #[arg(long, env = "OKOSCOPE_WEBHOOK_ALLOW_HTTP", default_value_t = false)]
    pub allow_http: bool,
    #[arg(
        long,
        env = "OKOSCOPE_WEBHOOK_ALLOW_PRIVATE_IPS",
        default_value_t = false
    )]
    pub allow_private_ips: bool,
}

impl Default for NotificationArgs {
    fn default() -> Self {
        Self {
            enabled: false,
            encryption_key: None,
            poll_ms: 1000,
            claim_size: 50,
            concurrency: 8,
            lease_seconds: 30,
            request_timeout_seconds: 10,
            max_attempts: 8,
            backoff_min_seconds: 5,
            backoff_max_seconds: 3600,
            max_response_bytes: 4096,
            shutdown_drain_seconds: 15,
            retention_enabled: false,
            retention_paused: false,
            terminal_retention_days: 90,
            recovery_retention_days: 365,
            retention_batch_size: 1000,
            retention_poll_seconds: 3600,
            allow_http: false,
            allow_private_ips: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub poll_interval: Duration,
    pub claim_size: u32,
    pub concurrency: usize,
    pub lease_duration: Duration,
    pub request_timeout: Duration,
    pub max_attempts: u32,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub max_response_bytes: usize,
    pub shutdown_drain: Duration,
    pub retention: crate::notification::retention::RetentionConfig,
    pub allow_http: bool,
    pub allow_private_ips: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NotificationConfigError {
    #[error("notification delivery requires a 64-character hexadecimal encryption key")]
    InvalidEncryptionKey,
    #[error("notification delivery {0} is outside its supported range")]
    InvalidBound(&'static str),
    #[error("minimum webhook backoff must not exceed maximum backoff")]
    InvalidBackoff,
    #[error("private webhook addresses require both HTTP development mode and plaintext transport")]
    UnsafePrivateAddresses,
}

impl NotificationArgs {
    pub fn build(
        &self,
        development_plaintext: bool,
    ) -> Result<NotificationConfig, NotificationConfigError> {
        let encryption_key = self.encryption_key.as_deref().map(decode_key).transpose()?;
        if self.enabled
            && encryption_key
                .as_ref()
                .is_none_or(|key| key.iter().all(|byte| *byte == 0))
        {
            return Err(NotificationConfigError::InvalidEncryptionKey);
        }
        validate_range("poll interval", self.poll_ms, 50, 60_000)?;
        validate_range("claim size", u64::from(self.claim_size), 1, 1_000)?;
        validate_range("concurrency", u64::from(self.concurrency), 1, 256)?;
        validate_range("lease duration", self.lease_seconds, 5, 3_600)?;
        validate_range("request timeout", self.request_timeout_seconds, 1, 120)?;
        validate_range("maximum attempts", u64::from(self.max_attempts), 1, 100)?;
        validate_range("minimum backoff", self.backoff_min_seconds, 1, 86_400)?;
        validate_range("maximum backoff", self.backoff_max_seconds, 1, 604_800)?;
        validate_range(
            "response byte limit",
            u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX),
            128,
            65_536,
        )?;
        validate_range("shutdown drain", self.shutdown_drain_seconds, 1, 300)?;
        validate_range("terminal retention", self.terminal_retention_days, 1, 3650)?;
        validate_range("recovery retention", self.recovery_retention_days, 1, 3650)?;
        validate_range(
            "retention batch size",
            u64::try_from(self.retention_batch_size).unwrap_or_default(),
            1,
            10_000,
        )?;
        validate_range("retention poll", self.retention_poll_seconds, 60, 86_400)?;
        if self.backoff_min_seconds > self.backoff_max_seconds {
            return Err(NotificationConfigError::InvalidBackoff);
        }
        if self.allow_private_ips && !(self.allow_http && development_plaintext) {
            return Err(NotificationConfigError::UnsafePrivateAddresses);
        }
        Ok(NotificationConfig {
            enabled: self.enabled,
            encryption_key,
            poll_interval: Duration::from_millis(self.poll_ms),
            claim_size: self.claim_size,
            concurrency: usize::try_from(self.concurrency).unwrap_or(usize::MAX),
            lease_duration: Duration::from_secs(self.lease_seconds),
            request_timeout: Duration::from_secs(self.request_timeout_seconds),
            max_attempts: self.max_attempts,
            backoff_min: Duration::from_secs(self.backoff_min_seconds),
            backoff_max: Duration::from_secs(self.backoff_max_seconds),
            max_response_bytes: self.max_response_bytes,
            shutdown_drain: Duration::from_secs(self.shutdown_drain_seconds),
            retention: crate::notification::retention::RetentionConfig {
                enabled: !self.retention_paused,
                batch_size: self.retention_batch_size,
                poll_interval: Duration::from_secs(self.retention_poll_seconds),
            },
            allow_http: self.allow_http,
            allow_private_ips: self.allow_private_ips,
        })
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32], NotificationConfigError> {
    let bytes = hex::decode(encoded).map_err(|_| NotificationConfigError::InvalidEncryptionKey)?;
    bytes
        .try_into()
        .map_err(|_| NotificationConfigError::InvalidEncryptionKey)
}

fn validate_range(
    name: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), NotificationConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(NotificationConfigError::InvalidBound(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_defaults_are_valid_and_disabled() {
        let config = NotificationArgs::default().build(false).unwrap();
        assert!(!config.enabled);
        assert!(!config.allow_http);
        assert!(!config.allow_private_ips);
        assert!(config.encryption_key.is_none());
        assert!(config.retention.enabled);
    }

    #[test]
    fn operational_pause_is_independent_of_legacy_policy_and_delivery() {
        let args = NotificationArgs {
            retention_enabled: true,
            retention_paused: true,
            ..NotificationArgs::default()
        };
        let config = args.build(false).unwrap();
        assert!(!config.retention.enabled);
        assert!(!config.enabled);
    }

    #[test]
    fn enabled_worker_requires_key_and_valid_bounds() {
        let args = NotificationArgs {
            enabled: true,
            ..NotificationArgs::default()
        };
        assert_eq!(
            args.build(false),
            Err(NotificationConfigError::InvalidEncryptionKey)
        );
        let args = NotificationArgs {
            poll_ms: 1,
            ..NotificationArgs::default()
        };
        assert_eq!(
            args.build(false),
            Err(NotificationConfigError::InvalidBound("poll interval"))
        );
        let args = NotificationArgs {
            enabled: true,
            encryption_key: Some(hex::encode([0_u8; 32])),
            ..NotificationArgs::default()
        };
        assert_eq!(
            args.build(false),
            Err(NotificationConfigError::InvalidEncryptionKey)
        );
        let args = NotificationArgs {
            shutdown_drain_seconds: 0,
            ..NotificationArgs::default()
        };
        assert_eq!(
            args.build(false),
            Err(NotificationConfigError::InvalidBound("shutdown drain"))
        );
    }

    #[test]
    fn private_addresses_require_explicit_development_mode() {
        let args = NotificationArgs {
            allow_http: true,
            allow_private_ips: true,
            ..NotificationArgs::default()
        };
        assert_eq!(
            args.build(false),
            Err(NotificationConfigError::UnsafePrivateAddresses)
        );
        assert!(args.build(true).is_ok());
    }
}
