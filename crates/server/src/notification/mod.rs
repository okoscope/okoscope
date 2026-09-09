pub mod api;
pub mod crypto;
pub mod health;
pub mod recovery;
pub mod repository;
pub mod retention;
pub mod retention_api;
pub mod retention_settings;
pub mod webhook;
pub mod worker;

use sqlx::PgPool;

use crate::notification_config::NotificationConfig;

use self::{
    crypto::SecretVault, recovery::RecoveryRepository, repository::DestinationRepository,
    webhook::WebhookPolicy,
};

#[derive(Clone, Debug)]
pub struct NotificationService {
    pub pool: PgPool,
    pub config: NotificationConfig,
    pub vault: SecretVault,
    pub destinations: DestinationRepository,
    pub recovery: RecoveryRepository,
    pub policy: WebhookPolicy,
}

impl NotificationService {
    #[must_use]
    pub fn new(pool: PgPool, config: NotificationConfig) -> Option<Self> {
        let key = config.encryption_key.as_ref()?;
        let vault = SecretVault::new(key);
        let destinations = DestinationRepository::new(pool.clone(), vault.clone());
        let recovery = RecoveryRepository::new(pool.clone(), *key);
        let policy = WebhookPolicy {
            allow_http: config.allow_http,
            allow_private_ips: config.allow_private_ips,
            connect_timeout: config
                .request_timeout
                .min(std::time::Duration::from_secs(5)),
            request_timeout: config.request_timeout,
            max_response_bytes: config.max_response_bytes,
        };
        Some(Self {
            pool,
            config,
            vault,
            destinations,
            recovery,
            policy,
        })
    }
}
