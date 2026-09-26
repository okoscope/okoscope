//! A project's notifications as its members manage them: webhook
//! destinations, delivery history and health, and recovery of failed
//! deliveries. This service checks project access and validates the request,
//! then hands destinations to [`super::notification_destinations`], recovery
//! to [`super::notification_recovery`], and delivery history and health to
//! the notification domain ([`crate::notification`]).

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::IdentityPrincipal;
use crate::notification::{
    NotificationService,
    health::{NotificationHealthResponse, load_project_snapshot},
    webhook::{parse_url, resolve_target},
    worker::{
        DeliveryDetail, DeliveryFilter, DeliverySummary, delivery_detail, list_deliveries,
        test_destination,
    },
};
use crate::service::notification_destinations::{
    DestinationError, DestinationUpdate, WebhookDestination,
};
use crate::service::notification_recovery::{
    BulkRecoveryResult, BulkRetryFilter, DeliveryRecoveryResult, RecoveryActor, RecoveryError,
    RecoveryOperationDetail, RecoveryOperationFilter, RecoveryOperationSummary,
};
use crate::service::project_access::project_scope;

/// Why a project notification use case failed.
#[derive(Debug, Error)]
pub enum ProjectNotificationError {
    /// The project, destination, delivery or operation does not exist, or
    /// the principal may not see the project.
    #[error("not found")]
    NotFound,
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Destination(#[from] DestinationError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

type Result<T, E = ProjectNotificationError> = std::result::Result<T, E>;

/// A destination to create.
#[derive(Clone, Debug)]
pub struct NewDestination {
    pub name: String,
    pub url: String,
    pub deliver_backfill: bool,
}

/// Changes to a destination, applied only at the given revision.
#[derive(Clone, Debug)]
pub struct DestinationChange {
    pub name: Option<String>,
    pub url: Option<String>,
    pub deliver_backfill: Option<bool>,
    pub enabled: Option<bool>,
    pub revision: i64,
}

/// A destination with its signing secret, which is shown once.
#[derive(Debug, Serialize)]
pub struct DestinationWithSecret {
    #[serde(flatten)]
    destination: WebhookDestination,
    secret: String,
}

#[derive(Debug, Serialize)]
pub struct DeliveryList {
    items: Vec<DeliverySummary>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryOperationList {
    items: Vec<RecoveryOperationSummary>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub struct ProjectNotificationService {
    notifications: NotificationService,
}

impl ProjectNotificationService {
    pub fn new(notifications: NotificationService) -> Self {
        Self { notifications }
    }

    /// The project's webhook destinations.
    pub async fn list_destinations(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<Vec<WebhookDestination>> {
        let organization_id = self.project_organization(principal, project_id).await?;
        Ok(self
            .notifications
            .destinations
            .list(organization_id, project_id)
            .await?)
    }

    /// One webhook destination.
    pub async fn get_destination(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<WebhookDestination> {
        let organization_id = self.project_organization(principal, project_id).await?;
        self.notifications
            .destinations
            .get(organization_id, project_id, destination_id)
            .await?
            .ok_or(ProjectNotificationError::NotFound)
    }

    /// Creates a destination once its URL is a permitted target.
    pub async fn create_destination(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        input: NewDestination,
    ) -> Result<DestinationWithSecret> {
        let organization_id = self.project_organization(principal, project_id).await?;
        self.validate_target(&input.url).await?;
        let (destination, secret) = self
            .notifications
            .destinations
            .create(
                organization_id,
                project_id,
                &input.name,
                &input.url,
                input.deliver_backfill,
            )
            .await?;
        Ok(DestinationWithSecret {
            destination,
            secret: secret.to_string(),
        })
    }

    /// Changes a destination at the revision the caller saw; a new URL must
    /// be a permitted target.
    pub async fn update_destination(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        destination_id: Uuid,
        input: DestinationChange,
    ) -> Result<WebhookDestination> {
        let organization_id = self.project_organization(principal, project_id).await?;
        if let Some(url) = &input.url {
            self.validate_target(url).await?;
        }
        Ok(self
            .notifications
            .destinations
            .update(
                organization_id,
                project_id,
                destination_id,
                DestinationUpdate {
                    name: input.name.as_deref(),
                    url: input.url.as_deref(),
                    deliver_backfill: input.deliver_backfill,
                    enabled: input.enabled,
                    expected_revision: input.revision,
                },
            )
            .await?)
    }

    /// Stops delivering to a destination.
    pub async fn disable_destination(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<WebhookDestination> {
        let organization_id = self.project_organization(principal, project_id).await?;
        Ok(self
            .notifications
            .destinations
            .disable(organization_id, project_id, destination_id)
            .await?)
    }

    /// Replaces a destination's signing secret; the new one is shown once.
    pub async fn rotate_secret(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<DestinationWithSecret> {
        let organization_id = self.project_organization(principal, project_id).await?;
        let (destination, secret) = self
            .notifications
            .destinations
            .rotate_secret(organization_id, project_id, destination_id)
            .await?;
        Ok(DestinationWithSecret {
            destination,
            secret: secret.to_string(),
        })
    }

    /// Sends a test delivery to a destination. Why it failed is logged, not
    /// returned.
    pub async fn test_destination(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<DeliverySummary> {
        let organization_id = self.project_organization(principal, project_id).await?;
        test_destination(
            &self.notifications,
            organization_id,
            project_id,
            destination_id,
        )
        .await
        .map_err(|error| {
            tracing::warn!(error=%error, "test webhook delivery failed");
            ProjectNotificationError::Invalid("test delivery could not be completed".into())
        })
    }

    /// The project's deliveries, filtered.
    pub async fn list_deliveries(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        filter: DeliveryFilter,
    ) -> Result<DeliveryList> {
        let organization_id = self.project_organization(principal, project_id).await?;
        page_limit(filter.limit)?;
        let (items, next_cursor) = list_deliveries(
            &self.notifications.pool,
            organization_id,
            project_id,
            &filter,
        )
        .await?;
        Ok(DeliveryList { items, next_cursor })
    }

    /// How the project's notifications are doing.
    pub async fn health(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<NotificationHealthResponse> {
        let organization_id = self.project_organization(principal, project_id).await?;
        let snapshot =
            load_project_snapshot(&self.notifications.pool, organization_id, project_id).await?;
        Ok(NotificationHealthResponse::from_snapshot(
            self.notifications.config.enabled,
            crate::metrics::notification_worker_is_draining(),
            &snapshot,
        ))
    }

    /// One delivery with its attempts.
    pub async fn get_delivery(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        delivery_id: Uuid,
    ) -> Result<DeliveryDetail> {
        let organization_id = self.project_organization(principal, project_id).await?;
        delivery_detail(
            &self.notifications.pool,
            organization_id,
            project_id,
            delivery_id,
        )
        .await?
        .ok_or(ProjectNotificationError::NotFound)
    }

    /// Retries a failed delivery. The idempotency key is required.
    pub async fn retry_delivery(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        delivery_id: Uuid,
        idempotency_key: Option<&str>,
        request_id: &str,
    ) -> Result<DeliveryRecoveryResult> {
        let organization_id = self.project_organization(principal, project_id).await?;
        let key = required_key(idempotency_key)?;
        Ok(self
            .notifications
            .recovery
            .retry_delivery(
                organization_id,
                project_id,
                delivery_id,
                RecoveryActor {
                    id: principal.user_id,
                    request_id,
                },
                key,
            )
            .await?)
    }

    /// Cancels a pending delivery. The idempotency key is required.
    pub async fn cancel_delivery(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        delivery_id: Uuid,
        idempotency_key: Option<&str>,
        request_id: &str,
    ) -> Result<DeliveryRecoveryResult> {
        let organization_id = self.project_organization(principal, project_id).await?;
        let key = required_key(idempotency_key)?;
        Ok(self
            .notifications
            .recovery
            .cancel_delivery(
                organization_id,
                project_id,
                delivery_id,
                RecoveryActor {
                    id: principal.user_id,
                    request_id,
                },
                key,
            )
            .await?)
    }

    /// Retries every failed delivery the filter selects. The idempotency key
    /// is required.
    pub async fn bulk_retry(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        filter: BulkRetryFilter,
        idempotency_key: Option<&str>,
        request_id: &str,
    ) -> Result<BulkRecoveryResult> {
        let organization_id = self.project_organization(principal, project_id).await?;
        let key = required_key(idempotency_key)?;
        Ok(self
            .notifications
            .recovery
            .bulk_retry(
                organization_id,
                project_id,
                &filter,
                RecoveryActor {
                    id: principal.user_id,
                    request_id,
                },
                key,
            )
            .await?)
    }

    /// The project's recovery operations, filtered.
    pub async fn list_recovery_operations(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        filter: RecoveryOperationFilter,
    ) -> Result<RecoveryOperationList> {
        let organization_id = self.project_organization(principal, project_id).await?;
        page_limit(filter.limit)?;
        let (items, next_cursor) = self
            .notifications
            .recovery
            .list_operations(organization_id, project_id, &filter)
            .await?;
        Ok(RecoveryOperationList { items, next_cursor })
    }

    /// One recovery operation.
    pub async fn get_recovery_operation(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<RecoveryOperationDetail> {
        let organization_id = self.project_organization(principal, project_id).await?;
        self.notifications
            .recovery
            .operation_detail(organization_id, project_id, operation_id)
            .await?
            .ok_or(ProjectNotificationError::NotFound)
    }

    /// Resolves the project's organization and checks the principal may see
    /// the project; a project they cannot see does not exist for them.
    async fn project_organization(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<Uuid> {
        let scope = project_scope(&self.notifications.pool, principal, project_id)
            .await?
            .ok_or(ProjectNotificationError::NotFound)?;
        Ok(scope.organization_id)
    }

    /// A destination URL must parse under the webhook policy and resolve to
    /// a permitted address.
    async fn validate_target(&self, value: &str) -> Result<()> {
        let policy = &self.notifications.policy;
        let url = parse_url(value, policy)
            .map_err(|error| ProjectNotificationError::Invalid(error.to_string()))?;
        resolve_target(&url, policy)
            .await
            .map_err(|error| ProjectNotificationError::Invalid(error.to_string()))?;
        Ok(())
    }
}

/// A page of deliveries or recovery operations holds 1 to 200 items.
fn page_limit(limit: Option<i64>) -> Result<()> {
    if limit.is_some_and(|limit| !(1..=200).contains(&limit)) {
        return Err(ProjectNotificationError::Invalid(
            "limit must be between 1 and 200".into(),
        ));
    }
    Ok(())
}

fn required_key(value: Option<&str>) -> Result<&str> {
    value.ok_or_else(|| {
        ProjectNotificationError::Invalid("missing or invalid Idempotency-Key header".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::OrganizationRole;
    use crate::notification_config::NotificationArgs;
    use crate::repository::test_support::{Tenant, tenant};

    fn service(pool: sqlx::PgPool) -> ProjectNotificationService {
        let args = NotificationArgs {
            enabled: true,
            encryption_key: Some(hex::encode([9_u8; 32])),
            allow_http: true,
            allow_private_ips: true,
            ..NotificationArgs::default()
        };
        ProjectNotificationService::new(
            NotificationService::new(pool, args.build(true).unwrap()).unwrap(),
        )
    }

    fn owner(tenant: &Tenant) -> IdentityPrincipal {
        IdentityPrincipal {
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            active_organization_id: Some(tenant.organization_id),
            organization_role: Some(OrganizationRole::Owner),
            is_super_admin: false,
            privileged_until: None,
        }
    }

    fn destination(url: &str) -> NewDestination {
        NewDestination {
            name: "Alerts".into(),
            url: url.into(),
            deliver_backfill: false,
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn destinations_need_project_access_and_a_permitted_target(pool: sqlx::PgPool) {
        let other = tenant(&pool, "notifications-service-other").await;
        let tenant = tenant(&pool, "notifications-service").await;
        let service = service(pool.clone());
        let principal = owner(&tenant);
        let project = tenant.project_id;

        // Access is checked before the target.
        assert!(matches!(
            service
                .create_destination(owner(&other), project, destination("ftp://x"))
                .await,
            Err(ProjectNotificationError::NotFound)
        ));
        assert!(matches!(
            service
                .create_destination(principal, project, destination("ftp://x"))
                .await,
            Err(ProjectNotificationError::Invalid(_))
        ));
        let created = service
            .create_destination(principal, project, destination("http://127.0.0.1:9/hook"))
            .await
            .unwrap();
        assert!(!created.secret.is_empty());
        let id = created.destination.id;
        assert_eq!(
            service
                .list_destinations(principal, project)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            service
                .update_destination(
                    principal,
                    project,
                    id,
                    DestinationChange {
                        name: Some("Renamed".into()),
                        url: None,
                        deliver_backfill: None,
                        enabled: None,
                        revision: created.destination.revision + 1,
                    },
                )
                .await,
            Err(ProjectNotificationError::Destination(
                DestinationError::RevisionConflict
            ))
        ));
        let disabled = service
            .disable_destination(principal, project, id)
            .await
            .unwrap();
        assert!(!disabled.enabled);
        let rotated = service.rotate_secret(principal, project, id).await.unwrap();
        assert_ne!(rotated.secret, created.secret);
        assert!(matches!(
            service
                .get_destination(principal, project, Uuid::new_v4())
                .await,
            Err(ProjectNotificationError::NotFound)
        ));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn recovery_requires_an_idempotency_key_after_access(pool: sqlx::PgPool) {
        let other = tenant(&pool, "notifications-recovery-other").await;
        let tenant = tenant(&pool, "notifications-recovery").await;
        let service = service(pool.clone());
        let project = tenant.project_id;

        assert!(matches!(
            service
                .retry_delivery(owner(&other), project, Uuid::new_v4(), None, "r")
                .await,
            Err(ProjectNotificationError::NotFound)
        ));
        assert!(matches!(
            service
                .retry_delivery(owner(&tenant), project, Uuid::new_v4(), None, "r")
                .await,
            Err(ProjectNotificationError::Invalid(message))
                if message == "missing or invalid Idempotency-Key header"
        ));
        assert!(matches!(
            service
                .get_delivery(owner(&tenant), project, Uuid::new_v4())
                .await,
            Err(ProjectNotificationError::NotFound)
        ));
        service.health(owner(&tenant), project).await.unwrap();
    }
}
