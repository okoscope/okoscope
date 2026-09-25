//! Recovery of failed webhook deliveries: retrying or cancelling one
//! delivery, retrying a filtered batch, and the audit of those operations.
//! Every command is idempotent under its key: a repeated key with the same
//! request replays the recorded result, and with a different request it is a
//! conflict. Project access is checked by the caller, [`super::notifications`].

use crate::repository::notification_deliveries::NotificationDeliveryRepository;
use crate::repository::notification_recovery::NotificationRecoveryRepository;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 200;
pub const MIN_IDEMPOTENCY_KEY_BYTES: usize = 8;
pub const DEFAULT_BULK_LIMIT: i64 = 50;
pub const MAX_BULK_LIMIT: i64 = 200;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCommandType {
    Retry,
    Cancel,
    BulkRetry,
}

impl RecoveryCommandType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::Cancel => "cancel",
            Self::BulkRetry => "bulk_retry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryConflictCode {
    InvalidState,
    ActiveLease,
    DestinationDisabled,
    IdempotencyKeyReused,
    BulkLimitExceeded,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeliveryRecoveryEligibility {
    pub retry_allowed: bool,
    pub cancel_allowed: bool,
    pub conflict: Option<RecoveryConflictCode>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeliveryRecoveryResult {
    pub operation_id: Uuid,
    pub delivery_id: Uuid,
    pub status: String,
    pub recovery_generation: i32,
    pub current_attempt_count: i32,
    pub total_attempt_count: i64,
    pub replayed: bool,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BulkRetryFilter {
    pub destination_id: Option<Uuid>,
    pub failed_before: Option<DateTime<Utc>>,
    pub failed_after: Option<DateTime<Utc>>,
    pub error_class: Option<String>,
    pub limit: Option<i64>,
}

impl BulkRetryFilter {
    pub fn bounded_limit(&self) -> Result<i64, RecoveryError> {
        let limit = self.limit.unwrap_or(DEFAULT_BULK_LIMIT);
        if (1..=MAX_BULK_LIMIT).contains(&limit) {
            Ok(limit)
        } else {
            Err(RecoveryError::Conflict(
                RecoveryConflictCode::BulkLimitExceeded,
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BulkRecoveryResult {
    pub operation_id: Uuid,
    pub selected_count: i32,
    pub retried_count: i32,
    pub skipped_count: i32,
    pub remaining_count: i32,
    pub has_more: bool,
    pub replayed: bool,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct RecoveryOperationSummary {
    pub id: Uuid,
    pub project_id: Uuid,
    pub command_type: String,
    pub target_delivery_id: Option<Uuid>,
    pub actor_kind: String,
    pub actor_id: Uuid,
    pub request_id: String,
    pub outcome: String,
    pub selected_count: i32,
    pub retried_count: i32,
    pub cancelled_count: i32,
    pub skipped_count: i32,
    pub remaining_count: i32,
    pub created_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryOperationDetail {
    #[serde(flatten)]
    pub operation: RecoveryOperationSummary,
    pub affected_deliveries: Vec<RecoveryOperationDelivery>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct RecoveryOperationDelivery {
    pub delivery_id: Uuid,
    pub recovery_generation: i32,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RecoveryOperationFilter {
    pub command_type: Option<String>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryActor<'a> {
    pub id: Uuid,
    pub request_id: &'a str,
}

#[derive(Debug, FromRow)]
struct ExistingCommand {
    request_fingerprint: Vec<u8>,
    result: serde_json::Value,
}

#[derive(Debug, FromRow)]
struct LockedDelivery {
    status: String,
    destination_enabled: bool,
    lease_expires_at: Option<DateTime<Utc>>,
    recovery_generation: i32,
    attempt_count: i32,
    total_attempt_count: i64,
}

#[derive(Clone, Debug)]
pub struct RecoveryService {
    pool: PgPool,
    hash_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("delivery or recovery operation was not found")]
    NotFound,
    #[error("recovery command conflicts with current state: {0:?}")]
    Conflict(RecoveryConflictCode),
    #[error("idempotency key must contain 8 to 200 visible ASCII characters")]
    InvalidIdempotencyKey,
    #[error("recovery request could not be serialized: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl RecoveryService {
    #[must_use]
    pub fn new(pool: PgPool, hash_key: [u8; 32]) -> Self {
        Self { pool, hash_key }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn idempotency_hash(&self, key: &str) -> Result<[u8; 32], RecoveryError> {
        validate_idempotency_key(key)?;
        let mut mac = HmacSha256::new_from_slice(&self.hash_key)
            .expect("HMAC accepts a 32-byte recovery key");
        mac.update(b"okoscope.notification-recovery.idempotency.v1\0");
        mac.update(key.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    pub async fn retry_delivery(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        actor: RecoveryActor<'_>,
        idempotency_key: &str,
    ) -> Result<DeliveryRecoveryResult, RecoveryError> {
        let key_hash = self.idempotency_hash(idempotency_key)?;
        let fingerprint =
            request_fingerprint(&(RecoveryCommandType::Retry, project_id, delivery_id))?;
        let mut tx = self.pool.begin().await?;
        if let Some(result) = replay::<DeliveryRecoveryResult>(
            &mut tx,
            organization_id,
            project_id,
            &key_hash,
            &fingerprint,
        )
        .await?
        {
            return Ok(result);
        }
        let delivery = lock_delivery(&mut tx, organization_id, project_id, delivery_id).await?;
        ensure_retry_eligible(&delivery)?;
        let operation_id = Uuid::new_v4();
        let completed_at = Utc::now();
        let generation = delivery.recovery_generation.saturating_add(1);
        let changed = NotificationDeliveryRepository::requeue_failed(
            &mut *tx,
            organization_id,
            project_id,
            delivery_id,
            generation,
            operation_id,
        )
        .await?;
        if changed.rows_affected() != 1 {
            return Err(RecoveryError::Conflict(RecoveryConflictCode::InvalidState));
        }
        let result = DeliveryRecoveryResult {
            operation_id,
            delivery_id,
            status: "pending".into(),
            recovery_generation: generation,
            current_attempt_count: 0,
            total_attempt_count: delivery.total_attempt_count,
            replayed: false,
            completed_at,
        };
        insert_operation(
            &mut tx,
            OperationInsert {
                id: operation_id,
                organization_id,
                project_id,
                command: RecoveryCommandType::Retry,
                target_delivery_id: Some(delivery_id),
                actor,
                key_hash: &key_hash,
                fingerprint: &fingerprint,
                safe_filters: serde_json::json!({}),
                selected: 1,
                retried: 1,
                cancelled: 0,
                skipped: 0,
                remaining: 0,
                result: &result,
                completed_at,
            },
        )
        .await?;
        link_delivery(
            &mut tx,
            operation_id,
            organization_id,
            project_id,
            delivery_id,
            generation,
            "retried",
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn cancel_delivery(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        delivery_id: Uuid,
        actor: RecoveryActor<'_>,
        idempotency_key: &str,
    ) -> Result<DeliveryRecoveryResult, RecoveryError> {
        let key_hash = self.idempotency_hash(idempotency_key)?;
        let fingerprint =
            request_fingerprint(&(RecoveryCommandType::Cancel, project_id, delivery_id))?;
        let mut tx = self.pool.begin().await?;
        if let Some(result) = replay::<DeliveryRecoveryResult>(
            &mut tx,
            organization_id,
            project_id,
            &key_hash,
            &fingerprint,
        )
        .await?
        {
            return Ok(result);
        }
        let delivery = lock_delivery(&mut tx, organization_id, project_id, delivery_id).await?;
        ensure_cancel_eligible(&delivery)?;
        let operation_id = Uuid::new_v4();
        let completed_at = Utc::now();
        let changed = NotificationDeliveryRepository::cancel_pending(
            &mut *tx,
            organization_id,
            project_id,
            delivery_id,
            operation_id,
        )
        .await?;
        if changed.rows_affected() != 1 {
            return Err(RecoveryError::Conflict(RecoveryConflictCode::ActiveLease));
        }
        let result = DeliveryRecoveryResult {
            operation_id,
            delivery_id,
            status: "cancelled".into(),
            recovery_generation: delivery.recovery_generation,
            current_attempt_count: delivery.attempt_count,
            total_attempt_count: delivery.total_attempt_count,
            replayed: false,
            completed_at,
        };
        insert_operation(
            &mut tx,
            OperationInsert {
                id: operation_id,
                organization_id,
                project_id,
                command: RecoveryCommandType::Cancel,
                target_delivery_id: Some(delivery_id),
                actor,
                key_hash: &key_hash,
                fingerprint: &fingerprint,
                safe_filters: serde_json::json!({}),
                selected: 1,
                retried: 0,
                cancelled: 1,
                skipped: 0,
                remaining: 0,
                result: &result,
                completed_at,
            },
        )
        .await?;
        link_delivery(
            &mut tx,
            operation_id,
            organization_id,
            project_id,
            delivery_id,
            delivery.recovery_generation,
            "cancelled",
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn bulk_retry(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        filter: &BulkRetryFilter,
        actor: RecoveryActor<'_>,
        idempotency_key: &str,
    ) -> Result<BulkRecoveryResult, RecoveryError> {
        let limit = validate_bulk_filter(filter)?;
        let key_hash = self.idempotency_hash(idempotency_key)?;
        let fingerprint =
            request_fingerprint(&(RecoveryCommandType::BulkRetry, project_id, filter))?;
        let mut tx = self.pool.begin().await?;
        if let Some(result) = replay::<BulkRecoveryResult>(
            &mut tx,
            organization_id,
            project_id,
            &key_hash,
            &fingerprint,
        )
        .await?
        {
            return Ok(result);
        }
        let mut candidates = NotificationDeliveryRepository::failed_for_retry(
            &mut *tx,
            organization_id,
            project_id,
            filter.destination_id,
            filter.failed_before,
            filter.failed_after,
            filter.error_class.as_deref(),
            limit + 1,
        )
        .await?;
        let saw_more = i64::try_from(candidates.len()).unwrap_or(i64::MAX) > limit;
        if saw_more {
            candidates.pop();
        }
        let operation_id = Uuid::new_v4();
        let completed_at = Utc::now();
        let mut changed = Vec::with_capacity(candidates.len());
        for (delivery_id, previous_generation) in candidates {
            let generation = previous_generation.saturating_add(1);
            let updated = NotificationDeliveryRepository::requeue_failed(
                &mut *tx,
                organization_id,
                project_id,
                delivery_id,
                generation,
                operation_id,
            )
            .await?;
            if updated.rows_affected() == 1 {
                changed.push((delivery_id, generation));
            }
        }
        let remaining = NotificationDeliveryRepository::count_failed_for_retry(
            &mut *tx,
            organization_id,
            project_id,
            filter.destination_id,
            filter.failed_before,
            filter.failed_after,
            filter.error_class.as_deref(),
        )
        .await?;
        let retried = i32::try_from(changed.len()).unwrap_or(i32::MAX);
        let selected = retried;
        let remaining = i32::try_from(remaining).unwrap_or(i32::MAX);
        let result = BulkRecoveryResult {
            operation_id,
            selected_count: selected,
            retried_count: retried,
            skipped_count: 0,
            remaining_count: remaining,
            has_more: saw_more || remaining > 0,
            replayed: false,
            completed_at,
        };
        insert_operation(
            &mut tx,
            OperationInsert {
                id: operation_id,
                organization_id,
                project_id,
                command: RecoveryCommandType::BulkRetry,
                target_delivery_id: None,
                actor,
                key_hash: &key_hash,
                fingerprint: &fingerprint,
                safe_filters: serde_json::to_value(filter)?,
                selected,
                retried,
                cancelled: 0,
                skipped: 0,
                remaining,
                result: &result,
                completed_at,
            },
        )
        .await?;
        for (delivery_id, generation) in changed {
            link_delivery(
                &mut tx,
                operation_id,
                organization_id,
                project_id,
                delivery_id,
                generation,
                "retried",
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result)
    }

    pub async fn list_operations(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        filter: &RecoveryOperationFilter,
    ) -> Result<(Vec<RecoveryOperationSummary>, Option<Uuid>), RecoveryError> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 200);
        let cursor = if let Some(cursor) = filter.cursor {
            NotificationRecoveryRepository::cursor(&self.pool, organization_id, project_id, cursor)
                .await?
        } else {
            None
        };
        let (cursor_time, cursor_id) = cursor.unzip();
        let mut rows = NotificationRecoveryRepository::page::<_, RecoveryOperationSummary>(
            &self.pool,
            organization_id,
            project_id,
            filter.command_type.as_deref(),
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
            rows.pop();
            rows.last().map(|row| row.id)
        } else {
            None
        };
        Ok((rows, next_cursor))
    }

    pub async fn operation_detail(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<RecoveryOperationDetail>, RecoveryError> {
        let operation = NotificationRecoveryRepository::get::<_, RecoveryOperationSummary>(
            &self.pool,
            organization_id,
            project_id,
            operation_id,
        )
        .await?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        let affected_deliveries = NotificationRecoveryRepository::deliveries::<
            _,
            RecoveryOperationDelivery,
        >(&self.pool, organization_id, project_id, operation_id)
        .await?;
        Ok(Some(RecoveryOperationDetail {
            operation,
            affected_deliveries,
        }))
    }
}

async fn lock_delivery(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    delivery_id: Uuid,
) -> Result<LockedDelivery, RecoveryError> {
    NotificationDeliveryRepository::lock_for_recovery::<_, LockedDelivery>(
        &mut **tx,
        organization_id,
        project_id,
        delivery_id,
    )
    .await?
    .ok_or(RecoveryError::NotFound)
}

fn ensure_retry_eligible(delivery: &LockedDelivery) -> Result<(), RecoveryError> {
    if delivery.status == "in_flight"
        && delivery
            .lease_expires_at
            .is_some_and(|lease| lease > Utc::now())
    {
        return Err(RecoveryError::Conflict(RecoveryConflictCode::ActiveLease));
    }
    if !delivery.destination_enabled {
        return Err(RecoveryError::Conflict(
            RecoveryConflictCode::DestinationDisabled,
        ));
    }
    if delivery.status != "failed" {
        return Err(RecoveryError::Conflict(RecoveryConflictCode::InvalidState));
    }
    Ok(())
}

fn ensure_cancel_eligible(delivery: &LockedDelivery) -> Result<(), RecoveryError> {
    if delivery.status == "in_flight"
        || delivery
            .lease_expires_at
            .is_some_and(|lease| lease > Utc::now())
    {
        return Err(RecoveryError::Conflict(RecoveryConflictCode::ActiveLease));
    }
    if delivery.status != "pending" {
        return Err(RecoveryError::Conflict(RecoveryConflictCode::InvalidState));
    }
    Ok(())
}

fn validate_bulk_filter(filter: &BulkRetryFilter) -> Result<i64, RecoveryError> {
    if filter
        .error_class
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 100)
    {
        return Err(RecoveryError::Conflict(RecoveryConflictCode::InvalidState));
    }
    filter.bounded_limit()
}

async fn replay<T: DeserializeOwned + Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    key_hash: &[u8; 32],
    fingerprint: &[u8; 32],
) -> Result<Option<T>, RecoveryError> {
    let existing = NotificationRecoveryRepository::by_idempotency_key_for_update::<
        _,
        ExistingCommand,
    >(&mut **tx, organization_id, project_id, key_hash.as_slice())
    .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.request_fingerprint.as_slice() != fingerprint {
        return Err(RecoveryError::Conflict(
            RecoveryConflictCode::IdempotencyKeyReused,
        ));
    }
    let mut value: serde_json::Value = existing.result;
    if let Some(object) = value.as_object_mut() {
        object.insert("replayed".into(), serde_json::Value::Bool(true));
    }
    Ok(Some(serde_json::from_value(value)?))
}

struct OperationInsert<'a, T> {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    command: RecoveryCommandType,
    target_delivery_id: Option<Uuid>,
    actor: RecoveryActor<'a>,
    key_hash: &'a [u8; 32],
    fingerprint: &'a [u8; 32],
    safe_filters: serde_json::Value,
    selected: i32,
    retried: i32,
    cancelled: i32,
    skipped: i32,
    remaining: i32,
    result: &'a T,
    completed_at: DateTime<Utc>,
}

async fn insert_operation<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    input: OperationInsert<'_, T>,
) -> Result<(), RecoveryError> {
    NotificationRecoveryRepository::insert(
        &mut **tx,
        input.id,
        input.organization_id,
        input.project_id,
        input.command.as_str(),
        input.target_delivery_id,
        input.actor.id,
        input.actor.request_id,
        input.key_hash.as_slice(),
        input.fingerprint.as_slice(),
        input.safe_filters,
        input.selected,
        input.retried,
        input.cancelled,
        input.skipped,
        input.remaining,
        serde_json::to_value(input.result)?,
        input.completed_at,
    )
    .await?;
    Ok(())
}

async fn link_delivery(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    delivery_id: Uuid,
    recovery_generation: i32,
    action: &str,
) -> Result<(), RecoveryError> {
    NotificationRecoveryRepository::link_delivery(
        &mut **tx,
        operation_id,
        organization_id,
        project_id,
        delivery_id,
        recovery_generation,
        action,
    )
    .await?;
    Ok(())
}

pub fn request_fingerprint<T: Serialize>(request: &T) -> Result<[u8; 32], RecoveryError> {
    let encoded = serde_json::to_vec(request)?;
    Ok(Sha256::digest(encoded).into())
}

fn validate_idempotency_key(key: &str) -> Result<(), RecoveryError> {
    if (MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&key.len())
        && key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        Ok(())
    } else {
        Err(RecoveryError::InvalidIdempotencyKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_keys_without_exposing_them() {
        let repository =
            RecoveryService::new(PgPool::connect_lazy("postgres://unused").unwrap(), [7; 32]);
        let first = repository.idempotency_hash("retry-command-1").unwrap();
        assert_eq!(
            first,
            repository.idempotency_hash("retry-command-1").unwrap()
        );
        assert_ne!(
            first,
            repository.idempotency_hash("retry-command-2").unwrap()
        );
        assert!(!hex::encode(first).contains("retry-command"));
    }

    #[test]
    fn rejects_unsafe_idempotency_keys_and_bulk_limits() {
        assert!(matches!(
            validate_idempotency_key("short"),
            Err(RecoveryError::InvalidIdempotencyKey)
        ));
        assert!(matches!(
            validate_idempotency_key("contains space"),
            Err(RecoveryError::InvalidIdempotencyKey)
        ));
        assert_eq!(BulkRetryFilter::default().bounded_limit().unwrap(), 50);
        assert!(
            BulkRetryFilter {
                limit: Some(201),
                ..BulkRetryFilter::default()
            }
            .bounded_limit()
            .is_err()
        );
    }

    #[test]
    fn fingerprints_are_canonical_for_typed_requests() {
        let request = BulkRetryFilter {
            destination_id: Some(Uuid::nil()),
            error_class: Some("timeout".into()),
            limit: Some(10),
            ..BulkRetryFilter::default()
        };
        assert_eq!(
            request_fingerprint(&request).unwrap(),
            request_fingerprint(&request).unwrap()
        );
    }
}
