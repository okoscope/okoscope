use crate::repository::event_groups::EventGroupRepository;
use crate::repository::notification_deliveries::NotificationDeliveryRepository;
use crate::repository::outbox::OutboxRepository;
use crate::repository::webhook_destinations::WebhookDestinationRepository;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use tokio::sync::watch;
use uuid::Uuid;

use super::{
    NotificationService,
    crypto::SecretVaultError,
    webhook::{WebhookEnvelope, WebhookError, WebhookResponse, send},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaterializeStats {
    pub outbox_messages: u64,
    pub deliveries: u64,
    pub suppressed: u64,
    pub no_destinations: u64,
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stored notification payload is invalid: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("stored webhook secret is invalid: {0}")]
    Secret(#[from] SecretVaultError),
}

#[derive(Debug, FromRow)]
struct OutboxRow {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    aggregate_id: Uuid,
    source: String,
    payload: Value,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct PolicyEligibility {
    reason: String,
    evaluated_at: DateTime<Utc>,
    policy_revision_id: Option<Uuid>,
    policy_suppression_id: Option<Uuid>,
}

#[derive(Debug, FromRow)]
struct DestinationSnapshot {
    id: Uuid,
    deliver_backfill: bool,
}

#[derive(Clone, Debug, FromRow)]
pub struct DeliveryClaim {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub destination_id: Uuid,
    pub outbox_message_id: Option<Uuid>,
    pub source: String,
    pub event_name: String,
    pub payload: Value,
    pub recovery_generation: i32,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub lease_owner: Uuid,
    pub url: String,
    pub encrypted_secret: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeliveryFilter {
    pub destination_id: Option<Uuid>,
    pub status: Option<String>,
    pub source: Option<String>,
    pub origin: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliverySummary {
    pub id: Uuid,
    pub project_id: Uuid,
    pub destination_id: Uuid,
    pub outbox_message_id: Option<Uuid>,
    pub origin: String,
    pub source: String,
    pub event_name: String,
    pub semantic_metadata: Option<DeliverySemanticMetadata>,
    pub destination: SafeDestination,
    pub status: String,
    pub available_at: DateTime<Utc>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub recovery_generation: i32,
    pub attempt_count: i32,
    pub total_attempt_count: i64,
    pub max_attempts: i32,
    pub last_error_class: Option<String>,
    pub terminal_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub terminal_at: Option<DateTime<Utc>>,
    pub retry_allowed: bool,
    pub cancel_allowed: bool,
    pub last_recovery_operation_id: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct SafeDestination {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliverySemanticMetadata {
    pub application_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub event_kind: Option<String>,
    pub user_labels: Vec<Value>,
}

#[derive(Clone, Debug, FromRow)]
struct DeliverySummaryRow {
    id: Uuid,
    project_id: Uuid,
    destination_id: Uuid,
    outbox_message_id: Option<Uuid>,
    origin: String,
    source: String,
    event_name: String,
    payload: Value,
    destination_name: String,
    destination_enabled: bool,
    status: String,
    available_at: DateTime<Utc>,
    recovery_generation: i32,
    attempt_count: i32,
    total_attempt_count: i64,
    max_attempts: i32,
    last_error_class: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    terminal_at: Option<DateTime<Utc>>,
    last_recovery_operation_id: Option<Uuid>,
}

impl From<DeliverySummaryRow> for DeliverySummary {
    fn from(row: DeliverySummaryRow) -> Self {
        let next_attempt_at = (row.status == "pending").then_some(row.available_at);
        let terminal_reason = row.terminal_at.map(|_| {
            row.last_error_class
                .clone()
                .unwrap_or_else(|| match row.status.as_str() {
                    "succeeded" => "delivered".to_owned(),
                    "suppressed" => "suppressed".to_owned(),
                    "cancelled" => "cancelled".to_owned(),
                    _ => "terminal".to_owned(),
                })
        });
        let semantic_metadata = delivery_semantic_metadata(&row.payload);
        let retry_allowed = row.status == "failed" && row.destination_enabled;
        let cancel_allowed = row.status == "pending";
        Self {
            id: row.id,
            project_id: row.project_id,
            destination_id: row.destination_id,
            outbox_message_id: row.outbox_message_id,
            origin: row.origin,
            source: row.source,
            event_name: row.event_name,
            semantic_metadata,
            destination: SafeDestination {
                id: row.destination_id,
                name: row.destination_name,
                enabled: row.destination_enabled,
            },
            status: row.status,
            available_at: row.available_at,
            next_attempt_at,
            recovery_generation: row.recovery_generation,
            attempt_count: row.attempt_count,
            total_attempt_count: row.total_attempt_count,
            max_attempts: row.max_attempts,
            last_error_class: row.last_error_class,
            terminal_reason,
            created_at: row.created_at,
            updated_at: row.updated_at,
            terminal_at: row.terminal_at,
            retry_allowed,
            cancel_allowed,
            last_recovery_operation_id: row.last_recovery_operation_id,
        }
    }
}

fn delivery_semantic_metadata(payload: &Value) -> Option<DeliverySemanticMetadata> {
    let metadata = DeliverySemanticMetadata {
        application_id: uuid_field(payload, "application_id"),
        group_id: uuid_field(payload, "group_id"),
        event_kind: payload
            .get("event_kind")
            .and_then(Value::as_str)
            .map(str::to_owned),
        user_labels: payload
            .get("user_labels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    (metadata.application_id.is_some()
        || metadata.group_id.is_some()
        || metadata.event_kind.is_some())
    .then_some(metadata)
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct DeliveryAttempt {
    pub id: Uuid,
    pub recovery_generation: i32,
    pub attempt_number: i32,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub outcome: String,
    pub http_status: Option<i32>,
    pub error_class: Option<String>,
    pub response_excerpt: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeliveryDetail {
    #[serde(flatten)]
    pub delivery: DeliverySummary,
    pub attempts: Vec<DeliveryAttempt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptDisposition {
    Succeeded,
    Retryable,
    Failed,
}

#[derive(Debug)]
struct AttemptResult {
    disposition: AttemptDisposition,
    http_status: Option<u16>,
    error_class: Option<&'static str>,
    response_excerpt: Option<String>,
    retry_after: Option<Duration>,
    duration: Duration,
}

pub async fn materialize_once(
    service: &NotificationService,
) -> Result<MaterializeStats, WorkerError> {
    let mut tx = service.pool.begin().await?;
    let rows = OutboxRepository::claim_first_seen::<_, OutboxRow>(
        &mut *tx,
        i64::from(service.config.claim_size),
    )
    .await?;
    let mut stats = MaterializeStats::default();
    for row in rows {
        stats.outbox_messages = stats.outbox_messages.saturating_add(1);
        materialize_message(&mut tx, service, &row, &mut stats).await?;
    }
    tx.commit().await?;
    crate::metrics::record_notification_materialization(
        stats.deliveries,
        stats.suppressed,
        stats.no_destinations,
    );
    Ok(stats)
}

async fn materialize_message(
    tx: &mut Transaction<'_, Postgres>,
    service: &NotificationService,
    outbox: &OutboxRow,
    stats: &mut MaterializeStats,
) -> Result<(), WorkerError> {
    let eligibility: PolicyEligibility = EventGroupRepository::notification_eligibility(
        &mut **tx,
        outbox.organization_id,
        outbox.aggregate_id,
        crate::policy::POLICY_EVALUATOR_VERSION,
    )
    .await?;
    OutboxRepository::record_eligibility(
        &mut **tx,
        outbox.id,
        &eligibility.reason,
        eligibility.evaluated_at,
        eligibility.policy_revision_id,
        eligibility.policy_suppression_id,
    )
    .await?;
    if matches!(
        eligibility.reason.as_str(),
        "expected" | "active_suppression"
    ) {
        stats.suppressed = stats.suppressed.saturating_add(1);
        OutboxRepository::complete(&mut **tx, outbox.id, &eligibility.reason).await?;
        return Ok(());
    }
    let destinations = WebhookDestinationRepository::enabled_for_project::<_, DestinationSnapshot>(
        &mut **tx,
        outbox.organization_id,
        outbox.project_id,
    )
    .await?;
    let user_labels: Value = EventGroupRepository::user_labels_json(
        &mut **tx,
        outbox.organization_id,
        outbox.aggregate_id,
    )
    .await?;
    if destinations.is_empty() {
        stats.no_destinations = stats.no_destinations.saturating_add(1);
        OutboxRepository::complete_without_destinations(&mut **tx, outbox.id).await?;
        return Ok(());
    }
    let mut pending = 0_u64;
    for destination in destinations {
        let suppressed = outbox.source == "backfill" && !destination.deliver_backfill;
        let delivery_id = Uuid::new_v4();
        let envelope = envelope(outbox, delivery_id, &user_labels);
        let delivery_status = if suppressed { "suppressed" } else { "pending" };
        let terminal_at = suppressed.then(Utc::now);
        let inserted = NotificationDeliveryRepository::insert_for_outbox(
            &mut **tx,
            delivery_id,
            outbox.organization_id,
            outbox.project_id,
            destination.id,
            outbox.id,
            &outbox.source,
            serde_json::to_value(envelope)?,
            delivery_status,
            i32::try_from(service.config.max_attempts).unwrap_or(i32::MAX),
            terminal_at,
            suppressed.then_some("backfill_suppressed"),
            suppressed.then_some("historical delivery is disabled"),
        )
        .await?;
        if inserted.rows_affected() == 1 {
            stats.deliveries = stats.deliveries.saturating_add(1);
            if suppressed {
                stats.suppressed = stats.suppressed.saturating_add(1);
            } else {
                pending = pending.saturating_add(1);
            }
        }
    }
    if pending == 0 {
        OutboxRepository::complete_backfill_suppressed(&mut **tx, outbox.id).await?;
    } else {
        OutboxRepository::mark_materialized(&mut **tx, outbox.id).await?;
    }
    Ok(())
}

fn envelope(outbox: &OutboxRow, delivery_id: Uuid, user_labels: &Value) -> WebhookEnvelope {
    let value = &outbox.payload;
    WebhookEnvelope {
        schema_version: 1,
        delivery_id,
        event: "runtime_group.first_seen".into(),
        created_at: outbox.created_at,
        source: outbox.source.clone(),
        organization_id: outbox.organization_id,
        project_id: outbox.project_id,
        application_id: uuid_field(value, "application_id"),
        group_id: uuid_field(value, "group_id"),
        event_kind: value
            .get("event_kind")
            .and_then(Value::as_str)
            .map(str::to_owned),
        semantic_summary: value.get("semantic").cloned(),
        user_labels: user_labels.as_array().cloned().unwrap_or_default(),
    }
}

fn uuid_field(value: &Value, name: &str) -> Option<Uuid> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}

pub async fn claim_due(service: &NotificationService) -> Result<Vec<DeliveryClaim>, sqlx::Error> {
    let lease_owner = Uuid::new_v4();
    let lease_seconds = i64::try_from(service.config.lease_duration.as_secs()).unwrap_or(i64::MAX);
    let claims = NotificationDeliveryRepository::claim_due::<_, DeliveryClaim>(
        &service.pool,
        i64::from(service.config.claim_size),
        lease_owner,
        lease_seconds,
    )
    .await?;
    crate::metrics::record_notification_claims(claims.len());
    Ok(claims)
}

pub async fn process_claim(
    service: &NotificationService,
    claim: DeliveryClaim,
) -> Result<(), WorkerError> {
    let started_at = Utc::now();
    let started = Instant::now();
    let result = match service
        .vault
        .decrypt(&claim.encrypted_secret, &claim.secret_nonce)
    {
        Ok(secret) => match serde_json::from_value::<WebhookEnvelope>(claim.payload.clone()) {
            Ok(envelope) => classify(
                send(&claim.url, &service.policy, &secret, &envelope).await,
                started.elapsed(),
            ),
            Err(_) => AttemptResult::failed("invalid_payload", started.elapsed()),
        },
        Err(_) => AttemptResult::failed("secret_decryption", started.elapsed()),
    };
    persist_attempt(service, &claim, started_at, result).await
}

pub async fn test_destination(
    service: &NotificationService,
    organization_id: Uuid,
    project_id: Uuid,
    destination_id: Uuid,
) -> Result<DeliverySummary, WorkerError> {
    let target = service
        .destinations
        .target(organization_id, project_id, destination_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    if !target.enabled {
        return Err(WorkerError::Database(sqlx::Error::Protocol(
            "destination is disabled".into(),
        )));
    }
    let delivery_id = Uuid::new_v4();
    let lease_owner = Uuid::new_v4();
    let payload = serde_json::to_value(WebhookEnvelope {
        schema_version: 1,
        delivery_id,
        event: "okoscope.test".into(),
        created_at: Utc::now(),
        source: "test".into(),
        organization_id,
        project_id,
        application_id: None,
        group_id: None,
        event_kind: None,
        semantic_summary: None,
        user_labels: Vec::new(),
    })?;
    NotificationDeliveryRepository::insert_test(
        &service.pool,
        delivery_id,
        organization_id,
        project_id,
        destination_id,
        &payload,
        lease_owner,
        i64::try_from(service.config.lease_duration.as_secs()).unwrap_or(i64::MAX),
    )
    .await?;
    process_claim(
        service,
        DeliveryClaim {
            id: delivery_id,
            organization_id,
            project_id,
            destination_id,
            outbox_message_id: None,
            source: "test".into(),
            event_name: "okoscope.test".into(),
            payload,
            recovery_generation: 0,
            attempt_count: 0,
            max_attempts: 1,
            lease_owner,
            url: target.url,
            encrypted_secret: target.encrypted_secret,
            secret_nonce: target.secret_nonce,
        },
    )
    .await?;
    delivery_by_id(&service.pool, organization_id, project_id, delivery_id)
        .await?
        .ok_or(WorkerError::Database(sqlx::Error::RowNotFound))
}

pub async fn list_deliveries(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    filter: &DeliveryFilter,
) -> Result<(Vec<DeliverySummary>, Option<Uuid>), sqlx::Error> {
    let limit = filter.limit.unwrap_or(50).clamp(1, 200);
    let cursor = if let Some(cursor) = filter.cursor {
        NotificationDeliveryRepository::cursor(pool, organization_id, project_id, cursor).await?
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut rows = NotificationDeliveryRepository::page::<_, DeliverySummaryRow>(
        pool,
        organization_id,
        project_id,
        filter.destination_id,
        filter.status.as_deref(),
        filter.source.as_deref(),
        filter.origin.as_deref(),
        filter.since,
        cursor_time,
        cursor_id,
        limit + 1,
    )
    .await?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last().map(|delivery| delivery.id)
    } else {
        None
    };
    Ok((
        rows.into_iter().map(DeliverySummary::from).collect(),
        next_cursor,
    ))
}

pub async fn delivery_detail(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    delivery_id: Uuid,
) -> Result<Option<DeliveryDetail>, sqlx::Error> {
    let Some(delivery) = delivery_by_id(pool, organization_id, project_id, delivery_id).await?
    else {
        return Ok(None);
    };
    let attempts = NotificationDeliveryRepository::attempts::<_, DeliveryAttempt>(
        pool,
        organization_id,
        project_id,
        delivery_id,
    )
    .await?;
    Ok(Some(DeliveryDetail { delivery, attempts }))
}

async fn delivery_by_id(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<DeliverySummary>, sqlx::Error> {
    let row = NotificationDeliveryRepository::get::<_, DeliverySummaryRow>(
        pool,
        organization_id,
        project_id,
        id,
    )
    .await?;
    Ok(row.map(DeliverySummary::from))
}

fn classify(result: Result<WebhookResponse, WebhookError>, elapsed: Duration) -> AttemptResult {
    match result {
        Ok(response) if response.status.is_success() => AttemptResult {
            disposition: AttemptDisposition::Succeeded,
            http_status: Some(response.status.as_u16()),
            error_class: None,
            response_excerpt: Some(response.response_excerpt),
            retry_after: None,
            duration: response.duration,
        },
        Ok(response) => {
            let retryable = retryable_status(response.status);
            AttemptResult {
                disposition: if retryable {
                    AttemptDisposition::Retryable
                } else {
                    AttemptDisposition::Failed
                },
                http_status: Some(response.status.as_u16()),
                error_class: Some(if retryable {
                    "http_retryable"
                } else {
                    "http_rejected"
                }),
                response_excerpt: Some(response.response_excerpt),
                retry_after: response.retry_after,
                duration: response.duration,
            }
        }
        Err(error) => {
            let (disposition, class) = match error {
                WebhookError::Request(ref request) if request.is_timeout() => {
                    (AttemptDisposition::Retryable, "timeout")
                }
                WebhookError::Request(_)
                | WebhookError::Resolution(_)
                | WebhookError::Response(_) => (AttemptDisposition::Retryable, "network"),
                WebhookError::UnsafeAddress | WebhookError::InvalidUrl(_) => {
                    (AttemptDisposition::Failed, "unsafe_target")
                }
                WebhookError::Client(_) => (AttemptDisposition::Retryable, "client"),
                WebhookError::Serialization(_) | WebhookError::SigningKey => {
                    (AttemptDisposition::Failed, "invalid_payload")
                }
            };
            AttemptResult {
                disposition,
                http_status: None,
                error_class: Some(class),
                response_excerpt: None,
                retry_after: None,
                duration: elapsed,
            }
        }
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error() || matches!(status.as_u16(), 408 | 425 | 429)
}

impl AttemptResult {
    fn failed(class: &'static str, duration: Duration) -> Self {
        Self {
            disposition: AttemptDisposition::Failed,
            http_status: None,
            error_class: Some(class),
            response_excerpt: None,
            retry_after: None,
            duration,
        }
    }
}

async fn persist_attempt(
    service: &NotificationService,
    claim: &DeliveryClaim,
    started_at: DateTime<Utc>,
    result: AttemptResult,
) -> Result<(), WorkerError> {
    let mut tx = service.pool.begin().await?;
    let attempt_number = claim.attempt_count.saturating_add(1);
    let exhausted = attempt_number >= claim.max_attempts;
    let disposition = if result.disposition == AttemptDisposition::Retryable && exhausted {
        AttemptDisposition::Failed
    } else {
        result.disposition
    };
    crate::metrics::record_notification_attempt(
        u64::try_from(result.duration.as_micros()).unwrap_or(u64::MAX),
        disposition == AttemptDisposition::Retryable,
        disposition == AttemptDisposition::Failed,
    );
    NotificationDeliveryRepository::insert_attempt(
        &mut *tx,
        Uuid::new_v4(),
        claim.organization_id,
        claim.project_id,
        claim.id,
        claim.recovery_generation,
        attempt_number,
        started_at,
        i64::try_from(result.duration.as_millis()).unwrap_or(i64::MAX),
        match disposition {
            AttemptDisposition::Succeeded => "succeeded",
            AttemptDisposition::Retryable => "retryable",
            AttemptDisposition::Failed => "failed",
        },
        result.http_status.map(i32::from),
        result.error_class,
        result.response_excerpt,
    )
    .await?;
    match disposition {
        AttemptDisposition::Succeeded => {
            update_terminal(&mut tx, claim, attempt_number, "succeeded", None).await?;
        }
        AttemptDisposition::Failed => {
            update_terminal(&mut tx, claim, attempt_number, "failed", result.error_class).await?;
        }
        AttemptDisposition::Retryable => {
            let delay = retry_delay(service, attempt_number, result.retry_after);
            let delay_seconds = i64::try_from(delay.as_secs()).unwrap_or(i64::MAX);
            NotificationDeliveryRepository::schedule_retry(
                &mut *tx,
                claim.id,
                claim.lease_owner,
                attempt_number,
                delay_seconds,
                result.error_class,
            )
            .await?;
        }
    }
    complete_outbox_if_terminal(&mut tx, claim.outbox_message_id).await?;
    tx.commit().await?;
    Ok(())
}

async fn update_terminal(
    tx: &mut Transaction<'_, Postgres>,
    claim: &DeliveryClaim,
    attempt_number: i32,
    status: &str,
    error_class: Option<&str>,
) -> Result<(), sqlx::Error> {
    NotificationDeliveryRepository::finish(
        &mut **tx,
        claim.id,
        claim.lease_owner,
        status,
        attempt_number,
        error_class,
    )
    .await?;
    Ok(())
}

fn retry_delay(
    service: &NotificationService,
    attempt_number: i32,
    retry_after: Option<Duration>,
) -> Duration {
    let exponent = u32::try_from(attempt_number.saturating_sub(1))
        .unwrap_or(31)
        .min(31);
    let base = service
        .config
        .backoff_min
        .as_secs()
        .saturating_mul(1_u64 << exponent)
        .min(service.config.backoff_max.as_secs());
    let jitter_max = base / 4;
    let jitter = if jitter_max == 0 {
        0
    } else {
        rand::rng().random_range(0..=jitter_max)
    };
    let computed = Duration::from_secs(
        base.saturating_add(jitter)
            .min(service.config.backoff_max.as_secs()),
    );
    retry_after.map_or(computed, |retry_after| {
        retry_after
            .min(service.config.backoff_max)
            .max(service.config.backoff_min)
    })
}

async fn complete_outbox_if_terminal(
    tx: &mut Transaction<'_, Postgres>,
    outbox_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    if let Some(outbox_id) = outbox_id {
        OutboxRepository::complete_if_deliveries_terminal(&mut **tx, outbox_id).await?;
    }
    Ok(())
}

pub async fn run(service: NotificationService, mut shutdown: watch::Receiver<bool>) {
    tracing::info!("notification worker active");
    let mut ticker = tokio::time::interval(service.config.poll_interval);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = ticker.tick() => {
                match run_cycle(&service).await {
                    Ok(()) => crate::metrics::record_notification_cycle_success(),
                    Err(error) => {
                        crate::metrics::record_notification_cycle_failure();
                        tracing::error!(error=%error, "notification worker cycle failed");
                    }
                }
            }
        }
    }
    tracing::info!("notification worker stopped claiming work");
}

async fn run_cycle(service: &NotificationService) -> Result<(), WorkerError> {
    let stats = materialize_once(service).await?;
    if stats != MaterializeStats::default() {
        tracing::info!(?stats, "notification outbox materialized");
    }
    let claims = claim_due(service).await?;
    stream::iter(claims.into_iter().map(|claim| {
        let service = service.clone();
        async move {
            if let Err(error) = process_claim(&service, claim).await {
                tracing::error!(error=%error, "notification delivery attempt failed to persist");
            }
        }
    }))
    .buffer_unordered(service.config.concurrency)
    .collect::<Vec<_>>()
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_classification_matches_contract() {
        for status in [408, 425, 429, 500, 503] {
            assert!(retryable_status(StatusCode::from_u16(status).unwrap()));
        }
        for status in [301, 400, 401, 404, 422] {
            assert!(!retryable_status(StatusCode::from_u16(status).unwrap()));
        }
    }

    #[test]
    fn delivery_summary_exposes_safe_typed_ui_metadata() {
        let application_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let available_at = Utc::now();
        let summary = DeliverySummary::from(DeliverySummaryRow {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            destination_id: Uuid::new_v4(),
            outbox_message_id: None,
            origin: "outbox".into(),
            source: "live".into(),
            event_name: "runtime_group.first_seen".into(),
            payload: serde_json::json!({
                "application_id": application_id,
                "group_id": group_id,
                "event_kind": "exec"
            }),
            destination_name: "operations".into(),
            destination_enabled: true,
            status: "pending".into(),
            available_at,
            recovery_generation: 0,
            attempt_count: 1,
            total_attempt_count: 1,
            max_attempts: 3,
            last_error_class: Some("timeout".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            terminal_at: None,
            last_recovery_operation_id: None,
        });

        assert_eq!(summary.next_attempt_at, Some(available_at));
        assert_eq!(summary.terminal_reason, None);
        assert_eq!(summary.destination.name, "operations");
        let metadata = summary
            .semantic_metadata
            .as_ref()
            .expect("semantic metadata");
        assert_eq!(metadata.application_id, Some(application_id));
        assert_eq!(metadata.group_id, Some(group_id));
        assert_eq!(metadata.event_kind.as_deref(), Some("exec"));
        let json = serde_json::to_value(summary).unwrap();
        assert!(json["destination"].get("url").is_none());
    }
}
