//! Resource usage of applications: recording the agents' aggregates,
//! retention cleanup, regression findings per release, and reading history
//! and release comparisons.
//!
//! The query types below are also the request's query strings.

use chrono::{DateTime, Duration, Timelike, Utc};
use event_model::{ResourceAggregate, ResourceValues};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::{
    collections::BTreeSet,
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;
use uuid::Uuid;

use crate::access_control::resolve_project_access;
use crate::application_credentials::ApplicationCredentialScope;
use crate::auth::{IdentityPrincipal, SessionScope};
use crate::repository::resources::ResourceRepository;
use crate::repository::{ApplicationRepository, ProjectRepository};

/// Why a resource read failed.
#[derive(Debug, Error)]
pub enum ResourceServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The project, application or release does not exist, or the principal
    /// may not see it.
    #[error("application or release not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub const RESOURCE_DETAIL_RETENTION_DAYS: i64 = 7;
pub const RESOURCE_ROLLUP_RETENTION_DAYS: i64 = 90;
static CLEANUP_DELETED: AtomicU64 = AtomicU64::new(0);
static CLEANUP_ERRORS: AtomicU64 = AtomicU64::new(0);
static CLEANUP_DURATION_US: AtomicU64 = AtomicU64::new(0);
static CLEANUP_LAST_SUCCESS: AtomicU64 = AtomicU64::new(0);

pub fn render_metrics() -> String {
    let values = [
        ("cleanup_deleted_rows_total", &CLEANUP_DELETED),
        ("cleanup_errors_total", &CLEANUP_ERRORS),
        ("cleanup_duration_microseconds_total", &CLEANUP_DURATION_US),
        (
            "cleanup_last_success_timestamp_seconds",
            &CLEANUP_LAST_SUCCESS,
        ),
    ];
    values
        .iter()
        .fold(String::new(), |mut output, (name, value)| {
            let _ = writeln!(
                &mut output,
                "okoscope_resource_retention_{name} {}",
                value.load(Ordering::Relaxed)
            );
            output
        })
}

pub async fn cleanup_project(
    pool: &PgPool,
    project_id: Uuid,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let started = std::time::Instant::now();
    let result = cleanup_project_inner(pool, project_id, now, limit).await;
    CLEANUP_DURATION_US.fetch_add(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    match &result {
        Ok(deleted) => {
            CLEANUP_DELETED.fetch_add(*deleted, Ordering::Relaxed);
            CLEANUP_LAST_SUCCESS.store(
                u64::try_from(Utc::now().timestamp()).unwrap_or(0),
                Ordering::Relaxed,
            );
        }
        Err(_) => {
            CLEANUP_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
    result
}

async fn cleanup_project_inner(
    pool: &PgPool,
    project_id: Uuid,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Lock order for project-scoped work is organization FOR SHARE, then
    // project FOR UPDATE; see OrganizationRepository::lock_shared. A single
    // `JOIN … FOR UPDATE` locked the project first and then took an exclusive
    // lock on the organization, which deadlocked against the retention worker
    // and inventory operations. A project never changes organization, so the
    // unlocked read below is only used to find which row to lock.
    let organization_id: Uuid = ProjectRepository::organization_id_of(&mut *tx, project_id).await?;
    crate::repository::OrganizationRepository::lock_shared(&mut *tx, organization_id).await?;
    let (detail, rollup): (i32, i32) =
        ResourceRepository::retention_days_for_update(&mut *tx, project_id).await?;
    let detail_before = now - Duration::days(i64::from(detail));
    let rollup_before = now - Duration::days(i64::from(rollup));
    ResourceRepository::advance_retention_horizons(
        &mut *tx,
        project_id,
        detail_before,
        rollup_before,
    )
    .await?;
    let contributions = ResourceRepository::delete_expired_contributions(
        &mut *tx,
        project_id,
        detail_before,
        limit.clamp(1, 1_000),
    )
    .await?
    .rows_affected();
    let remaining = limit
        .clamp(1, 1_000)
        .saturating_sub(i64::try_from(contributions).unwrap_or(i64::MAX));
    let rollups = if remaining == 0 {
        0
    } else {
        ResourceRepository::delete_expired_rollups(
            &mut *tx,
            project_id,
            detail_before,
            rollup_before,
            remaining,
        )
        .await?
        .rows_affected()
    };
    tx.commit().await?;
    Ok(contributions.saturating_add(rollups))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistResourceOutcome {
    Accepted,
    Duplicate,
    Expired,
}

pub async fn persist_resource_aggregate(
    pool: &PgPool,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    agent_id: Uuid,
    aggregate: &ResourceAggregate,
) -> Result<PersistResourceOutcome, sqlx::Error> {
    let retention_days = effective_detail_retention(pool, application.project_id).await?;
    if aggregate.interval_end < Utc::now() - Duration::days(retention_days) {
        return Ok(PersistResourceOutcome::Expired);
    }
    let release_id = resolve_release(pool, application, aggregate).await?;
    let mut transaction = pool.begin().await?;
    let inserted = insert_contribution(
        &mut transaction,
        scope,
        application,
        agent_id,
        release_id,
        aggregate,
    )
    .await?;
    if !inserted {
        transaction.rollback().await?;
        return Ok(PersistResourceOutcome::Duplicate);
    }
    for metric in metric_contributions(
        &aggregate.values,
        aggregate.covered_usec,
        aggregate.sample_count,
    ) {
        upsert_rollup(
            &mut transaction,
            application,
            release_id,
            aggregate,
            &metric,
            60,
        )
        .await?;
        upsert_rollup(
            &mut transaction,
            application,
            release_id,
            aggregate,
            &metric,
            3_600,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(PersistResourceOutcome::Accepted)
}

async fn effective_detail_retention(pool: &PgPool, project_id: Uuid) -> Result<i64, sqlx::Error> {
    let days: i32 = ResourceRepository::detail_retention_days(pool, project_id).await?;
    Ok(i64::from(days))
}

async fn resolve_release(
    pool: &PgPool,
    application: ApplicationCredentialScope,
    aggregate: &ResourceAggregate,
) -> Result<Option<Uuid>, sqlx::Error> {
    let Some(identity) = &aggregate.release_identity else {
        return Ok(None);
    };
    crate::repository::ReleaseRepository::id_by_identity(
        pool,
        crate::repository::ApplicationScope {
            organization_id: application.organization_id,
            project_id: application.project_id,
            application_id: application.application_id,
        },
        i16::try_from(identity.version).unwrap_or(i16::MAX),
        identity.digest.as_slice(),
    )
    .await
}

async fn insert_contribution(
    transaction: &mut Transaction<'_, Postgres>,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    agent_id: Uuid,
    release_id: Option<Uuid>,
    aggregate: &ResourceAggregate,
) -> Result<bool, sqlx::Error> {
    let values = serde_json::to_value(&aggregate.values).unwrap_or_else(|_| serde_json::json!({}));
    let result = ResourceRepository::insert_contribution(
        &mut **transaction,
        aggregate.id,
        application.organization_id,
        application.project_id,
        application.application_id,
        scope.cluster_id,
        agent_id,
        release_id,
        i16::try_from(aggregate.schema_version).unwrap_or(i16::MAX),
        aggregate.interval_start,
        aggregate.interval_end,
        i64::try_from(aggregate.covered_usec).unwrap_or(i64::MAX),
        i32::try_from(aggregate.sample_count).unwrap_or(i32::MAX),
        i32::try_from(aggregate.contributing_containers).unwrap_or(i32::MAX),
        &aggregate.namespace,
        &aggregate.workload_uid,
        &aggregate.workload_kind,
        &aggregate.workload_name,
        &aggregate.container_name,
        &aggregate.node_name,
        i64::try_from(aggregate.unavailable_sources).unwrap_or(i64::MAX),
        values,
    )
    .await?;
    Ok(result.rows_affected() == 1)
}

#[derive(Clone, Copy, Debug)]
struct MetricContribution {
    name: &'static str,
    unit: &'static str,
    value: f64,
    limit: Option<f64>,
}

fn metric_contributions(
    values: &ResourceValues,
    covered_usec: u64,
    sample_count: u32,
) -> Vec<MetricContribution> {
    let covered = u64_as_f64(covered_usec);
    let samples = f64::from(sample_count.max(1));
    let mut metrics = Vec::with_capacity(25);
    push_ratio(
        &mut metrics,
        "cpu_usage_cores",
        "cores",
        values.cpu_usage_usec,
        Some(covered_usec),
    );
    push_cpu_quota(&mut metrics, values, covered_usec);
    push_ratio(
        &mut metrics,
        "cpu_throttled_period_ratio",
        "ratio",
        values.cpu_nr_throttled,
        values.cpu_nr_periods,
    );
    push_scaled(
        &mut metrics,
        "cpu_throttled_seconds",
        "seconds",
        values.cpu_throttled_usec,
        1_000_000.0,
    );
    push_memory_metrics(&mut metrics, values, samples);
    push_count_metrics(&mut metrics, values);
    push_pressure_metrics(&mut metrics, values, covered_usec);
    push_rate(
        &mut metrics,
        "io_read_bytes",
        "bytes_per_second",
        values.io_read_bytes,
        covered,
    );
    push_rate(
        &mut metrics,
        "io_write_bytes",
        "bytes_per_second",
        values.io_write_bytes,
        covered,
    );
    push_io_rates(&mut metrics, values, covered);
    push_gauge(
        &mut metrics,
        "pids_current",
        "count",
        values.pids_current_sum,
        values.pids_limit,
        samples,
    );
    push_ratio(
        &mut metrics,
        "pids_limit_ratio",
        "ratio",
        values.pids_current_max,
        values.pids_limit,
    );
    push_scaled(
        &mut metrics,
        "pids_max_events",
        "count",
        values.pids_max_events,
        1.0,
    );
    metrics
}

fn push_cpu_quota(metrics: &mut Vec<MetricContribution>, values: &ResourceValues, covered: u64) {
    let Some((usage, quota, period)) = values
        .cpu_usage_usec
        .zip(values.cpu_quota_usec)
        .zip(values.cpu_period_usec)
        .map(|((usage, quota), period)| (usage, quota, period))
        .filter(|(_, quota, period)| *quota > 0 && *period > 0 && covered > 0)
    else {
        return;
    };
    let usage_cores = u64_as_f64(usage) / u64_as_f64(covered);
    let quota_cores = u64_as_f64(quota) / u64_as_f64(period);
    metrics.push(MetricContribution {
        name: "cpu_quota_ratio",
        unit: "ratio",
        value: usage_cores / quota_cores,
        limit: Some(quota_cores),
    });
}

fn push_memory_metrics(
    metrics: &mut Vec<MetricContribution>,
    values: &ResourceValues,
    samples: f64,
) {
    for (name, sum, limit) in [
        (
            "memory_current_bytes",
            values.memory_current_sum_bytes,
            values.memory_limit_bytes,
        ),
        ("memory_anon_bytes", values.memory_anon_sum_bytes, None),
        ("memory_file_bytes", values.memory_file_sum_bytes, None),
    ] {
        push_gauge(metrics, name, "bytes", sum, limit, samples);
    }
    if let Some((sum, limit)) = values
        .memory_current_sum_bytes
        .zip(values.memory_limit_bytes)
        .filter(|(_, limit)| *limit > 0)
    {
        let limit = u64_as_f64(limit);
        let average = u64_as_f64(sum) / samples;
        metrics.push(MetricContribution {
            name: "memory_headroom_ratio",
            unit: "ratio",
            value: ((limit - average) / limit).max(0.0),
            limit: Some(limit),
        });
    }
}

fn push_count_metrics(metrics: &mut Vec<MetricContribution>, values: &ResourceValues) {
    for (name, value) in [
        ("memory_high_events", values.memory_high_events),
        ("memory_max_events", values.memory_max_events),
        ("oom_events", values.memory_oom_events),
        ("oom_kill_events", values.memory_oom_kill_events),
    ] {
        push_scaled(metrics, name, "count", value, 1.0);
    }
}

fn push_pressure_metrics(
    metrics: &mut Vec<MetricContribution>,
    values: &ResourceValues,
    covered: u64,
) {
    for (name, value) in [
        ("cpu_psi_some_ratio", values.cpu_psi_some_usec),
        ("cpu_psi_full_ratio", values.cpu_psi_full_usec),
        ("memory_psi_some_ratio", values.memory_psi_some_usec),
        ("memory_psi_full_ratio", values.memory_psi_full_usec),
        ("io_psi_some_ratio", values.io_psi_some_usec),
        ("io_psi_full_ratio", values.io_psi_full_usec),
    ] {
        push_ratio(metrics, name, "ratio", value, Some(covered));
    }
}

fn push_io_rates(metrics: &mut Vec<MetricContribution>, values: &ResourceValues, covered: f64) {
    for (name, value) in [
        ("io_read_operations", values.io_read_operations),
        ("io_write_operations", values.io_write_operations),
    ] {
        if let Some(value) = value {
            metrics.push(MetricContribution {
                name,
                unit: "operations_per_second",
                value: u64_as_f64(value) * 1_000_000.0 / covered,
                limit: None,
            });
        }
    }
}

fn push_rate(
    metrics: &mut Vec<MetricContribution>,
    name: &'static str,
    unit: &'static str,
    value: Option<u64>,
    covered: f64,
) {
    if let Some(value) = value.filter(|_| covered > 0.0) {
        metrics.push(MetricContribution {
            name,
            unit,
            value: u64_as_f64(value) * 1_000_000.0 / covered,
            limit: None,
        });
    }
}

fn push_ratio(
    metrics: &mut Vec<MetricContribution>,
    name: &'static str,
    unit: &'static str,
    numerator: Option<u64>,
    denominator: Option<u64>,
) -> bool {
    let Some((numerator, denominator)) = numerator
        .zip(denominator)
        .filter(|(_, denominator)| *denominator > 0)
    else {
        return false;
    };
    metrics.push(MetricContribution {
        name,
        unit,
        value: u64_as_f64(numerator) / u64_as_f64(denominator),
        limit: None,
    });
    true
}

fn push_scaled(
    metrics: &mut Vec<MetricContribution>,
    name: &'static str,
    unit: &'static str,
    value: Option<u64>,
    scale: f64,
) {
    if let Some(value) = value {
        metrics.push(MetricContribution {
            name,
            unit,
            value: u64_as_f64(value) / scale,
            limit: None,
        });
    }
}

fn push_gauge(
    metrics: &mut Vec<MetricContribution>,
    name: &'static str,
    unit: &'static str,
    sum: Option<u64>,
    limit: Option<u64>,
    divisor: f64,
) {
    if let Some(value) = sum {
        metrics.push(MetricContribution {
            name,
            unit,
            value: u64_as_f64(value) / divisor,
            limit: limit.map(u64_as_f64),
        });
    }
}

#[allow(clippy::cast_precision_loss)]
fn u64_as_f64(value: u64) -> f64 {
    value as f64
}

#[allow(clippy::cast_precision_loss)]
fn i64_as_f64(value: i64) -> f64 {
    value as f64
}

async fn upsert_rollup(
    transaction: &mut Transaction<'_, Postgres>,
    application: ApplicationCredentialScope,
    release_id: Option<Uuid>,
    aggregate: &ResourceAggregate,
    metric: &MetricContribution,
    step: i32,
) -> Result<(), sqlx::Error> {
    let release_key = release_id.unwrap_or(Uuid::nil());
    let expected = (aggregate.interval_end - aggregate.interval_start)
        .num_microseconds()
        .unwrap_or(0)
        .saturating_mul(i64::from(aggregate.contributing_containers));
    ResourceRepository::add_rollup_point(
        &mut **transaction,
        application.organization_id,
        application.project_id,
        application.application_id,
        release_key,
        release_id,
        &aggregate.container_name,
        aggregate.interval_start,
        step,
        metric.name,
        metric.unit,
        metric.value,
        u64_as_f64(aggregate.covered_usec),
        metric.limit,
        i64::try_from(aggregate.covered_usec).unwrap_or(i64::MAX),
        expected,
        i64::from(aggregate.sample_count),
        i32::try_from(aggregate.contributing_containers).unwrap_or(i32::MAX),
        i32::try_from(aggregate.ready_containers).unwrap_or(i32::MAX),
        i64::try_from(aggregate.unavailable_sources).unwrap_or(i64::MAX),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    metric: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    step: String,
    release_id: Option<Uuid>,
    container: Option<String>,
    #[serde(default = "default_normalization")]
    mode: String,
}

fn default_normalization() -> String {
    "total".into()
}

#[derive(Debug, FromRow)]
struct HistoryRow {
    bucket_start: DateTime<Utc>,
    unit: String,
    value: f64,
    limit_value: Option<f64>,
    covered_usec: i64,
    expected_usec: i64,
    sample_count: i64,
    contributor_count: i64,
    observed_replicas: i32,
    ready_replicas: i32,
    unavailable_sources: i64,
    release_id: Option<Uuid>,
    release_display_name: Option<String>,
    container_name: String,
}

#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    metric: String,
    unit: String,
    step: String,
    normalization: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    availability: &'static str,
    points: Vec<HistoryPoint>,
    releases: Vec<ReleaseMarker>,
    containers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HistoryPoint {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    value: Option<f64>,
    availability: &'static str,
    coverage: Coverage,
    release: Option<ReleaseRef>,
    container: Option<String>,
    limit: Option<Limit>,
}

#[derive(Clone, Debug, Serialize)]
struct Coverage {
    covered_seconds: f64,
    expected_seconds: f64,
    ratio: f64,
    sample_count: i64,
    contributor_count: i64,
    observed_replicas: i32,
    ready_replicas: i32,
    complete: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ReleaseRef {
    id: Uuid,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct ReleaseMarker {
    release: ReleaseRef,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct Limit {
    value: f64,
    unit: String,
}

fn history_response(query: HistoryQuery, step: i32, rows: Vec<HistoryRow>) -> HistoryResponse {
    let unit = rows.first().map_or_else(
        || metric_unit(&query.metric).to_owned(),
        |row| row.unit.clone(),
    );
    let mut containers = rows
        .iter()
        .map(|row| row.container_name.clone())
        .collect::<Vec<_>>();
    containers.sort();
    containers.dedup();
    containers.truncate(24);
    let mut releases = rows
        .iter()
        .filter_map(|row| {
            row.release_id
                .zip(row.release_display_name.clone())
                .map(|(id, display_name)| (id, display_name, row.bucket_start))
        })
        .map(|(id, display_name, observed_at)| ReleaseMarker {
            release: ReleaseRef { id, display_name },
            observed_at,
        })
        .collect::<Vec<_>>();
    releases.sort_by_key(|marker| marker.observed_at);
    releases.dedup_by_key(|marker| marker.release.id);
    releases.truncate(100);
    let observed_buckets = rows
        .iter()
        .map(|row| row.bucket_start)
        .collect::<BTreeSet<_>>();
    let mut points: Vec<HistoryPoint> = rows
        .into_iter()
        .map(|row| history_point(row, step, &query.mode, &query.metric))
        .collect();
    append_history_gaps(&mut points, &observed_buckets, query.from, query.to, step);
    points.sort_by(|left, right| left.from.cmp(&right.from));
    let availability = if points.iter().any(|point| point.value.is_some()) {
        "available"
    } else if points
        .iter()
        .any(|point| point.availability == "unsupported")
    {
        "unsupported"
    } else {
        "insufficient_coverage"
    };
    HistoryResponse {
        metric: query.metric,
        unit,
        step: query.step,
        normalization: query.mode,
        from: query.from,
        to: query.to,
        availability,
        points,
        releases,
        containers,
    }
}

fn append_history_gaps(
    points: &mut Vec<HistoryPoint>,
    observed: &BTreeSet<DateTime<Utc>>,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    step: i32,
) {
    let duration = Duration::seconds(i64::from(step));
    let mut bucket = from;
    while bucket < to {
        if !observed.contains(&bucket) {
            points.push(HistoryPoint {
                from: bucket,
                to: bucket + duration,
                value: None,
                availability: "insufficient_coverage",
                coverage: Coverage {
                    covered_seconds: 0.0,
                    expected_seconds: f64::from(step),
                    ratio: 0.0,
                    sample_count: 0,
                    contributor_count: 0,
                    observed_replicas: 0,
                    ready_replicas: 0,
                    complete: false,
                },
                release: None,
                container: None,
                limit: None,
            });
        }
        bucket += duration;
    }
}

fn history_point(row: HistoryRow, step: i32, mode: &str, metric: &str) -> HistoryPoint {
    let ratio = if row.expected_usec > 0 {
        i64_as_f64(row.covered_usec) / i64_as_f64(row.expected_usec)
    } else {
        0.0
    }
    .clamp(0.0, 1.0);
    let unsupported = u64::try_from(row.unavailable_sources)
        .is_ok_and(|mask| mask & metric_source_mask(metric) != 0);
    let complete = ratio >= 0.8 && !unsupported;
    let interval_usec = i64::from(step).saturating_mul(1_000_000);
    let effective_replicas = if interval_usec > 0 {
        (i64_as_f64(row.covered_usec) / i64_as_f64(interval_usec)).max(1.0)
    } else {
        1.0
    };
    let scale = if mode == "total" && !metric.ends_with("_ratio") {
        effective_replicas
    } else {
        1.0
    };
    HistoryPoint {
        from: row.bucket_start,
        to: row.bucket_start + Duration::seconds(i64::from(step)),
        value: complete.then_some(row.value * scale),
        availability: if unsupported {
            "unsupported"
        } else if complete {
            "available"
        } else {
            "insufficient_coverage"
        },
        coverage: Coverage {
            covered_seconds: i64_as_f64(row.covered_usec) / 1_000_000.0,
            expected_seconds: i64_as_f64(row.expected_usec) / 1_000_000.0,
            ratio,
            sample_count: row.sample_count,
            contributor_count: row.contributor_count,
            observed_replicas: row.observed_replicas,
            ready_replicas: row.ready_replicas,
            complete,
        },
        release: row
            .release_id
            .zip(row.release_display_name)
            .map(|(id, display_name)| ReleaseRef { id, display_name }),
        container: Some(row.container_name),
        limit: row.limit_value.map(|value| Limit {
            value: value * scale,
            unit: row.unit,
        }),
    }
}

fn metric_source_mask(metric: &str) -> u64 {
    if metric.starts_with("cpu_psi_") {
        1 << 2
    } else if metric.starts_with("memory_psi_") {
        1 << 3
    } else if metric.starts_with("io_psi_") {
        1 << 5
    } else if metric.starts_with("cpu_") {
        1 << 0
    } else if metric.starts_with("memory_") || metric.starts_with("oom_") {
        1 << 1
    } else if metric.starts_with("io_") {
        1 << 4
    } else if metric.starts_with("pids_") {
        1 << 6
    } else {
        0
    }
}

fn validate_history_query(query: &HistoryQuery) -> Result<i32, ResourceServiceError> {
    if !RESOURCE_METRICS.contains(&query.metric.as_str()) {
        return Err(ResourceServiceError::Invalid(
            "unsupported resource metric".into(),
        ));
    }
    if query.from >= query.to
        || query.from.second() != 0
        || query.from.nanosecond() != 0
        || query.to.second() != 0
        || query.to.nanosecond() != 0
    {
        return Err(ResourceServiceError::Invalid(
            "from and to must be aligned UTC minute bounds with from before to".into(),
        ));
    }
    if query
        .container
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(ResourceServiceError::Invalid(
            "container must contain 1..=256 bytes".into(),
        ));
    }
    if !matches!(query.mode.as_str(), "total" | "per_ready_replica") {
        return Err(ResourceServiceError::Invalid(
            "mode must be total or per_ready_replica".into(),
        ));
    }
    match query.step.as_str() {
        "minute" if query.to - query.from <= Duration::days(31) => Ok(60),
        "hour"
            if query.to - query.from <= Duration::days(366)
                && query.from.minute() == 0
                && query.to.minute() == 0 =>
        {
            Ok(3_600)
        }
        "minute" | "hour" => Err(ResourceServiceError::Invalid(
            "resource history range exceeds the selected step bound or is not hour aligned".into(),
        )),
        _ => Err(ResourceServiceError::Invalid(
            "step must be minute or hour".into(),
        )),
    }
}

async fn project_organization(
    state: &ResourceService,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Uuid, ResourceServiceError> {
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await?
        .ok_or(ResourceServiceError::NotFound)?;
    resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await?
        .ok_or(ResourceServiceError::NotFound)?;
    Ok(organization_id)
}

async fn ensure_application(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ResourceServiceError> {
    let exists =
        ApplicationRepository::exists(pool, organization_id, project_id, application_id).await?;
    if exists {
        Ok(())
    } else {
        Err(ResourceServiceError::NotFound)
    }
}

fn metric_unit(metric: &str) -> &'static str {
    match metric {
        "cpu_usage_cores" => "cores",
        "cpu_throttled_seconds" => "seconds",
        "memory_current_bytes" | "memory_anon_bytes" | "memory_file_bytes" => "bytes",
        "io_read_bytes" | "io_write_bytes" => "bytes_per_second",
        "io_read_operations" | "io_write_operations" => "operations_per_second",
        value if value.ends_with("_ratio") => "ratio",
        _ => "count",
    }
}

const RESOURCE_METRICS: &[&str] = &[
    "cpu_usage_cores",
    "cpu_quota_ratio",
    "cpu_throttled_period_ratio",
    "cpu_throttled_seconds",
    "memory_current_bytes",
    "memory_anon_bytes",
    "memory_file_bytes",
    "memory_headroom_ratio",
    "memory_high_events",
    "memory_max_events",
    "oom_events",
    "oom_kill_events",
    "cpu_psi_some_ratio",
    "cpu_psi_full_ratio",
    "memory_psi_some_ratio",
    "memory_psi_full_ratio",
    "io_psi_some_ratio",
    "io_psi_full_ratio",
    "io_read_bytes",
    "io_write_bytes",
    "io_read_operations",
    "io_write_operations",
    "pids_current",
    "pids_limit_ratio",
    "pids_max_events",
];

#[derive(Debug, Deserialize)]
pub struct ComparisonQuery {
    baseline_id: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow)]
struct EpisodeWindowSource {
    episode_id: Uuid,
    release_id: Uuid,
    release_display_name: String,
    first_observed_at: DateTime<Utc>,
    first_ready_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct ProjectEvaluationTarget {
    organization_id: Uuid,
    application_id: Uuid,
    episode_id: Uuid,
    release_id: Uuid,
    release_display_name: String,
    first_observed_at: DateTime<Utc>,
    first_ready_at: Option<DateTime<Utc>>,
}

impl ProjectEvaluationTarget {
    fn episode(&self) -> EpisodeWindowSource {
        EpisodeWindowSource {
            episode_id: self.episode_id,
            release_id: self.release_id,
            release_display_name: self.release_display_name.clone(),
            first_observed_at: self.first_observed_at,
            first_ready_at: self.first_ready_at,
        }
    }
}

#[derive(Clone, Debug, FromRow)]
struct MetricSummary {
    metric: String,
    unit: String,
    value: f64,
    limit_value: Option<f64>,
    covered_usec: i64,
    expected_usec: i64,
    sample_count: i64,
    contributor_count: i64,
    observed_replicas: i32,
    ready_replicas: i32,
    bucket_count: i64,
}

#[derive(Debug, FromRow)]
struct MetricBucket {
    metric: String,
    bucket_start: DateTime<Utc>,
    value: f64,
}

#[derive(Debug, Serialize)]
pub struct ComparisonResponse {
    state: &'static str,
    interpretation: &'static str,
    baseline_selection_source: &'static str,
    baseline_window: Option<ComparisonWindow>,
    target_window: Option<ComparisonWindow>,
    collection_progress: f64,
    metrics: Vec<MetricComparison>,
    findings: Vec<RegressionFinding>,
}

#[derive(Clone, Debug, Serialize)]
struct ComparisonWindow {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    duration_seconds: i64,
    release: ReleaseRef,
    episode_id: Uuid,
    coverage: Coverage,
}

#[derive(Debug, Serialize)]
struct MetricComparison {
    metric: String,
    unit: String,
    state: &'static str,
    interpretation: &'static str,
    availability: &'static str,
    baseline: Option<f64>,
    target: Option<f64>,
    absolute_change: Option<f64>,
    relative_change: Option<f64>,
    percentage_point_change: Option<f64>,
    limit: Option<Limit>,
}

#[derive(Clone, Debug, Serialize)]
struct RegressionFinding {
    id: Uuid,
    reason_code: &'static str,
    priority: &'static str,
    metric: String,
    rule_version: u16,
    threshold: f64,
    sustained_buckets: u32,
    baseline: Option<f64>,
    target: f64,
    change: Option<f64>,
}

async fn fetch_episode(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Uuid,
) -> Result<Option<EpisodeWindowSource>, sqlx::Error> {
    ResourceRepository::episode_window(
        pool,
        organization_id,
        project_id,
        application_id,
        release_id,
    )
    .await
}

async fn fetch_baseline_episode(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    target: &EpisodeWindowSource,
    explicit: Option<Uuid>,
) -> Result<(Option<EpisodeWindowSource>, &'static str), ResourceServiceError> {
    if let Some(release_id) = explicit {
        let episode = fetch_episode(
            pool,
            organization_id,
            project_id,
            application_id,
            release_id,
        )
        .await?
        .ok_or(ResourceServiceError::NotFound)?;
        return Ok((Some(episode), "explicit"));
    }
    let rows = ResourceRepository::predecessor_episode_windows::<_, EpisodeWindowSource>(
        pool,
        target.episode_id,
        organization_id,
        project_id,
        application_id,
    )
    .await?;
    let source = match rows.len() {
        0 => "none",
        1 => "transition",
        _ => "concurrent_transition_fallback",
    };
    Ok((rows.into_iter().next(), source))
}

pub async fn refresh_project_findings(pool: &PgPool, organization_id: Uuid, project_id: Uuid) {
    let targets = ResourceRepository::latest_ready_episodes::<_, ProjectEvaluationTarget>(
        pool,
        organization_id,
        project_id,
    )
    .await;
    let Ok(targets) = targets else {
        tracing::warn!(%organization_id, %project_id, "resource finding target scan failed");
        return;
    };
    for target in targets {
        let episode = target.episode();
        let baseline = fetch_baseline_episode(
            pool,
            target.organization_id,
            project_id,
            target.application_id,
            &episode,
            None,
        )
        .await;
        let Ok((baseline, source)) = baseline else {
            tracing::warn!(application_id=%target.application_id, "resource baseline scan failed");
            continue;
        };
        if let Err(error) = build_comparison(
            pool,
            target.organization_id,
            project_id,
            target.application_id,
            episode,
            baseline,
            source,
        )
        .await
        {
            tracing::warn!(application_id=%target.application_id, ?error, "resource finding refresh failed");
        }
    }
}

async fn build_comparison(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    target: EpisodeWindowSource,
    baseline: Option<EpisodeWindowSource>,
    source: &'static str,
) -> Result<ComparisonResponse, ResourceServiceError> {
    let target_start = target
        .first_ready_at
        .map(|time| time + Duration::minutes(10));
    let target_end = target_start.map(|time| time + Duration::minutes(30));
    let now = Utc::now();
    let progress = target_start.map_or(0.0, |start| {
        (i64_as_f64((now - start).num_seconds()) / 1800.0).clamp(0.0, 1.0)
    });
    let Some((target_start, target_end, baseline)) = target_start
        .zip(target_end)
        .zip(baseline)
        .map(|((start, end), baseline)| (start, end, baseline))
    else {
        return Ok(empty_comparison(source, progress, "unavailable"));
    };
    let baseline_end = target.first_observed_at;
    let baseline_start = baseline_end - Duration::minutes(30);
    let baseline_metrics = summarize_window(
        pool,
        organization_id,
        project_id,
        application_id,
        baseline.release_id,
        baseline_start,
        baseline_end,
    )
    .await?;
    let target_metrics = summarize_window(
        pool,
        organization_id,
        project_id,
        application_id,
        target.release_id,
        target_start,
        target_end.min(now),
    )
    .await?;
    let baseline_coverage = window_coverage(&baseline_metrics, 1800);
    let target_coverage = window_coverage(&target_metrics, 1800);
    let comparable = now >= target_end && baseline_coverage.complete && target_coverage.complete;
    let metrics = compare_metrics(&baseline_metrics, &target_metrics, comparable);
    let findings = if comparable {
        let candidates = evaluate_findings(target.release_id, &metrics);
        sustained_findings(
            pool,
            organization_id,
            project_id,
            application_id,
            target.release_id,
            target_start,
            target_end,
            candidates,
        )
        .await?
    } else {
        Vec::new()
    };
    let state = if now < target_end {
        "collecting"
    } else if comparable {
        "comparable"
    } else {
        "insufficient_coverage"
    };
    let baseline_window =
        comparison_window(baseline, baseline_start, baseline_end, baseline_coverage);
    let target_window =
        comparison_window(target.clone(), target_start, target_end, target_coverage);
    if comparable {
        persist_findings(
            pool,
            organization_id,
            project_id,
            application_id,
            target.release_id,
            baseline_window.release.id,
            &metrics,
            &findings,
            &baseline_window,
            &target_window,
        )
        .await?;
    }
    Ok(ComparisonResponse {
        state,
        interpretation: "observed_after_release",
        baseline_selection_source: source,
        baseline_window: Some(baseline_window),
        target_window: Some(target_window),
        collection_progress: progress,
        metrics,
        findings,
    })
}

#[allow(clippy::too_many_arguments)]
async fn persist_findings(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    target_release_id: Uuid,
    baseline_release_id: Uuid,
    metrics: &[MetricComparison],
    findings: &[RegressionFinding],
    baseline_window: &ComparisonWindow,
    target_window: &ComparisonWindow,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let active_ids = findings
        .iter()
        .map(|finding| finding.id)
        .collect::<Vec<_>>();
    ResourceRepository::age_findings(
        &mut *tx,
        organization_id,
        project_id,
        application_id,
        target_release_id,
        &active_ids,
    )
    .await?;
    for finding in findings {
        let unit = metrics
            .iter()
            .find(|metric| metric.metric == finding.metric)
            .map_or("count", |metric| metric.unit.as_str());
        let facts = serde_json::json!({"finding_id":finding.id,"reason_code":finding.reason_code,
            "metric":finding.metric,"unit":unit,"rule_version":finding.rule_version,
            "threshold":finding.threshold,"sustained_buckets":finding.sustained_buckets,
            "baseline":finding.baseline,"target":finding.target,"change":finding.change,
            "baseline_window":baseline_window,"target_window":target_window});
        ResourceRepository::upsert_finding(
            &mut *tx,
            finding.id,
            organization_id,
            project_id,
            application_id,
            target_release_id,
            baseline_release_id,
            finding.reason_code,
            finding.priority,
            &finding.metric,
            i16::try_from(finding.rule_version).unwrap_or(i16::MAX),
            facts,
            target_window.from,
        )
        .await?;
    }
    tx.commit().await
}

fn empty_comparison(
    source: &'static str,
    progress: f64,
    state: &'static str,
) -> ComparisonResponse {
    ComparisonResponse {
        state,
        interpretation: "observed_after_release",
        baseline_selection_source: source,
        baseline_window: None,
        target_window: None,
        collection_progress: progress,
        metrics: Vec::new(),
        findings: Vec::new(),
    }
}

async fn summarize_window(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<MetricSummary>, sqlx::Error> {
    ResourceRepository::window_summary(
        pool,
        organization_id,
        project_id,
        application_id,
        release_id,
        from,
        to,
    )
    .await
}

fn window_coverage(metrics: &[MetricSummary], expected_seconds: i64) -> Coverage {
    let representative = metrics.iter().max_by_key(|value| value.bucket_count);
    let covered = representative.map_or(0, |value| value.covered_usec);
    let expected = representative.map_or(expected_seconds * 1_000_000, |value| {
        value.expected_usec.max(expected_seconds * 1_000_000)
    });
    let ratio = if expected > 0 {
        i64_as_f64(covered) / i64_as_f64(expected)
    } else {
        0.0
    }
    .clamp(0.0, 1.0);
    Coverage {
        covered_seconds: i64_as_f64(covered) / 1_000_000.0,
        expected_seconds: i64_as_f64(expected) / 1_000_000.0,
        ratio,
        sample_count: representative.map_or(0, |value| value.sample_count),
        contributor_count: representative.map_or(0, |value| value.contributor_count),
        observed_replicas: representative.map_or(0, |value| value.observed_replicas),
        ready_replicas: representative.map_or(0, |value| value.ready_replicas),
        complete: ratio >= 0.8 && representative.is_some_and(|value| value.bucket_count >= 24),
    }
}

fn comparison_window(
    source: EpisodeWindowSource,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    coverage: Coverage,
) -> ComparisonWindow {
    ComparisonWindow {
        from,
        to,
        duration_seconds: (to - from).num_seconds(),
        release: ReleaseRef {
            id: source.release_id,
            display_name: source.release_display_name,
        },
        episode_id: source.episode_id,
        coverage,
    }
}

fn compare_metrics(
    baseline: &[MetricSummary],
    target: &[MetricSummary],
    comparable: bool,
) -> Vec<MetricComparison> {
    RESOURCE_METRICS
        .iter()
        .filter_map(|name| {
            let base = baseline.iter().find(|value| value.metric == *name);
            let target = target.iter().find(|value| value.metric == *name);
            if base.is_none() && target.is_none() {
                return None;
            }
            let base_value = base.map(|value| value.value);
            let target_value = target.map(|value| value.value);
            let change = target_value
                .zip(base_value)
                .map(|(target, base)| target - base);
            let relative = target_value
                .zip(base_value)
                .and_then(|(target, base)| (base != 0.0).then_some((target - base) / base));
            let ratio = name.ends_with("_ratio");
            let state = if comparable && base.is_some() && target.is_some() {
                "comparable"
            } else {
                "insufficient_coverage"
            };
            let interpretation = interpretation(name, base_value, target_value);
            Some(MetricComparison {
                metric: (*name).into(),
                unit: target
                    .or(base)
                    .map_or_else(|| metric_unit(name).into(), |value| value.unit.clone()),
                state,
                interpretation,
                availability: if base.is_some() && target.is_some() {
                    "available"
                } else {
                    "insufficient_coverage"
                },
                baseline: base_value,
                target: target_value,
                absolute_change: change,
                relative_change: relative,
                percentage_point_change: ratio.then(|| change.map(|value| value * 100.0)).flatten(),
                limit: target.or(base).and_then(|value| {
                    value.limit_value.map(|limit| Limit {
                        value: limit,
                        unit: value.unit.clone(),
                    })
                }),
            })
        })
        .collect()
}

fn interpretation(metric: &str, baseline: Option<f64>, target: Option<f64>) -> &'static str {
    let Some((baseline, target)) = baseline.zip(target) else {
        return "no_material_change";
    };
    if metric == "oom_kill_events" && target > 0.0 {
        "resource_failure"
    } else if (metric.contains("psi")
        || metric.contains("throttled")
        || metric == "memory_headroom_ratio")
        && (target - baseline).abs() >= 0.03
    {
        "resource_pressure"
    } else if baseline != 0.0 && (target - baseline).abs() / baseline.abs() >= 0.25 {
        "observed_increase"
    } else {
        "no_material_change"
    }
}

fn evaluate_findings(release_id: Uuid, metrics: &[MetricComparison]) -> Vec<RegressionFinding> {
    metrics
        .iter()
        .filter_map(|metric| {
            let target = metric.target?;
            let baseline = metric.baseline;
            let change = metric.absolute_change;
            let (reason, priority, threshold) = match metric.metric.as_str() {
                "oom_kill_events" if target > 0.0 => ("oom_observed", "urgent", 1.0),
                "memory_headroom_ratio" if target <= 0.1 => ("memory_limit_pressure", "high", 0.1),
                "memory_high_events" | "memory_max_events"
                    if change.is_some_and(|value| value >= 1.0) =>
                {
                    ("memory_limit_pressure", "high", 1.0)
                }
                "cpu_throttled_period_ratio"
                    if target >= 0.05 && change.is_some_and(|v| v >= 0.05) =>
                {
                    ("cpu_throttling_increased", "high", 0.05)
                }
                "cpu_psi_some_ratio" if target >= 0.05 && change.is_some_and(|v| v >= 0.03) => {
                    ("cpu_pressure_increased", "high", 0.05)
                }
                "memory_psi_some_ratio" if target >= 0.05 && change.is_some_and(|v| v >= 0.03) => {
                    ("memory_pressure_increased", "high", 0.05)
                }
                "io_psi_some_ratio" if target >= 0.05 && change.is_some_and(|v| v >= 0.03) => {
                    ("io_pressure_increased", "high", 0.05)
                }
                "cpu_usage_cores" | "memory_current_bytes"
                    if metric.relative_change.is_some_and(|v| v >= 0.25) =>
                {
                    ("resource_usage_increased", "normal", 0.25)
                }
                _ => return None,
            };
            Some(RegressionFinding {
                id: finding_id(release_id, reason, &metric.metric),
                reason_code: reason,
                priority,
                metric: metric.metric.clone(),
                rule_version: 1,
                threshold,
                sustained_buckets: 3,
                baseline,
                target,
                change,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn sustained_findings(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    candidates: Vec<RegressionFinding>,
) -> Result<Vec<RegressionFinding>, sqlx::Error> {
    if candidates.is_empty() {
        return Ok(candidates);
    }
    let buckets = ResourceRepository::covered_buckets::<_, MetricBucket>(
        pool,
        organization_id,
        project_id,
        application_id,
        release_id,
        from,
        to,
    )
    .await?;
    Ok(candidates
        .into_iter()
        .filter(|finding| finding.reason_code == "oom_observed" || sustained(finding, &buckets))
        .collect())
}

fn sustained(finding: &RegressionFinding, buckets: &[MetricBucket]) -> bool {
    let mut previous = None;
    let mut run = 0_u32;
    for bucket in buckets
        .iter()
        .filter(|value| value.metric == finding.metric)
    {
        let matches = match finding.reason_code {
            "memory_limit_pressure" => bucket.value <= finding.threshold,
            "resource_usage_increased" => finding.baseline.is_some_and(|baseline| {
                baseline != 0.0 && (bucket.value - baseline) / baseline.abs() >= finding.threshold
            }),
            _ => bucket.value >= finding.threshold,
        };
        let adjacent =
            previous.is_some_and(|time| bucket.bucket_start - time == Duration::minutes(1));
        run = if matches && (adjacent || previous.is_none()) {
            run.saturating_add(1)
        } else {
            u32::from(matches)
        };
        previous = Some(bucket.bucket_start);
        if run >= finding.sustained_buckets {
            return true;
        }
    }
    false
}

fn finding_id(release_id: Uuid, reason: &str, metric: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{release_id}:{reason}:{metric}:1"));
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Reads resource history and release comparisons.
#[derive(Clone, Debug)]
pub struct ResourceService {
    pool: PgPool,
}

impl ResourceService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// One resource metric of an application over time, bucketed by the
    /// requested step, with gaps, releases and limits.
    pub async fn history(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: HistoryQuery,
    ) -> Result<HistoryResponse, ResourceServiceError> {
        let organization_id = project_organization(self, principal, project_id).await?;
        ensure_application(&self.pool, organization_id, project_id, application_id).await?;
        let step = validate_history_query(&query)?;
        let rows = ResourceRepository::history::<_, HistoryRow>(
            &self.pool,
            organization_id,
            project_id,
            application_id,
            &query.metric,
            step,
            query.from,
            query.to,
            query.release_id,
            query.container.as_deref(),
        )
        .await?;
        Ok(history_response(query, step, rows))
    }

    /// How a release's resource usage compares with its baseline: the release
    /// named by `baseline_id`, or else the one it replaced.
    pub async fn comparison(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        target_id: Uuid,
        query: ComparisonQuery,
    ) -> Result<ComparisonResponse, ResourceServiceError> {
        let organization_id = project_organization(self, principal, project_id).await?;
        ensure_application(&self.pool, organization_id, project_id, application_id).await?;
        let target = fetch_episode(
            &self.pool,
            organization_id,
            project_id,
            application_id,
            target_id,
        )
        .await?
        .ok_or(ResourceServiceError::NotFound)?;
        let (baseline, source) = fetch_baseline_episode(
            &self.pool,
            organization_id,
            project_id,
            application_id,
            &target,
            query.baseline_id,
        )
        .await?;
        build_comparison(
            &self.pool,
            organization_id,
            project_id,
            application_id,
            target,
            baseline,
            source,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every path that locks a project for update takes the organization's
    /// share lock first — see `OrganizationRepository::lock_shared`. Resource
    /// cleanup used to lock both rows in one `JOIN … FOR UPDATE`, which took the
    /// project first and then an exclusive lock on the organization. Against the
    /// retention worker or an inventory operation on the same project, which
    /// hold the organization and then ask for the project, that is a deadlock,
    /// and `PostgreSQL` aborts one side.
    ///
    /// This holds the organization the way those paths do, lets cleanup start,
    /// then asks for the project. Both must finish.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn cleanup_takes_locks_in_the_shared_order(pool: sqlx::PgPool) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Locks')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(project)
            .bind(organization)
            .execute(&pool)
            .await
            .unwrap();

        let mut holder = pool.begin().await.unwrap();
        assert!(
            crate::repository::OrganizationRepository::lock_shared(&mut *holder, organization)
                .await
                .unwrap()
        );

        let cleanup_pool = pool.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_project_inner(&cleanup_pool, project, Utc::now(), 10).await
        });
        // Let cleanup reach its locks before the holder asks for the project.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let project_lock =
            sqlx::query("SELECT id FROM projects WHERE organization_id=$1 AND id=$2 FOR UPDATE")
                .bind(organization)
                .bind(project)
                .fetch_one(&mut *holder)
                .await;
        let holder_result = match project_lock {
            Ok(_) => holder.commit().await,
            Err(error) => Err(error),
        };

        assert!(
            holder_result.is_ok(),
            "the organization-then-project path must not be aborted: {holder_result:?}"
        );
        assert!(
            cleanup.await.unwrap().is_ok(),
            "resource cleanup must not be aborted"
        );
    }

    #[test]
    fn metric_semantics_keep_pressure_and_throttling_separate() {
        let values = ResourceValues {
            cpu_usage_usec: Some(500_000),
            cpu_nr_periods: Some(10),
            cpu_nr_throttled: Some(2),
            cpu_psi_some_usec: Some(100_000),
            ..ResourceValues::default()
        };
        let metrics = metric_contributions(&values, 1_000_000, 1);
        let value = |name| {
            metrics
                .iter()
                .find(|metric| metric.name == name)
                .unwrap()
                .value
        };
        assert!((value("cpu_usage_cores") - 0.5).abs() < f64::EPSILON);
        assert!((value("cpu_throttled_period_ratio") - 0.2).abs() < f64::EPSILON);
        assert!((value("cpu_psi_some_ratio") - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn history_gaps_are_explicit_and_bounded_by_the_requested_range() {
        let from = Utc::now()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();
        let mut points = Vec::new();
        append_history_gaps(
            &mut points,
            &BTreeSet::new(),
            from,
            from + Duration::minutes(3),
            60,
        );
        assert_eq!(points.len(), 3);
        assert!(points.iter().all(|point| {
            point.value.is_none()
                && point.availability == "insufficient_coverage"
                && point.coverage.ratio.abs() < f64::EPSILON
        }));
    }

    #[test]
    fn history_total_scales_additive_metrics_but_not_ratios() {
        let make_row = |unit: &str| HistoryRow {
            bucket_start: Utc::now(),
            unit: unit.into(),
            value: 10.0,
            limit_value: None,
            covered_usec: 120_000_000,
            expected_usec: 120_000_000,
            sample_count: 8,
            contributor_count: 2,
            observed_replicas: 2,
            ready_replicas: 2,
            unavailable_sources: 0,
            release_id: None,
            release_display_name: None,
            container_name: "api".into(),
        };
        let total = history_point(make_row("bytes"), 60, "total", "memory_current_bytes");
        let per_replica = history_point(
            make_row("bytes"),
            60,
            "per_ready_replica",
            "memory_current_bytes",
        );
        let ratio = history_point(make_row("ratio"), 60, "total", "memory_headroom_ratio");
        assert!((total.value.unwrap() - 20.0).abs() < f64::EPSILON);
        assert!((per_replica.value.unwrap() - 10.0).abs() < f64::EPSILON);
        assert!((ratio.value.unwrap() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn regression_requires_three_adjacent_covered_buckets() {
        let start = Utc::now();
        let finding = RegressionFinding {
            id: Uuid::new_v4(),
            reason_code: "cpu_throttling_increased",
            priority: "high",
            metric: "cpu_throttled_period_ratio".into(),
            rule_version: 1,
            threshold: 0.05,
            sustained_buckets: 3,
            baseline: Some(0.0),
            target: 0.08,
            change: Some(0.08),
        };
        let bucket = |minute, value| MetricBucket {
            metric: finding.metric.clone(),
            bucket_start: start + Duration::minutes(minute),
            value,
        };
        assert!(!sustained(
            &finding,
            &[bucket(0, 0.08), bucket(1, 0.08), bucket(3, 0.08)]
        ));
        assert!(sustained(
            &finding,
            &[bucket(0, 0.08), bucket(1, 0.08), bucket(2, 0.08)]
        ));
    }

    fn summary(metric: &str, value: f64, buckets: i64) -> MetricSummary {
        MetricSummary {
            metric: metric.into(),
            unit: if metric.ends_with("_ratio") {
                "ratio".into()
            } else {
                "count".into()
            },
            value,
            limit_value: None,
            covered_usec: buckets * 60_000_000,
            expected_usec: 30 * 60_000_000,
            sample_count: buckets,
            contributor_count: buckets,
            observed_replicas: 1,
            ready_replicas: 1,
            bucket_count: buckets,
        }
    }

    #[test]
    fn comparison_handles_zero_baseline_scaling_and_missing_coverage() {
        let baseline = [summary("cpu_usage_cores", 0.0, 30)];
        let target = [summary("cpu_usage_cores", 1.0, 30)];
        let metrics = compare_metrics(&baseline, &target, true);
        assert_eq!(metrics[0].absolute_change, Some(1.0));
        assert_eq!(metrics[0].relative_change, None);

        let scaled_baseline = [summary("memory_current_bytes", 100.0, 30)];
        let scaled_target = [summary("memory_current_bytes", 100.0, 30)];
        let scaled = compare_metrics(&scaled_baseline, &scaled_target, true);
        assert_eq!(scaled[0].absolute_change, Some(0.0));

        let coverage = window_coverage(&[summary("cpu_usage_cores", 1.0, 23)], 1_800);
        assert!(!coverage.complete);
        assert_eq!(
            empty_comparison("none", 0.0, "no_baseline").state,
            "no_baseline"
        );
    }

    #[test]
    fn oom_is_immediate_while_transient_pressure_and_recovery_are_inert() {
        let release = Uuid::new_v4();
        let oom = compare_metrics(
            &[summary("oom_kill_events", 0.0, 30)],
            &[summary("oom_kill_events", 1.0, 30)],
            true,
        );
        let findings = evaluate_findings(release, &oom);
        assert_eq!(findings[0].reason_code, "oom_observed");
        assert_eq!(findings[0].priority, "urgent");

        let pressure = compare_metrics(
            &[summary("io_psi_some_ratio", 0.0, 30)],
            &[summary("io_psi_some_ratio", 0.08, 30)],
            true,
        );
        let finding = evaluate_findings(release, &pressure).remove(0);
        let start = Utc::now();
        let bucket = |minute, value| MetricBucket {
            metric: finding.metric.clone(),
            bucket_start: start + Duration::minutes(minute),
            value,
        };
        assert!(!sustained(&finding, &[bucket(0, 0.08), bucket(1, 0.01)]));
        assert!(!sustained(
            &finding,
            &[bucket(0, 0.01), bucket(1, 0.01), bucket(2, 0.01)]
        ));
    }

    /// The reads against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::auth::OrganizationRole;
        use crate::repository::test_support::{Tenant, observe_revision, tenant};

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

        fn history(metric: &str, step: &str) -> HistoryQuery {
            let to = Utc::now()
                .with_second(0)
                .and_then(|value| value.with_nanosecond(0))
                .and_then(|value| value.with_minute(0))
                .unwrap();
            HistoryQuery {
                metric: metric.into(),
                from: to - Duration::hours(2),
                to,
                step: step.into(),
                release_id: None,
                container: None,
                mode: "total".into(),
            }
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn history_checks_access_then_the_query(pool: PgPool) {
            let other = tenant(&pool, "resources-service-other").await;
            let tenant = tenant(&pool, "resources-service-history").await;
            let service = ResourceService::new(pool.clone());
            let (project, application) = (tenant.project_id, tenant.application_id);

            assert!(matches!(
                service
                    .history(
                        owner(&other),
                        project,
                        application,
                        history("bogus", "minute")
                    )
                    .await,
                Err(ResourceServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .history(
                        owner(&tenant),
                        project,
                        other.application_id,
                        history("bogus", "minute"),
                    )
                    .await,
                Err(ResourceServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .history(owner(&tenant), project, application, history("bogus", "minute"))
                    .await,
                Err(ResourceServiceError::Invalid(message)) if message == "unsupported resource metric"
            ));
            assert!(matches!(
                service
                    .history(
                        owner(&tenant),
                        project,
                        application,
                        history("cpu_usage_cores", "day"),
                    )
                    .await,
                Err(ResourceServiceError::Invalid(message)) if message == "step must be minute or hour"
            ));
            let empty = service
                .history(
                    owner(&tenant),
                    project,
                    application,
                    history("cpu_usage_cores", "hour"),
                )
                .await
                .unwrap();
            assert_eq!(empty.unit, "cores");
            assert_eq!(empty.step, "hour");
            assert!(empty.containers.is_empty());
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn comparison_needs_the_release_and_its_baseline(pool: PgPool) {
            let tenant = tenant(&pool, "resources-service-comparison").await;
            let service = ResourceService::new(pool.clone());
            let (project, application) = (tenant.project_id, tenant.application_id);
            let principal = owner(&tenant);
            let none = || ComparisonQuery { baseline_id: None };

            assert!(matches!(
                service
                    .comparison(principal, project, application, Uuid::new_v4(), none())
                    .await,
                Err(ResourceServiceError::NotFound)
            ));
            let release = observe_revision(
                &pool,
                &tenant,
                &"a".repeat(64),
                "api-1",
                Utc::now() - Duration::hours(1),
            )
            .await;
            assert!(matches!(
                service
                    .comparison(
                        principal,
                        project,
                        application,
                        release,
                        ComparisonQuery {
                            baseline_id: Some(Uuid::new_v4()),
                        },
                    )
                    .await,
                Err(ResourceServiceError::NotFound)
            ));
            let comparison = service
                .comparison(principal, project, application, release, none())
                .await
                .unwrap();
            assert_eq!(comparison.baseline_selection_source, "none");
            assert!(comparison.baseline_window.is_none());
            assert!(comparison.findings.is_empty());
        }
    }
}
