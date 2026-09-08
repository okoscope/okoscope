use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use event_model::{ResourceAggregate, ResourceValues};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::{
    collections::BTreeSet,
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

use crate::{
    application_credentials::ApplicationCredentialScope,
    auth::{SessionScope, UserPrincipal, UserSessionAuthenticator},
};

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
    let (detail, rollup): (i32, i32) = sqlx::query_as("SELECT COALESCE(p.resource_detail_retention_days,o.resource_detail_retention_days),COALESCE(p.resource_rollup_retention_days,o.resource_rollup_retention_days) FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1 FOR UPDATE")
        .bind(project_id).fetch_one(&mut *tx).await?;
    let detail_before = now - Duration::days(i64::from(detail));
    let rollup_before = now - Duration::days(i64::from(rollup));
    sqlx::query("UPDATE projects SET resource_closed_before=GREATEST(resource_closed_before,$2),resource_rollup_expired_before=GREATEST(resource_rollup_expired_before,$3) WHERE id=$1")
        .bind(project_id).bind(detail_before).bind(rollup_before).execute(&mut *tx).await?;
    let contributions = sqlx::query("DELETE FROM resource_contributions WHERE (organization_id,application_id,id) IN (SELECT organization_id,application_id,id FROM resource_contributions WHERE project_id=$1 AND interval_end<$2 ORDER BY interval_end,id LIMIT $3 FOR UPDATE SKIP LOCKED)")
        .bind(project_id).bind(detail_before).bind(limit.clamp(1,1_000)).execute(&mut *tx).await?.rows_affected();
    let remaining = limit
        .clamp(1, 1_000)
        .saturating_sub(i64::try_from(contributions).unwrap_or(i64::MAX));
    let rollups = if remaining == 0 {
        0
    } else {
        sqlx::query("DELETE FROM resource_rollup_points WHERE (application_id,release_key,container_name,bucket_start,step_seconds,metric) IN (SELECT application_id,release_key,container_name,bucket_start,step_seconds,metric FROM resource_rollup_points WHERE project_id=$1 AND ((step_seconds=60 AND bucket_start<$2) OR bucket_start<$3) ORDER BY bucket_start,application_id LIMIT $4 FOR UPDATE SKIP LOCKED)")
            .bind(project_id).bind(detail_before).bind(rollup_before).bind(remaining)
            .execute(&mut *tx).await?.rows_affected()
    };
    tx.commit().await?;
    Ok(contributions.saturating_add(rollups))
}

#[derive(Clone, Debug)]
struct ResourceState {
    pool: PgPool,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ResourceState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/resources",
            get(resource_history),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/resource-comparison",
            get(resource_comparison),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ResourceError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ResourceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl IntoResponse for ResourceError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid or missing bearer credential".into(),
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "application or release not found".into(),
            ),
            Self::Database(error) => {
                tracing::error!(%error, "resource API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
        };
        (
            status,
            Json(serde_json::json!({"error": code, "message": message})),
        )
            .into_response()
    }
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
    let days: i32 = sqlx::query_scalar("SELECT COALESCE(p.resource_detail_retention_days,o.resource_detail_retention_days) FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1")
        .bind(project_id).fetch_one(pool).await?;
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
    sqlx::query_scalar("SELECT id FROM releases WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=$4 AND identity_digest=$5")
        .bind(application.organization_id).bind(application.project_id).bind(application.application_id)
        .bind(i16::try_from(identity.version).unwrap_or(i16::MAX)).bind(identity.digest.as_slice())
        .fetch_optional(pool).await
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
    let result = sqlx::query("INSERT INTO resource_contributions(id,organization_id,project_id,application_id,cluster_id,agent_id,release_id,schema_version,interval_start,interval_end,covered_usec,sample_count,contributing_containers,namespace,workload_uid,workload_kind,workload_name,container_name,node_name,unavailable_sources,values) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(organization_id,application_id,id) DO NOTHING")
        .bind(aggregate.id).bind(application.organization_id).bind(application.project_id)
        .bind(application.application_id).bind(scope.cluster_id).bind(agent_id).bind(release_id)
        .bind(i16::try_from(aggregate.schema_version).unwrap_or(i16::MAX))
        .bind(aggregate.interval_start).bind(aggregate.interval_end)
        .bind(i64::try_from(aggregate.covered_usec).unwrap_or(i64::MAX))
        .bind(i32::try_from(aggregate.sample_count).unwrap_or(i32::MAX))
        .bind(i32::try_from(aggregate.contributing_containers).unwrap_or(i32::MAX))
        .bind(&aggregate.namespace).bind(&aggregate.workload_uid).bind(&aggregate.workload_kind)
        .bind(&aggregate.workload_name).bind(&aggregate.container_name).bind(&aggregate.node_name)
        .bind(i64::try_from(aggregate.unavailable_sources).unwrap_or(i64::MAX)).bind(values)
        .execute(&mut **transaction).await?;
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
    sqlx::query("INSERT INTO resource_rollup_points(organization_id,project_id,application_id,release_key,release_id,container_name,bucket_start,step_seconds,metric,unit,value_sum,value_min,value_max,value_weight,limit_value,covered_usec,expected_usec,sample_count,contributor_count,observed_replicas,ready_replicas,unavailable_sources) VALUES($1,$2,$3,$4,$5,$6,to_timestamp(floor(extract(epoch from $7::timestamptz)/$8)*$8),$8,$9,$10,$11*$12,$11,$11,$12,$13,$14,$15,$16,1,$17,$18,$19) ON CONFLICT(application_id,release_key,container_name,bucket_start,step_seconds,metric) DO UPDATE SET value_sum=resource_rollup_points.value_sum+EXCLUDED.value_sum,value_min=LEAST(resource_rollup_points.value_min,EXCLUDED.value_min),value_max=GREATEST(resource_rollup_points.value_max,EXCLUDED.value_max),value_weight=resource_rollup_points.value_weight+EXCLUDED.value_weight,limit_value=COALESCE(EXCLUDED.limit_value,resource_rollup_points.limit_value),covered_usec=resource_rollup_points.covered_usec+EXCLUDED.covered_usec,expected_usec=resource_rollup_points.expected_usec+EXCLUDED.expected_usec,sample_count=resource_rollup_points.sample_count+EXCLUDED.sample_count,contributor_count=resource_rollup_points.contributor_count+1,observed_replicas=GREATEST(resource_rollup_points.observed_replicas,EXCLUDED.observed_replicas),ready_replicas=GREATEST(resource_rollup_points.ready_replicas,EXCLUDED.ready_replicas),unavailable_sources=resource_rollup_points.unavailable_sources|EXCLUDED.unavailable_sources,updated_at=now()")
        .bind(application.organization_id).bind(application.project_id).bind(application.application_id)
        .bind(release_key).bind(release_id).bind(&aggregate.container_name).bind(aggregate.interval_start)
        .bind(step).bind(metric.name).bind(metric.unit).bind(metric.value)
        .bind(u64_as_f64(aggregate.covered_usec)).bind(metric.limit)
        .bind(i64::try_from(aggregate.covered_usec).unwrap_or(i64::MAX)).bind(expected)
        .bind(i64::from(aggregate.sample_count)).bind(i32::try_from(aggregate.contributing_containers).unwrap_or(i32::MAX))
        .bind(i32::try_from(aggregate.ready_containers).unwrap_or(i32::MAX))
        .bind(i64::try_from(aggregate.unavailable_sources).unwrap_or(i64::MAX))
        .execute(&mut **transaction).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
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
struct HistoryResponse {
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

async fn resource_history(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, ResourceError> {
    let principal = principal(&headers, &state).await?;
    ensure_application(
        &state.pool,
        principal.organization_id,
        project_id,
        application_id,
    )
    .await?;
    let step = validate_history_query(&query)?;
    let rows = sqlx::query_as::<_, HistoryRow>("SELECT p.bucket_start,p.unit,p.value_sum/p.value_weight value,p.limit_value,p.covered_usec,p.expected_usec,p.sample_count,p.contributor_count,ceil(p.covered_usec::numeric/($5::bigint*1000000))::int observed_replicas,ceil(p.covered_usec::numeric/($5::bigint*1000000))::int ready_replicas,p.unavailable_sources,p.release_id,CASE WHEN r.id IS NULL THEN NULL ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name,p.container_name FROM resource_rollup_points p JOIN applications a ON a.id=p.application_id LEFT JOIN releases r ON r.id=p.release_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND p.metric=$4 AND p.step_seconds=$5 AND p.bucket_start >= $6 AND p.bucket_start < $7 AND ($8::uuid IS NULL OR p.release_id=$8) AND ($9::text IS NULL OR p.container_name=$9) ORDER BY p.bucket_start,p.container_name,p.release_key LIMIT 45360")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(&query.metric)
        .bind(step).bind(query.from).bind(query.to).bind(query.release_id).bind(&query.container)
        .fetch_all(&state.pool).await?;
    Ok(Json(history_response(query, step, rows)))
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

fn validate_history_query(query: &HistoryQuery) -> Result<i32, ResourceError> {
    if !RESOURCE_METRICS.contains(&query.metric.as_str()) {
        return Err(ResourceError::Invalid("unsupported resource metric".into()));
    }
    if query.from >= query.to
        || query.from.second() != 0
        || query.from.nanosecond() != 0
        || query.to.second() != 0
        || query.to.nanosecond() != 0
    {
        return Err(ResourceError::Invalid(
            "from and to must be aligned UTC minute bounds with from before to".into(),
        ));
    }
    if query
        .container
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(ResourceError::Invalid(
            "container must contain 1..=256 bytes".into(),
        ));
    }
    if !matches!(query.mode.as_str(), "total" | "per_ready_replica") {
        return Err(ResourceError::Invalid(
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
        "minute" | "hour" => Err(ResourceError::Invalid(
            "resource history range exceeds the selected step bound or is not hour aligned".into(),
        )),
        _ => Err(ResourceError::Invalid("step must be minute or hour".into())),
    }
}

async fn principal(
    headers: &HeaderMap,
    state: &ResourceState,
) -> Result<UserPrincipal, ResourceError> {
    state
        .authenticator
        .authenticate_headers(headers)
        .await?
        .ok_or(ResourceError::Unauthorized)
}

async fn ensure_application(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ResourceError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)")
        .bind(organization_id).bind(project_id).bind(application_id).fetch_one(pool).await?;
    if exists {
        Ok(())
    } else {
        Err(ResourceError::NotFound)
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
struct ComparisonQuery {
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
struct ComparisonResponse {
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

async fn resource_comparison(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<ComparisonQuery>,
) -> Result<Json<ComparisonResponse>, ResourceError> {
    let principal = principal(&headers, &state).await?;
    ensure_application(
        &state.pool,
        principal.organization_id,
        project_id,
        application_id,
    )
    .await?;
    let target = fetch_episode(
        &state.pool,
        principal.organization_id,
        project_id,
        application_id,
        target_id,
    )
    .await?
    .ok_or(ResourceError::NotFound)?;
    let (baseline, source) = fetch_baseline_episode(
        &state.pool,
        principal.organization_id,
        project_id,
        application_id,
        &target,
        query.baseline_id,
    )
    .await?;
    Ok(Json(
        build_comparison(
            &state.pool,
            principal.organization_id,
            project_id,
            application_id,
            target,
            baseline,
            source,
        )
        .await?,
    ))
}

async fn fetch_episode(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Uuid,
) -> Result<Option<EpisodeWindowSource>, sqlx::Error> {
    sqlx::query_as("SELECT e.id episode_id,e.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,e.first_observed_at,e.first_ready_at FROM deployment_episodes e JOIN releases r ON r.id=e.release_id JOIN applications a ON a.id=e.application_id WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3 AND e.release_id=$4 ORDER BY e.first_observed_at DESC,e.id DESC LIMIT 1")
        .bind(organization_id).bind(project_id).bind(application_id).bind(release_id).fetch_optional(pool).await
}

async fn fetch_baseline_episode(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    target: &EpisodeWindowSource,
    explicit: Option<Uuid>,
) -> Result<(Option<EpisodeWindowSource>, &'static str), ResourceError> {
    if let Some(release_id) = explicit {
        let episode = fetch_episode(
            pool,
            organization_id,
            project_id,
            application_id,
            release_id,
        )
        .await?
        .ok_or(ResourceError::NotFound)?;
        return Ok((Some(episode), "explicit"));
    }
    let rows = sqlx::query_as::<_, EpisodeWindowSource>("SELECT p.id episode_id,p.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,p.first_observed_at,p.first_ready_at FROM deployment_episode_predecessors x JOIN deployment_episodes p ON p.id=x.predecessor_episode_id JOIN releases r ON r.id=p.release_id JOIN applications a ON a.id=p.application_id WHERE x.episode_id=$1 AND p.organization_id=$2 AND p.project_id=$3 AND p.application_id=$4 ORDER BY x.observed_at DESC,p.id DESC LIMIT 2")
        .bind(target.episode_id).bind(organization_id).bind(project_id).bind(application_id).fetch_all(pool).await?;
    let source = match rows.len() {
        0 => "none",
        1 => "transition",
        _ => "concurrent_transition_fallback",
    };
    Ok((rows.into_iter().next(), source))
}

pub async fn refresh_project_findings(pool: &PgPool, organization_id: Uuid, project_id: Uuid) {
    let targets = sqlx::query_as::<_, ProjectEvaluationTarget>("SELECT DISTINCT ON(e.application_id) e.organization_id,e.application_id,e.id episode_id,e.release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,e.first_observed_at,e.first_ready_at FROM deployment_episodes e JOIN releases r ON r.id=e.release_id JOIN applications a ON a.id=e.application_id WHERE e.organization_id=$1 AND e.project_id=$2 AND e.first_ready_at IS NOT NULL ORDER BY e.application_id,e.first_observed_at DESC,e.id DESC LIMIT 64")
        .bind(organization_id).bind(project_id).fetch_all(pool).await;
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
) -> Result<ComparisonResponse, ResourceError> {
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
    sqlx::query("UPDATE release_resource_findings SET clean_evaluations=LEAST(clean_evaluations+1,2),closed_at=CASE WHEN clean_evaluations+1>=2 THEN now() ELSE NULL END,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND target_release_id=$4 AND closed_at IS NULL AND NOT(id=ANY($5))")
        .bind(organization_id).bind(project_id).bind(application_id).bind(target_release_id)
        .bind(&active_ids)
        .execute(&mut *tx).await?;
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
        sqlx::query("INSERT INTO release_resource_findings(id,organization_id,project_id,application_id,target_release_id,baseline_release_id,reason_code,priority,metric,rule_version,facts,opened_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(application_id,target_release_id,reason_code,metric,rule_version) DO UPDATE SET facts=EXCLUDED.facts,priority=EXCLUDED.priority,clean_evaluations=0,closed_at=NULL,updated_at=now()")
            .bind(finding.id).bind(organization_id).bind(project_id).bind(application_id)
            .bind(target_release_id).bind(baseline_release_id).bind(finding.reason_code)
            .bind(finding.priority).bind(&finding.metric).bind(i16::try_from(finding.rule_version).unwrap_or(i16::MAX))
            .bind(facts).bind(target_window.from).execute(&mut *tx).await?;
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
    sqlx::query_as("SELECT metric,min(unit) unit,sum(value_sum)/sum(value_weight) value,max(limit_value) limit_value,sum(covered_usec)::bigint covered_usec,sum(expected_usec)::bigint expected_usec,sum(sample_count)::bigint sample_count,sum(contributor_count)::bigint contributor_count,ceil(sum(covered_usec)::numeric/1800000000)::int observed_replicas,ceil(sum(covered_usec)::numeric/1800000000)::int ready_replicas,count(DISTINCT bucket_start)::bigint bucket_count FROM resource_rollup_points WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND release_id=$4 AND step_seconds=60 AND bucket_start >= $5 AND bucket_start < $6 GROUP BY metric ORDER BY metric")
        .bind(organization_id).bind(project_id).bind(application_id).bind(release_id).bind(from).bind(to).fetch_all(pool).await
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
    let buckets = sqlx::query_as::<_, MetricBucket>("SELECT metric,bucket_start,sum(value_sum)/sum(value_weight) value FROM resource_rollup_points WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND release_id=$4 AND step_seconds=60 AND bucket_start >= $5 AND bucket_start < $6 GROUP BY metric,bucket_start HAVING sum(covered_usec)::double precision/sum(expected_usec)>=0.8 ORDER BY metric,bucket_start")
        .bind(organization_id).bind(project_id).bind(application_id).bind(release_id)
        .bind(from).bind(to).fetch_all(pool).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
