use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use protocol::v1::{DropCounters, Heartbeat, ResourceCounters};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    application_credentials::ApplicationCredentialScope,
    auth::UserSessionAuthenticator,
    web_api::{RequestId, error_response},
};

pub const FRESHNESS_SECONDS: i64 = 300;
pub const HEALTH_RETENTION_HOURS: i64 = 25;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_CHARS: usize = 128;
const PAGE_LIMIT: i64 = 20;
const COUNTER_SKEW_HOURS: i64 = 24;
const DIAGNOSTIC_COUNT: usize = 9;

#[derive(Clone, Debug)]
struct HealthState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/agent-health",
            get(application_agent_health),
        )
        .with_state(HealthState {
            auth: UserSessionAuthenticator::new(pool.clone()),
            pool,
        })
}

#[derive(Debug)]
struct HealthError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    request_id: RequestId,
}

impl HealthError {
    fn new(status: StatusCode, code: &'static str, message: &'static str, id: &RequestId) -> Self {
        Self {
            status,
            code,
            message,
            request_id: id.clone(),
        }
    }
    fn invalid(message: &'static str, id: &RequestId) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message, id)
    }
    fn database(_error: &sqlx::Error, id: &RequestId) -> Self {
        tracing::error!(request_id=%id.0, "agent health database error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal server error",
            id,
        )
    }
}

impl IntoResponse for HealthError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message, &self.request_id)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
enum HealthRange {
    #[serde(rename = "1h")]
    #[default]
    OneHour,
    #[serde(rename = "6h")]
    SixHours,
    #[serde(rename = "24h")]
    TwentyFourHours,
}

impl HealthRange {
    fn hours(self) -> i64 {
        match self {
            Self::OneHour => 1,
            Self::SixHours => 6,
            Self::TwentyFourHours => 24,
        }
    }
    fn step_minutes(self) -> i64 {
        match self {
            Self::OneHour => 1,
            Self::SixHours => 5,
            Self::TwentyFourHours => 15,
        }
    }
}

#[derive(Debug, Deserialize)]
struct HealthQuery {
    #[serde(default)]
    range: HealthRange,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HealthCursor {
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    authenticated_at: DateTime<Utc>,
    agent_id: Uuid,
}

#[derive(Debug, FromRow)]
struct AgentRow {
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    agent_id: Uuid,
    cluster_id: Uuid,
    cluster_name: String,
    node_name: String,
    agent_version: String,
    architecture: Option<String>,
    kernel_release: Option<String>,
    capabilities: serde_json::Value,
    authenticated_at: DateTime<Utc>,
    history_started_at: DateTime<Utc>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    first_event_at: Option<DateTime<Utc>>,
    last_event_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct HealthPage {
    range: HealthRange,
    step_seconds: i64,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    freshness_seconds: i64,
    items: Vec<AgentHealth>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct AgentHealth {
    agent_id: Uuid,
    cluster_id: Uuid,
    cluster_name: String,
    node_name: String,
    agent_version: String,
    architecture: Option<String>,
    kernel_release: Option<String>,
    capabilities: Vec<String>,
    stream_state: &'static str,
    last_signal_at: Option<DateTime<Utc>>,
    first_event_at: Option<DateTime<Utc>>,
    last_event_at: Option<DateTime<Utc>>,
    coverage: HistoryCoverage,
    node_diagnostics: Vec<DiagnosticDelta>,
    timeline: Vec<TimelinePoint>,
}

#[derive(Debug, Serialize)]
struct HistoryCoverage {
    available_from: DateTime<Utc>,
    complete: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DiagnosticDelta {
    category: &'static str,
    delta: i64,
}

#[derive(Debug, Serialize)]
struct TimelinePoint {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    status: &'static str,
    diagnostics: Vec<DiagnosticDelta>,
    reset: bool,
}

#[derive(Debug, FromRow)]
struct BucketRow {
    bucket_at: DateTime<Utc>,
    received: bool,
    diagnostics_available: bool,
    reset: bool,
    dropped: i64,
    rate_limited: i64,
    decode_failed: i64,
    attribution_failed: i64,
    capacity: i64,
    kernel_lost: i64,
    correlation: i64,
    delivery_retry: i64,
    unsupported: i64,
}

pub fn validate_capabilities(values: &[String]) -> Result<Vec<String>, &'static str> {
    if values.len() > MAX_CAPABILITIES {
        return Err("hello has too many capabilities");
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        if value.trim() != value
            || value.is_empty()
            || value.chars().count() > MAX_CAPABILITY_CHARS
            || value.chars().any(char::is_control)
        {
            return Err("hello contains an invalid capability");
        }
        if !result.contains(value) {
            result.push(value.clone());
        }
    }
    Ok(result)
}

pub async fn register_application_agent(
    pool: &PgPool,
    scope: ApplicationCredentialScope,
    cluster_id: Uuid,
    agent_id: Uuid,
    capabilities: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO application_agents(organization_id,project_id,application_id,cluster_id,agent_id,capabilities) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id,project_id,application_id,agent_id) DO UPDATE SET cluster_id=EXCLUDED.cluster_id,capabilities=EXCLUDED.capabilities,authenticated_at=now(),last_session_ended_at=NULL")
        .bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id)
        .bind(cluster_id).bind(agent_id).bind(serde_json::json!(capabilities))
        .execute(pool).await?;
    Ok(())
}

pub async fn record_hello_counters(
    pool: &PgPool,
    organization_id: Uuid,
    cluster_id: Uuid,
    agent_id: Uuid,
    drop_counters: Option<DropCounters>,
    resource_counters: Option<ResourceCounters>,
) -> Result<(), sqlx::Error> {
    if drop_counters.is_none() && resource_counters.is_none() {
        return Ok(());
    }
    let received_at = Utc::now();
    let heartbeat = Heartbeat {
        sent_at_unix_nanos: received_at.timestamp_nanos_opt().unwrap_or_default(),
        drop_counters,
        resource_counters,
    };
    let mut tx = pool.begin().await?;
    record_diagnostics(
        &mut tx,
        organization_id,
        cluster_id,
        agent_id,
        received_at,
        &heartbeat,
        received_at,
    )
    .await?;
    tx.commit().await
}

pub async fn record_heartbeat(
    pool: &PgPool,
    scope: ApplicationCredentialScope,
    cluster_id: Uuid,
    agent_id: Uuid,
    heartbeat: &Heartbeat,
) -> Result<(), &'static str> {
    let received_at = Utc::now();
    let sent_at = DateTime::from_timestamp_nanos(heartbeat.sent_at_unix_nanos);
    if (received_at - sent_at).num_hours().unsigned_abs() > COUNTER_SKEW_HOURS as u64 {
        return Err("heartbeat timestamp is outside the accepted window");
    }
    let mut tx = pool.begin().await.map_err(|_| "database error")?;
    record_signal(&mut tx, scope, agent_id, received_at)
        .await
        .map_err(|_| "database error")?;
    record_diagnostics(
        &mut tx,
        scope.organization_id,
        cluster_id,
        agent_id,
        sent_at,
        heartbeat,
        received_at,
    )
    .await
    .map_err(|_| "database error")?;
    cleanup(&mut tx, received_at)
        .await
        .map_err(|_| "database error")?;
    tx.commit().await.map_err(|_| "database error")?;
    Ok(())
}

async fn record_signal(
    tx: &mut Transaction<'_, Postgres>,
    scope: ApplicationCredentialScope,
    agent_id: Uuid,
    received_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let bucket = minute(received_at);
    sqlx::query("UPDATE application_agents SET last_heartbeat_at=$5 WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4")
        .bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id).bind(agent_id).bind(received_at)
        .execute(&mut **tx).await?;
    sqlx::query("INSERT INTO application_agent_signal_buckets(organization_id,project_id,application_id,agent_id,bucket_at,first_received_at,last_received_at) VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(organization_id,project_id,application_id,agent_id,bucket_at) DO UPDATE SET received_count=LEAST(application_agent_signal_buckets.received_count+1,120),last_received_at=GREATEST(application_agent_signal_buckets.last_received_at,EXCLUDED.last_received_at)")
        .bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id).bind(agent_id).bind(bucket).bind(received_at)
        .execute(&mut **tx).await?;
    Ok(())
}

async fn record_diagnostics(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cluster_id: Uuid,
    agent_id: Uuid,
    sent_at: DateTime<Utc>,
    heartbeat: &Heartbeat,
    received_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let current = categorized(
        heartbeat.drop_counters.as_ref(),
        heartbeat.resource_counters.as_ref(),
    );
    let Some(current) = current else {
        return Ok(());
    };
    let previous: Option<(DateTime<Utc>, serde_json::Value)> = sqlx::query_as("SELECT sent_at,drop_counters FROM agent_counter_baselines WHERE organization_id=$1 AND cluster_id=$2 AND agent_id=$3 FOR UPDATE")
        .bind(organization_id).bind(cluster_id).bind(agent_id).fetch_optional(&mut **tx).await?;
    if previous.as_ref().is_some_and(|(at, _)| sent_at <= *at) {
        return Ok(());
    }
    let previous_values = previous
        .as_ref()
        .and_then(|(_, value)| serde_json::from_value::<Vec<u64>>(value.clone()).ok());
    let reset = previous_values
        .as_ref()
        .is_some_and(|values| values.iter().zip(&current).any(|(old, new)| new < old));
    let deltas = previous_values
        .as_ref()
        .filter(|_| !reset)
        .map(|old| deltas(old, &current));
    sqlx::query("INSERT INTO agent_counter_baselines(organization_id,cluster_id,agent_id,sent_at,drop_counters) VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,cluster_id,agent_id) DO UPDATE SET sent_at=EXCLUDED.sent_at,drop_counters=EXCLUDED.drop_counters")
        .bind(organization_id).bind(cluster_id).bind(agent_id).bind(sent_at).bind(serde_json::json!(current))
        .execute(&mut **tx).await?;
    upsert_diagnostic_bucket(
        tx,
        organization_id,
        cluster_id,
        agent_id,
        minute(received_at),
        reset,
        deltas,
    )
    .await
}

async fn upsert_diagnostic_bucket(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cluster_id: Uuid,
    agent_id: Uuid,
    bucket: DateTime<Utc>,
    reset: bool,
    deltas: Option<[i64; DIAGNOSTIC_COUNT]>,
) -> Result<(), sqlx::Error> {
    let d = deltas.unwrap_or([0; DIAGNOSTIC_COUNT]);
    sqlx::query("INSERT INTO agent_diagnostic_buckets(organization_id,cluster_id,agent_id,bucket_at,diagnostics_available,reset,dropped,rate_limited,decode_failed,attribution_failed,capacity,kernel_lost,correlation,delivery_retry,unsupported) VALUES($1,$2,$3,$4,TRUE,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(organization_id,cluster_id,agent_id,bucket_at) DO UPDATE SET diagnostics_available=TRUE,reset=agent_diagnostic_buckets.reset OR EXCLUDED.reset,dropped=agent_diagnostic_buckets.dropped+EXCLUDED.dropped,rate_limited=agent_diagnostic_buckets.rate_limited+EXCLUDED.rate_limited,decode_failed=agent_diagnostic_buckets.decode_failed+EXCLUDED.decode_failed,attribution_failed=agent_diagnostic_buckets.attribution_failed+EXCLUDED.attribution_failed,capacity=agent_diagnostic_buckets.capacity+EXCLUDED.capacity,kernel_lost=agent_diagnostic_buckets.kernel_lost+EXCLUDED.kernel_lost,correlation=agent_diagnostic_buckets.correlation+EXCLUDED.correlation,delivery_retry=agent_diagnostic_buckets.delivery_retry+EXCLUDED.delivery_retry,unsupported=agent_diagnostic_buckets.unsupported+EXCLUDED.unsupported")
        .bind(organization_id).bind(cluster_id).bind(agent_id).bind(bucket).bind(reset)
        .bind(d[0]).bind(d[1]).bind(d[2]).bind(d[3]).bind(d[4]).bind(d[5]).bind(d[6]).bind(d[7]).bind(d[8])
        .execute(&mut **tx).await?;
    Ok(())
}

fn categorized(
    drop: Option<&DropCounters>,
    resource: Option<&ResourceCounters>,
) -> Option<Vec<u64>> {
    if drop.is_none() && resource.is_none() {
        return None;
    }
    let d = drop.copied().unwrap_or_default();
    let r = resource.copied().unwrap_or_default();
    Some(vec![
        d.release_evidence_dropped.saturating_add(r.queue_dropped),
        d.dns_rate_limited
            .saturating_add(d.inbound_rate_limited)
            .saturating_add(d.file_rate_limited)
            .saturating_add(d.exit_rate_limited),
        d.decode_failed
            .saturating_add(d.connect_decode_failed)
            .saturating_add(d.dns_packet_decode_failed)
            .saturating_add(d.inbound_decode_failed)
            .saturating_add(d.file_decode_failed)
            .saturating_add(d.exit_decode_failed)
            .saturating_add(r.parse_failed),
        d.unattributed
            .saturating_add(d.dns_attribution_failed)
            .saturating_add(d.inbound_attribution_failed)
            .saturating_add(d.file_attribution_failed)
            .saturating_add(d.exit_attribution_failed)
            .saturating_add(d.lifecycle_attribution_failed)
            .saturating_add(r.attribution_failed),
        d.capacity
            .saturating_add(d.connect_correlation_capacity)
            .saturating_add(d.dns_correlation_capacity)
            .saturating_add(d.dns_capacity)
            .saturating_add(d.file_correlation_capacity)
            .saturating_add(d.file_aggregation_capacity)
            .saturating_add(d.lifecycle_capacity)
            .saturating_add(r.state_capacity_dropped)
            .saturating_add(r.aggregate_capacity_dropped),
        d.kernel_lost
            .saturating_add(d.connect_kernel_lost)
            .saturating_add(d.dns_kernel_lost)
            .saturating_add(d.inbound_kernel_lost)
            .saturating_add(d.file_kernel_lost)
            .saturating_add(d.exit_kernel_lost),
        d.connect_correlation_miss
            .saturating_add(d.dns_correlation_miss)
            .saturating_add(d.inbound_correlation_miss)
            .saturating_add(d.file_correlation_miss)
            .saturating_add(d.exit_correlation_before_observation)
            .saturating_add(d.exit_correlation_evicted)
            .saturating_add(d.exit_correlation_generation_mismatch)
            .saturating_add(d.exit_correlation_container_mismatch),
        r.retried,
        d.unsupported
            .saturating_add(d.connect_unsupported_family)
            .saturating_add(d.dns_unsupported_record)
            .saturating_add(d.dns_kernel_unsupported_framing)
            .saturating_add(d.inbound_unsupported_family)
            .saturating_add(d.file_unsupported_object)
            .saturating_add(r.unsupported_sources),
    ])
}

fn deltas(old: &[u64], new: &[u64]) -> [i64; DIAGNOSTIC_COUNT] {
    std::array::from_fn(|index| {
        i64::try_from(new[index].saturating_sub(old[index])).unwrap_or(i64::MAX)
    })
}

async fn cleanup(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let cutoff = now - Duration::hours(HEALTH_RETENTION_HOURS);
    for table in [
        "application_agent_signal_buckets",
        "agent_diagnostic_buckets",
    ] {
        let query = format!(
            "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE bucket_at<$1 ORDER BY bucket_at LIMIT 500)"
        );
        sqlx::query(&query).bind(cutoff).execute(&mut **tx).await?;
    }
    Ok(())
}

pub async fn end_session(
    pool: &PgPool,
    session_id: Uuid,
    scope: ApplicationCredentialScope,
    agent_id: Uuid,
) {
    let now = Utc::now();
    if let Err(error) = sqlx::query(
        "UPDATE agent_sessions SET disconnected_at=$2 WHERE id=$1 AND disconnected_at IS NULL",
    )
    .bind(session_id)
    .bind(now)
    .execute(pool)
    .await
    {
        tracing::warn!(%agent_id, %error, "failed to record agent session termination");
    }
    if let Err(error) = sqlx::query("UPDATE application_agents SET last_session_ended_at=$5 WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4")
        .bind(scope.organization_id).bind(scope.project_id).bind(scope.application_id).bind(agent_id).bind(now).execute(pool).await
    { tracing::warn!(%agent_id, %error, "failed to record Application stream termination"); }
}

async fn application_agent_health(
    State(state): State<HealthState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<HealthQuery>,
) -> Result<Json<HealthPage>, HealthError> {
    let organization_id =
        authorize_application(&state, &headers, project_id, application_id, &request_id).await?;
    let limit = query.limit.unwrap_or(PAGE_LIMIT);
    if !(1..=PAGE_LIMIT).contains(&limit) {
        return Err(HealthError::invalid(
            "limit must be between 1 and 20",
            &request_id,
        ));
    }
    let cursor = query
        .cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()
        .map_err(|m| HealthError::invalid(m, &request_id))?;
    if cursor.as_ref().is_some_and(|c| {
        c.organization_id != organization_id
            || c.project_id != project_id
            || c.application_id != application_id
    }) {
        return Err(HealthError::invalid(
            "cursor is outside this scope",
            &request_id,
        ));
    }
    if let Some(cursor) = &cursor {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM application_agents WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 AND authenticated_at=$5)")
            .bind(organization_id).bind(project_id).bind(application_id)
            .bind(cursor.agent_id).bind(cursor.authenticated_at).fetch_one(&state.pool).await
            .map_err(|e| HealthError::database(&e, &request_id))?;
        if !valid {
            return Err(HealthError::invalid(
                "cursor is outside this scope",
                &request_id,
            ));
        }
    }
    let now = window_end(Utc::now(), query.range.step_minutes());
    let start = now - Duration::hours(query.range.hours());
    let mut rows = fetch_agents(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        cursor.as_ref(),
        limit,
    )
    .await
    .map_err(|e| HealthError::database(&e, &request_id))?;
    let has_more = rows.len() > usize::try_from(limit).unwrap_or_default();
    if has_more {
        rows.pop();
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|row| encode_cursor(organization_id, project_id, application_id, row))
            .transpose()
            .map_err(|m| HealthError::invalid(m, &request_id))?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(
            build_agent_health(&state.pool, row, query.range, start, now)
                .await
                .map_err(|e| HealthError::database(&e, &request_id))?,
        );
    }
    Ok(Json(HealthPage {
        range: query.range,
        step_seconds: query.range.step_minutes() * 60,
        window_start: start,
        window_end: now,
        freshness_seconds: FRESHNESS_SECONDS,
        items,
        next_cursor,
    }))
}

async fn authorize_application(
    state: &HealthState,
    headers: &HeaderMap,
    project_id: Uuid,
    application_id: Uuid,
    request_id: &RequestId,
) -> Result<Uuid, HealthError> {
    let principal = state
        .auth
        .authenticate_headers(headers)
        .await
        .map_err(|e| HealthError::database(&e, request_id))?
        .ok_or_else(|| {
            HealthError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid or missing bearer credential",
                request_id,
            )
        })?;
    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications a WHERE a.organization_id=$1 AND a.project_id=$2 AND a.id=$3 AND ($4 OR EXISTS(SELECT 1 FROM project_memberships m WHERE m.organization_id=$1 AND m.project_id=$2 AND m.user_id=$5)))")
        .bind(principal.organization_id).bind(project_id).bind(application_id)
        .bind(principal.role.inherits_project_access()).bind(principal.user_id)
        .fetch_one(&state.pool).await.map_err(|e| HealthError::database(&e, request_id))?;
    if !owned {
        return Err(HealthError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            request_id,
        ));
    }
    Ok(principal.organization_id)
}

async fn fetch_agents(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    cursor: Option<&HealthCursor>,
    limit: i64,
) -> Result<Vec<AgentRow>, sqlx::Error> {
    sqlx::query_as("SELECT aa.organization_id,aa.project_id,aa.application_id,aa.agent_id,aa.cluster_id,c.name cluster_name,a.node_name,a.agent_version,a.architecture,a.kernel_release,aa.capabilities,aa.authenticated_at,aa.history_started_at,aa.last_heartbeat_at,(SELECT min(e.observed_at) FROM runtime_events e WHERE e.organization_id=aa.organization_id AND e.project_id=aa.project_id AND e.application_id=aa.application_id AND e.agent_id=aa.agent_id) first_event_at,(SELECT max(e.observed_at) FROM runtime_events e WHERE e.organization_id=aa.organization_id AND e.project_id=aa.project_id AND e.application_id=aa.application_id AND e.agent_id=aa.agent_id) last_event_at FROM application_agents aa JOIN agents a ON a.organization_id=aa.organization_id AND a.cluster_id=aa.cluster_id AND a.id=aa.agent_id JOIN clusters c ON c.organization_id=aa.organization_id AND c.id=aa.cluster_id WHERE aa.organization_id=$1 AND aa.project_id=$2 AND aa.application_id=$3 AND ($4::timestamptz IS NULL OR (aa.authenticated_at,aa.agent_id)<($4,$5)) ORDER BY aa.authenticated_at DESC,aa.agent_id DESC LIMIT $6")
        .bind(organization_id).bind(project_id).bind(application_id)
        .bind(cursor.map(|c| c.authenticated_at)).bind(cursor.map(|c| c.agent_id)).bind(limit + 1)
        .fetch_all(pool).await
}

async fn build_agent_health(
    pool: &PgPool,
    row: AgentRow,
    range: HealthRange,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<AgentHealth, sqlx::Error> {
    let buckets = fetch_buckets(pool, &row, range, start, end).await?;
    let coverage_from = std::cmp::max(
        row.history_started_at,
        end - Duration::hours(HEALTH_RETENTION_HOURS),
    );
    let timeline = timeline(&buckets, start, end, range.step_minutes(), coverage_from);
    let node_diagnostics = sum_diagnostics(&buckets);
    let stream_state = match row.last_heartbeat_at {
        None => "authenticated",
        Some(last) if Utc::now() - last <= Duration::seconds(FRESHNESS_SECONDS) => "reporting",
        Some(_) => "stale",
    };
    let capabilities = serde_json::from_value(row.capabilities).unwrap_or_default();
    Ok(AgentHealth {
        agent_id: row.agent_id,
        cluster_id: row.cluster_id,
        cluster_name: row.cluster_name,
        node_name: row.node_name,
        agent_version: row.agent_version,
        architecture: row.architecture,
        kernel_release: row.kernel_release,
        capabilities,
        stream_state,
        last_signal_at: row.last_heartbeat_at,
        first_event_at: row.first_event_at,
        last_event_at: row.last_event_at,
        coverage: HistoryCoverage {
            available_from: coverage_from,
            complete: coverage_from <= start,
        },
        node_diagnostics,
        timeline,
    })
}

async fn fetch_buckets(
    pool: &PgPool,
    row: &AgentRow,
    range: HealthRange,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<BucketRow>, sqlx::Error> {
    let step = range.step_minutes();
    sqlx::query_as("WITH signals AS (SELECT date_bin(($6::text || ' minutes')::interval,bucket_at,'1970-01-01'::timestamptz) bucket_at,TRUE received FROM application_agent_signal_buckets WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND agent_id=$4 AND bucket_at >= $7 AND bucket_at < $8 GROUP BY 1), diagnostics AS (SELECT date_bin(($6::text || ' minutes')::interval,bucket_at,'1970-01-01'::timestamptz) bucket_at,bool_or(diagnostics_available) diagnostics_available,bool_or(reset) reset,sum(dropped)::bigint dropped,sum(rate_limited)::bigint rate_limited,sum(decode_failed)::bigint decode_failed,sum(attribution_failed)::bigint attribution_failed,sum(capacity)::bigint capacity,sum(kernel_lost)::bigint kernel_lost,sum(correlation)::bigint correlation,sum(delivery_retry)::bigint delivery_retry,sum(unsupported)::bigint unsupported FROM agent_diagnostic_buckets WHERE organization_id=$1 AND cluster_id=$5 AND agent_id=$4 AND bucket_at >= $7 AND bucket_at < $8 GROUP BY 1) SELECT COALESCE(s.bucket_at,d.bucket_at) bucket_at,COALESCE(s.received,FALSE) received,COALESCE(d.diagnostics_available,FALSE) diagnostics_available,COALESCE(d.reset,FALSE) reset,COALESCE(d.dropped,0) dropped,COALESCE(d.rate_limited,0) rate_limited,COALESCE(d.decode_failed,0) decode_failed,COALESCE(d.attribution_failed,0) attribution_failed,COALESCE(d.capacity,0) capacity,COALESCE(d.kernel_lost,0) kernel_lost,COALESCE(d.correlation,0) correlation,COALESCE(d.delivery_retry,0) delivery_retry,COALESCE(d.unsupported,0) unsupported FROM signals s FULL OUTER JOIN diagnostics d USING(bucket_at) ORDER BY bucket_at")
        .bind(row.organization_id).bind(row.project_id).bind(row.application_id).bind(row.agent_id)
        .bind(row.cluster_id).bind(step).bind(start).bind(end)
        .fetch_all(pool).await
}

fn timeline(
    rows: &[BucketRow],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step: i64,
    coverage: DateTime<Utc>,
) -> Vec<TimelinePoint> {
    let map: HashMap<_, _> = rows.iter().map(|row| (row.bucket_at, row)).collect();
    let mut points = Vec::new();
    let mut at = start;
    while at < end {
        let row = map.get(&at).copied();
        points.push(TimelinePoint {
            start: at,
            end: at + Duration::minutes(step),
            status: if at < coverage {
                "unavailable"
            } else if row.is_some_and(|r| r.received) {
                "received"
            } else {
                "missing"
            },
            diagnostics: row.map_or_else(Vec::new, diagnostics),
            reset: row.is_some_and(|r| r.reset),
        });
        at += Duration::minutes(step);
    }
    points
}

fn diagnostics(row: &BucketRow) -> Vec<DiagnosticDelta> {
    if !row.diagnostics_available {
        return Vec::new();
    }
    diagnostic_pairs(row)
        .into_iter()
        .filter(|(_, value)| *value > 0)
        .map(|(category, delta)| DiagnosticDelta { category, delta })
        .collect()
}

fn sum_diagnostics(rows: &[BucketRow]) -> Vec<DiagnosticDelta> {
    let mut sums = [0_i64; DIAGNOSTIC_COUNT];
    for row in rows {
        for (index, (_, value)) in diagnostic_pairs(row).into_iter().enumerate() {
            sums[index] = sums[index].saturating_add(value);
        }
    }
    DIAGNOSTIC_NAMES
        .into_iter()
        .zip(sums)
        .filter(|(_, value)| *value > 0)
        .map(|(category, delta)| DiagnosticDelta { category, delta })
        .collect()
}

const DIAGNOSTIC_NAMES: [&str; DIAGNOSTIC_COUNT] = [
    "dropped",
    "rate_limited",
    "decode_failed",
    "attribution_failed",
    "capacity",
    "kernel_lost",
    "correlation",
    "delivery_retry",
    "unsupported",
];

fn diagnostic_pairs(row: &BucketRow) -> [(&'static str, i64); DIAGNOSTIC_COUNT] {
    [
        (DIAGNOSTIC_NAMES[0], row.dropped),
        (DIAGNOSTIC_NAMES[1], row.rate_limited),
        (DIAGNOSTIC_NAMES[2], row.decode_failed),
        (DIAGNOSTIC_NAMES[3], row.attribution_failed),
        (DIAGNOSTIC_NAMES[4], row.capacity),
        (DIAGNOSTIC_NAMES[5], row.kernel_lost),
        (DIAGNOSTIC_NAMES[6], row.correlation),
        (DIAGNOSTIC_NAMES[7], row.delivery_retry),
        (DIAGNOSTIC_NAMES[8], row.unsupported),
    ]
}

fn minute(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_second(0)
        .and_then(|v| v.with_nanosecond(0))
        .unwrap_or(value)
}

fn window_end(value: DateTime<Utc>, step_minutes: i64) -> DateTime<Utc> {
    let step_seconds = step_minutes * 60;
    let boundary = value.timestamp().div_euclid(step_seconds) * step_seconds + step_seconds;
    DateTime::from_timestamp(boundary, 0).unwrap_or(value)
}

fn encode_cursor(
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    row: &AgentRow,
) -> Result<String, &'static str> {
    serde_json::to_vec(&HealthCursor {
        organization_id,
        project_id,
        application_id,
        authenticated_at: row.authenticated_at,
        agent_id: row.agent_id,
    })
    .map(hex::encode)
    .map_err(|_| "cursor cannot be encoded")
}

fn decode_cursor(value: &str) -> Result<HealthCursor, &'static str> {
    if value.len() > 2048 {
        return Err("cursor is invalid");
    }
    serde_json::from_slice(&hex::decode(value).map_err(|_| "cursor is invalid")?)
        .map_err(|_| "cursor is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maximum_timeline(at: DateTime<Utc>) -> Vec<TimelinePoint> {
        (0..96)
            .map(|index| TimelinePoint {
                start: at + Duration::minutes(index * 15),
                end: at + Duration::minutes((index + 1) * 15),
                status: "received",
                diagnostics: DIAGNOSTIC_NAMES
                    .into_iter()
                    .map(|category| DiagnosticDelta {
                        category,
                        delta: i64::MAX,
                    })
                    .collect(),
                reset: true,
            })
            .collect()
    }

    fn maximum_agent(at: DateTime<Utc>) -> AgentHealth {
        AgentHealth {
            agent_id: Uuid::max(),
            cluster_id: Uuid::max(),
            cluster_name: "c".repeat(200),
            node_name: "n".repeat(253),
            agent_version: "v".repeat(200),
            architecture: Some("a".repeat(64)),
            kernel_release: Some("k".repeat(255)),
            capabilities: (0..MAX_CAPABILITIES)
                .map(|index| format!("{index:02}{}", "x".repeat(MAX_CAPABILITY_CHARS - 2)))
                .collect(),
            stream_state: "reporting",
            last_signal_at: Some(at),
            first_event_at: Some(at),
            last_event_at: Some(at),
            coverage: HistoryCoverage {
                available_from: at,
                complete: true,
            },
            node_diagnostics: DIAGNOSTIC_NAMES
                .into_iter()
                .map(|category| DiagnosticDelta {
                    category,
                    delta: i64::MAX,
                })
                .collect(),
            timeline: maximum_timeline(at),
        }
    }

    #[test]
    fn capability_validation_is_bounded() {
        assert!(validate_capabilities(&vec!["x".into(); MAX_CAPABILITIES + 1]).is_err());
        assert!(validate_capabilities(&[" x".into()]).is_err());
        assert_eq!(
            validate_capabilities(&["x/v1".into(), "x/v1".into()]).unwrap(),
            ["x/v1"]
        );
    }

    #[test]
    fn categorized_counters_are_closed_and_reset_safe() {
        let old = categorized(
            Some(&DropCounters {
                decode_failed: 5,
                ..Default::default()
            }),
            None,
        )
        .unwrap();
        let new = categorized(
            Some(&DropCounters {
                decode_failed: 8,
                ..Default::default()
            }),
            None,
        )
        .unwrap();
        assert_eq!(deltas(&old, &new)[2], 3);
        let reset = categorized(
            Some(&DropCounters {
                decode_failed: 2,
                ..Default::default()
            }),
            None,
        )
        .unwrap();
        assert!(
            reset
                .iter()
                .zip(&new)
                .any(|(next, previous)| next < previous)
        );
    }

    #[test]
    fn maximum_24_hour_page_is_bounded() {
        let end = DateTime::parse_from_rfc3339("2026-09-09T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let page = HealthPage {
            range: HealthRange::TwentyFourHours,
            step_seconds: 900,
            window_start: end - Duration::hours(24),
            window_end: end,
            freshness_seconds: FRESHNESS_SECONDS,
            items: (0..PAGE_LIMIT).map(|_| maximum_agent(end)).collect(),
            next_cursor: Some("f".repeat(512)),
        };
        let serialized = serde_json::to_vec(&page).unwrap();
        eprintln!("maximum 24h agent-health page: {} bytes", serialized.len());
        assert!(serialized.len() < 4 * 1024 * 1024);
    }

    #[test]
    fn history_windows_align_to_the_selected_step() {
        let now = DateTime::parse_from_rfc3339("2026-09-09T12:03:27Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(window_end(now, 1).to_rfc3339(), "2026-09-09T12:04:00+00:00");
        assert_eq!(window_end(now, 5).to_rfc3339(), "2026-09-09T12:05:00+00:00");
        assert_eq!(
            window_end(now, 15).to_rfc3339(),
            "2026-09-09T12:15:00+00:00"
        );
    }
}
