//! Tenant-scoped persistence of named-thread activity windows.
use super::releases::ApplicationScope;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

#[derive(Clone, Debug, FromRow)]
pub struct WindowRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub process_cgroup_id: i64,
    pub process_pid: i64,
    pub process_tgid: i64,
    pub process_command: String,
    pub process_generation: i64,
    pub observation_epoch: Uuid,
    pub start_observed: bool,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub created_count: i64,
    pub exited_count: i64,
    pub active_at_start: i64,
    pub active_at_end: i64,
    pub peak_active: i64,
    pub baseline_provenance: String,
    pub baseline_complete: bool,
    pub name_overflow: i64,
    pub names: Value,
    pub gaps: Value,
}
#[derive(Clone, Copy, Debug)]
pub struct WindowFilter {
    pub scope: ApplicationScope,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub generation: Option<i64>,
    pub epoch: Option<Uuid>,
}
#[derive(Debug)]
pub struct ThreadActivityRepository;
impl ThreadActivityRepository {
    pub async fn windows<'e, E: PgExecutor<'e>>(
        executor: E,
        filter: WindowFilter,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<WindowRow>, sqlx::Error> {
        sqlx::query_as("SELECT id,agent_id,process_cgroup_id,process_pid,process_tgid,process_command,process_generation,observation_epoch,start_observed,window_started_at,window_ended_at,created_count,exited_count,active_at_start,active_at_end,peak_active,baseline_provenance,baseline_complete,name_overflow,names,gaps FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND window_started_at >= $4 AND window_ended_at <= $5 AND observed_at >= COALESCE((SELECT runtime_closed_before FROM projects WHERE organization_id=$1 AND id=$2),'-infinity'::timestamptz) AND ($6::bigint IS NULL OR process_generation=$6) AND ($7::uuid IS NULL OR observation_epoch=$7) AND ($8::uuid IS NULL OR (window_started_at,id) < (SELECT window_started_at,id FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$8)) ORDER BY window_started_at DESC,id DESC LIMIT $9")
            .bind(filter.scope.organization_id).bind(filter.scope.project_id)
            .bind(filter.scope.application_id).bind(filter.from).bind(filter.to)
            .bind(filter.generation).bind(filter.epoch).bind(cursor).bind(fetch_limit)
            .fetch_all(executor).await
    }
    pub async fn cursor_exists<'e, E: PgExecutor<'e>>(
        executor: E,
        filter: WindowFilter,
        cursor: Uuid,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM thread_activity_windows WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND window_started_at >= $4 AND window_ended_at <= $5 AND observed_at >= COALESCE((SELECT runtime_closed_before FROM projects WHERE organization_id=$1 AND id=$2),'-infinity'::timestamptz) AND ($6::bigint IS NULL OR process_generation=$6) AND ($7::uuid IS NULL OR observation_epoch=$7) AND id=$8)")
            .bind(filter.scope.organization_id).bind(filter.scope.project_id)
            .bind(filter.scope.application_id).bind(filter.from).bind(filter.to)
            .bind(filter.generation).bind(filter.epoch).bind(cursor)
            .fetch_one(executor).await
    }
}

#[derive(Debug)]
pub struct NewWindow<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub agent_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub process_cgroup_id: i64,
    pub process_pid: i64,
    pub process_tgid: i64,
    pub process_command: &'a str,
    pub process_generation: i64,
    pub observation_epoch: Uuid,
    pub start_observed: bool,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub created_count: i64,
    pub exited_count: i64,
    pub active_at_start: i64,
    pub active_at_end: i64,
    pub peak_active: i64,
    pub baseline_provenance: &'a str,
    pub baseline_complete: bool,
    pub name_overflow: i64,
    pub names: Value,
    pub gaps: Value,
}
impl ThreadActivityRepository {
    pub async fn insert<'e, E: PgExecutor<'e>>(
        executor: E,
        input: NewWindow<'_>,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
        "INSERT INTO thread_activity_windows (id,organization_id,project_id,application_id,cluster_id,agent_id,observed_at,process_cgroup_id,process_pid,process_tgid,process_command,process_generation,observation_epoch,start_observed,window_started_at,window_ended_at,created_count,exited_count,active_at_start,active_at_end,peak_active,baseline_provenance,baseline_complete,name_overflow,names,gaps) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(input.id)
    .bind(input.organization_id)
    .bind(input.project_id)
    .bind(input.application_id)
    .bind(input.cluster_id)
    .bind(input.agent_id)
    .bind(input.observed_at)
    .bind(input.process_cgroup_id)
    .bind(input.process_pid)
    .bind(input.process_tgid)
    .bind(input.process_command)
    .bind(input.process_generation)
    .bind(input.observation_epoch)
    .bind(input.start_observed)
    .bind(input.window_started_at)
    .bind(input.window_ended_at)
    .bind(input.created_count)
    .bind(input.exited_count)
    .bind(input.active_at_start)
    .bind(input.active_at_end)
    .bind(input.peak_active)
    .bind(input.baseline_provenance)
    .bind(input.baseline_complete)
    .bind(input.name_overflow)
    .bind(input.names)
    .bind(input.gaps)
    .fetch_optional(executor)
    .await
    }
}
