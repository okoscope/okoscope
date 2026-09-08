use std::time::{Duration, Instant};

use axum::{
    body::{Body, to_bytes},
    http::{Request, header::COOKIE},
};
use chrono::{Duration as ChronoDuration, Utc};
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, NetworkAccept, NetworkAddressFamily,
    ProcessExec, ProcessIdentity, RuntimeEvent,
};
use server::{
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    ingestion::{IngestionContext, persist_batch},
    inventory_api, releases,
};
use tower::ServiceExt;
use uuid::Uuid;

const EVENT_COUNT: usize = 10_000;
const ITEM_COUNT: usize = 1_000;
const POD_COUNT: usize = 200;
const MAX_PROJECTION_DURATION: Duration = Duration::from_secs(60);
const MAX_LIST_QUERY_DURATION: Duration = Duration::from_secs(2);
const MAX_DETAIL_QUERY_DURATION: Duration = Duration::from_secs(2);
const MAX_AGGREGATE_QUERY_DURATION: Duration = Duration::from_secs(2);
const SAMPLE_COUNT: usize = 30;

fn config() -> BootstrapConfig {
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: "inventory-benchmark".into(),
        organization_name: "Inventory benchmark".into(),
        project_slug: "benchmark".into(),
        project_name: "Benchmark".into(),
        cluster_external_id: "benchmark".into(),
        cluster_name: "Benchmark".into(),
        application_slug: "benchmark".into(),
        application_name: "Benchmark".into(),
        cluster_credential: "cluster-inventory-benchmark".into(),
        api_credential: "api-inventory-benchmark".into(),
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL; run explicitly for acceptance"]
async fn inventory_projection_and_read_queries_meet_documented_acceptance_limits(
    pool: sqlx::PgPool,
) {
    let ids = bootstrap(&pool, &config()).await.unwrap();
    let baseline_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,'benchmark-baseline',now()-interval '1 hour'),($5,$2,$3,$4,'benchmark-target',now())")
        .bind(baseline_id).bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(target_id)
        .execute(&pool).await.unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'benchmark-node','benchmark')")
        .bind(agent_id).bind(ids.organization_id).bind(ids.cluster_id).execute(&pool).await.unwrap();
    let events: Vec<_> = (0..EVENT_COUNT)
        .map(|index| RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now()
                - ChronoDuration::minutes(i64::try_from(index).unwrap_or(i64::MAX)),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: ids.project_id,
                application_id: ids.application_id,
                node_name: "benchmark-node".into(),
                namespace: if index % 2 == 0 {
                    "production"
                } else {
                    "canary"
                }
                .into(),
                pod_uid: format!("pod-{}", index % POD_COUNT),
                pod_name: format!("benchmark-{}", index % POD_COUNT),
                container_id: format!("container-{index}"),
                container_name: "benchmark".into(),
                workload_uid: "benchmark-workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "benchmark".into(),
                release: Some(
                    if index % 2 == 0 {
                        "benchmark-baseline"
                    } else {
                        "benchmark-target"
                    }
                    .into(),
                ),
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: u64::try_from(index + 1).unwrap(),
                pid: u32::try_from(index + 1).unwrap(),
                tgid: u32::try_from(index + 1).unwrap(),
                command: "benchmark".into(),
            },
            payload: EventPayload::ProcessExec(ProcessExec {
                executable: format!("/app/bin/{}", index % ITEM_COUNT),
                parent_command: None,
            }),
        })
        .collect();

    let projection_started = Instant::now();
    let accepted = persist_batch(
        &pool,
        IngestionContext {
            scope: SessionScope {
                organization_id: ids.organization_id,
                cluster_id: ids.cluster_id,
            },
            agent_id,
        },
        &events,
    )
    .await
    .unwrap();
    let projection_duration = projection_started.elapsed();
    assert_eq!(usize::try_from(accepted).unwrap(), EVENT_COUNT);
    assert!(projection_duration <= MAX_PROJECTION_DURATION);

    let list_started = Instant::now();
    let listed: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT i.id,i.occurrence_count,(SELECT count(*) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) sighting_count FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=1 ORDER BY i.last_seen_at DESC,i.id DESC LIMIT 200",
    )
    .bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id)
    .fetch_all(&pool).await.unwrap();
    let list_duration = list_started.elapsed();
    assert_eq!(listed.len(), ITEM_COUNT.min(200));
    assert!(list_duration <= MAX_LIST_QUERY_DURATION);

    let detail_started = Instant::now();
    let detail_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_inventory_event_memberships WHERE item_id=$1",
    )
    .bind(listed[0].0)
    .fetch_one(&pool)
    .await
    .unwrap();
    let detail_duration = detail_started.elapsed();
    assert_eq!(
        detail_count,
        i64::try_from(EVENT_COUNT / ITEM_COUNT).unwrap()
    );
    assert!(detail_duration <= MAX_DETAIL_QUERY_DURATION);

    let credential = owner_session(&pool, &ids).await;
    let inventory = inventory_api::router(pool.clone());
    let release_api = releases::router(pool.clone());
    let distribution_uri = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory/distribution?kind=process&release_id={baseline_id}&namespace=production&workload_kind=Deployment&limit=10",
        ids.project_id, ids.application_id
    );
    let diff_uri = format!(
        "/api/v1/projects/{}/applications/{}/releases/{target_id}/runtime-diff/summary?baseline_id={baseline_id}&limit=10",
        ids.project_id, ids.application_id
    );
    let inventory_base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory",
        ids.project_id, ids.application_id
    );
    let mut hardening_durations = Vec::new();
    for (name, uri) in [
        (
            "summary",
            format!("{inventory_base}/summary?release_id={baseline_id}&namespace=production"),
        ),
        (
            "facet_cluster",
            format!("{inventory_base}/facets/cluster?release_id={baseline_id}"),
        ),
        (
            "facet_namespace",
            format!("{inventory_base}/facets/namespace?release_id={baseline_id}"),
        ),
        (
            "facet_workload_kind",
            format!("{inventory_base}/facets/workload_kind?release_id={baseline_id}"),
        ),
        (
            "facet_workload_name",
            format!("{inventory_base}/facets/workload_name?release_id={baseline_id}"),
        ),
        (
            "facet_container_name",
            format!("{inventory_base}/facets/container_name?release_id={baseline_id}"),
        ),
    ] {
        let started = Instant::now();
        let response = inventory
            .clone()
            .oneshot(authenticated_request(&uri, &credential))
            .await
            .unwrap();
        let duration = started.elapsed();
        assert!(response.status().is_success(), "{name} response");
        assert!(
            duration <= MAX_AGGREGATE_QUERY_DURATION,
            "{name} duration {duration:?}"
        );
        hardening_durations.push((name, duration));
    }
    sqlx::query("ANALYZE runtime_inventory_items")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE runtime_event_group_releases")
        .execute(&pool)
        .await
        .unwrap();
    let mut distribution_samples = Vec::with_capacity(SAMPLE_COUNT);
    let mut diff_samples = Vec::with_capacity(SAMPLE_COUNT);
    let mut max_response_bytes = 0usize;
    for _ in 0..SAMPLE_COUNT {
        let started = Instant::now();
        let response = inventory
            .clone()
            .oneshot(authenticated_request(&distribution_uri, &credential))
            .await
            .unwrap();
        assert!(response.status().is_success());
        distribution_samples.push(started.elapsed());
        max_response_bytes = max_response_bytes.max(
            to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap()
                .len(),
        );

        let started = Instant::now();
        let response = release_api
            .clone()
            .oneshot(authenticated_request(&diff_uri, &credential))
            .await
            .unwrap();
        assert!(response.status().is_success());
        diff_samples.push(started.elapsed());
        max_response_bytes = max_response_bytes.max(
            to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap()
                .len(),
        );
    }
    distribution_samples.sort_unstable();
    diff_samples.sort_unstable();
    let mut plans = Vec::new();
    for kind in ["process", "destination", "domain", "syscall"] {
        let plan: Vec<String> = sqlx::query_scalar("EXPLAIN SELECT identity_digest,occurrence_count FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=1 AND inventory_kind=$4 ORDER BY occurrence_count DESC,identity_digest ASC LIMIT 10")
            .bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(kind).fetch_all(&pool).await.unwrap();
        plans.push((kind, plan));
    }
    let diff_plan: Vec<String> = sqlx::query_scalar("EXPLAIN WITH b AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$1),t AS (SELECT group_id,occurrence_count FROM runtime_event_group_releases WHERE release_id=$2) SELECT COALESCE(t.group_id,b.group_id) FROM b FULL OUTER JOIN t ON t.group_id=b.group_id ORDER BY ABS(COALESCE(t.occurrence_count,0)-COALESCE(b.occurrence_count,0)) DESC LIMIT 10")
        .bind(baseline_id).bind(target_id).fetch_all(&pool).await.unwrap();
    let hardening_plans = hardening_plans(&pool, &ids, baseline_id).await;

    eprintln!(
        "runtime inventory benchmark: events={EVENT_COUNT} items={ITEM_COUNT} pods={POD_COUNT} projection_ms={} list_ms={} detail_ms={} distribution_p50_ms={} distribution_p95_ms={} distribution_p99_ms={} diff_p50_ms={} diff_p95_ms={} diff_p99_ms={} max_response_bytes={} hardening_durations={:?} inventory_plans={:?} hardening_plans={:?} diff_plan={:?}",
        projection_duration.as_millis(),
        list_duration.as_millis(),
        detail_duration.as_millis(),
        percentile(&distribution_samples, 50).as_millis(),
        percentile(&distribution_samples, 95).as_millis(),
        percentile(&distribution_samples, 99).as_millis(),
        percentile(&diff_samples, 50).as_millis(),
        percentile(&diff_samples, 95).as_millis(),
        percentile(&diff_samples, 99).as_millis(),
        max_response_bytes,
        hardening_durations,
        plans,
        hardening_plans,
        diff_plan,
    );
}

async fn hardening_plans(
    pool: &sqlx::PgPool,
    ids: &server::bootstrap::BootstrapIds,
    release_id: Uuid,
) -> Vec<(String, Vec<String>)> {
    let summary: Vec<String> = sqlx::query_scalar("EXPLAIN (ANALYZE, BUFFERS) SELECT i.inventory_kind,count(*) FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=1 AND EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$4) AND EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace='production') GROUP BY i.inventory_kind")
        .bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(release_id)
        .fetch_all(pool).await.unwrap();
    let mut plans = vec![("summary".to_owned(), summary)];
    for (name, expression) in [
        ("cluster", "s.cluster_id::text"),
        ("namespace", "s.namespace"),
        ("workload_kind", "s.workload_kind"),
        ("workload_name", "s.workload_name"),
        ("container_name", "s.container_name"),
    ] {
        let sql = format!(
            "EXPLAIN (ANALYZE, BUFFERS) SELECT {expression},count(DISTINCT i.id),sum(s.occurrence_count) FROM runtime_inventory_sightings s JOIN runtime_inventory_items i ON i.id=s.item_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=1 AND EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$4) GROUP BY {expression} ORDER BY count(DISTINCT i.id) DESC,{expression} ASC LIMIT 201"
        );
        let plan = sqlx::query_scalar(&sql)
            .bind(ids.organization_id)
            .bind(ids.project_id)
            .bind(ids.application_id)
            .bind(release_id)
            .fetch_all(pool)
            .await
            .unwrap();
        plans.push((name.to_owned(), plan));
    }
    plans
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL; run explicitly for acceptance"]
async fn inbound_remote_cardinality_does_not_expand_inventory_identity(pool: sqlx::PgPool) {
    const ACCEPT_COUNT: usize = 10_000;
    const ENDPOINT_COUNT: usize = 100;
    let ids = bootstrap(&pool, &config()).await.unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'benchmark-node','benchmark')")
        .bind(agent_id).bind(ids.organization_id).bind(ids.cluster_id)
        .execute(&pool).await.unwrap();
    let events: Vec<_> = (0..ACCEPT_COUNT)
        .map(|index| RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: ids.project_id,
                application_id: ids.application_id,
                node_name: "benchmark-node".into(),
                namespace: "production".into(),
                pod_uid: format!("pod-{}", index % POD_COUNT),
                pod_name: format!("benchmark-{}", index % POD_COUNT),
                container_id: format!("container-{}", index % POD_COUNT),
                container_name: "benchmark".into(),
                workload_uid: "benchmark-workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "benchmark".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 1,
                tgid: 1,
                command: "benchmark".into(),
            },
            payload: EventPayload::NetworkAccept(
                NetworkAccept::new(
                    NetworkAddressFamily::Ipv4,
                    "0.0.0.0".parse().unwrap(),
                    u16::try_from(10_000 + index % ENDPOINT_COUNT).unwrap(),
                    format!("198.51.{}.{}", (index / 254) % 254, index % 254 + 1)
                        .parse()
                        .unwrap(),
                    u16::try_from(20_000 + index % 40_000).unwrap(),
                )
                .unwrap(),
            ),
        })
        .collect();
    let started = Instant::now();
    let accepted = persist_batch(
        &pool,
        IngestionContext {
            scope: SessionScope {
                organization_id: ids.organization_id,
                cluster_id: ids.cluster_id,
            },
            agent_id,
        },
        &events,
    )
    .await
    .unwrap();
    assert_eq!(usize::try_from(accepted).unwrap(), ACCEPT_COUNT);
    assert!(started.elapsed() <= MAX_PROJECTION_DURATION);
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM runtime_inventory_items WHERE inventory_kind='inbound_endpoint'),(SELECT count(*) FROM runtime_event_groups WHERE event_kind='network.accept'),(SELECT count(*) FROM runtime_events WHERE event_kind='network.accept')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        counts,
        (
            i64::try_from(ENDPOINT_COUNT).unwrap(),
            i64::try_from(ENDPOINT_COUNT).unwrap(),
            i64::try_from(ACCEPT_COUNT).unwrap()
        )
    );
}

fn authenticated_request(uri: &str, credential: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(COOKIE, format!("{SESSION_COOKIE}={credential}"))
        .body(Body::empty())
        .unwrap()
}

async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("inventory-benchmark-password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(ids.organization_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(ids.organization_id).bind(token.digest().as_slice())
        .execute(pool).await.unwrap();
    token.expose().to_owned()
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = ((samples.len() - 1) * percentile).div_ceil(100);
    samples[index]
}
