use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::COOKIE},
};
use chrono::{Duration, Utc};
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    RuntimeEvent,
};
use server::{
    api,
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    ingestion::{IngestionContext, persist_batch},
    inventory_api, releases,
    runtime_retention::worker,
};
use tower::ServiceExt;
use uuid::Uuid;
fn config(name: &str) -> BootstrapConfig {
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: name.into(),
        organization_name: name.into(),
        project_slug: "project".into(),
        project_name: "Project".into(),
        cluster_external_id: "cluster".into(),
        cluster_name: "Cluster".into(),
        application_slug: "app".into(),
        application_name: "App".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn request(
    method: &str,
    uri: &str,
    credential: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(COOKIE, format!("{SESSION_COOKIE}={credential}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn create_release(
    app: &axum::Router,
    ids: &BootstrapIds,
    credential: &str,
    version: &str,
    deployed_at: chrono::DateTime<Utc>,
) -> Uuid {
    let uri = format!(
        "/api/v1/projects/{}/applications/{}/releases",
        ids.project_id, ids.application_id
    );
    let response = app
        .clone()
        .clone()
        .oneshot(request(
            "POST",
            &uri,
            credential,
            Some(serde_json::json!({"version":version,"deployed_at":deployed_at})),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    Uuid::parse_str(json(response).await["id"].as_str().unwrap()).unwrap()
}

fn event(
    ids: &BootstrapIds,
    release: Option<&str>,
    executable: &str,
    observed_at: chrono::DateTime<Utc>,
) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at,
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: ids.project_id,
            application_id: ids.application_id,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_uid: Uuid::new_v4().to_string(),
            pod_name: "app-1".into(),
            container_id: Uuid::new_v4().to_string(),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: release.map(str::to_owned),
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 1,
            tgid: 1,
            command: "app".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: executable.into(),
            parent_command: None,
        }),
    }
}

async fn agent(pool: &sqlx::PgPool, ids: &BootstrapIds) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node','test')")
        .bind(id).bind(ids.organization_id).bind(ids.cluster_id).execute(pool).await.unwrap();
    id
}

async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("release-test-password").unwrap())
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
        .bind(Uuid::new_v4()).bind(user_id).bind(ids.organization_id)
        .bind(token.digest().as_slice()).execute(pool).await.unwrap();
    token.expose().to_owned()
}

struct Fixture {
    ids: BootstrapIds,
    token: String,
    context: IngestionContext,
    baseline: Uuid,
    target: Uuid,
    now: chrono::DateTime<Utc>,
}

async fn fixture(pool: &sqlx::PgPool) -> Fixture {
    let ids = bootstrap(pool, &config(&Uuid::new_v4().to_string()))
        .await
        .unwrap();
    let token = owner_session(pool, &ids).await;
    let app = releases::router(pool.clone());
    let now = Utc::now();
    let baseline = create_release(&app, &ids, &token, "baseline", now - Duration::days(21)).await;
    let target = create_release(&app, &ids, &token, "target", now - Duration::days(9)).await;
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        },
        agent_id: agent(pool, &ids).await,
    };
    let events = [
        event(&ids, Some("baseline"), "/shared", now - Duration::days(20)),
        event(&ids, Some("baseline"), "/old", now - Duration::days(20)),
        event(&ids, Some("target"), "/shared", now - Duration::days(8)),
        event(&ids, Some("target"), "/new", now - Duration::days(8)),
    ];
    assert_eq!(persist_batch(pool, context, &events).await.unwrap(), 4);
    sqlx::query("UPDATE organizations SET runtime_retention_enabled=true,runtime_retention_raw_days=1,runtime_retention_history_days=365 WHERE id=$1").bind(ids.organization_id).execute(pool).await.unwrap();
    Fixture {
        ids,
        token,
        context,
        baseline,
        target,
        now,
    }
}

async fn get(pool: &sqlx::PgPool, f: &Fixture, path: &str) -> serde_json::Value {
    let router = api::router(pool.clone())
        .merge(inventory_api::router(pool.clone()))
        .merge(releases::router(pool.clone()));
    let response = router
        .oneshot(request("GET", path, &f.token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    json(response).await
}

async fn compact(pool: &sqlx::PgPool, f: &Fixture) -> u64 {
    worker::process_project(pool, f.ids.organization_id, f.ids.project_id, f.now, 100)
        .await
        .unwrap()
}

fn diff_path(f: &Fixture) -> String {
    format!(
        "/api/v1/projects/{}/applications/{}/releases/{}/runtime-diff?baseline_id={}",
        f.ids.project_id, f.ids.application_id, f.target, f.baseline
    )
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn compaction_preserves_release_evidence_and_expiry_marks_unknown(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let before = get(&pool, &f, &diff_path(&f)).await;
    assert_eq!(compact(&pool, &f).await, 4);
    let after = get(&pool, &f, &diff_path(&f)).await;
    assert_eq!(before["items"], after["items"]);
    assert_eq!(after["coverage"]["detail_scope"], "raw");
    assert!(after["coverage"]["closed_before"].is_string());
    let groups: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM runtime_event_groups WHERE project_id=$1")
            .bind(f.ids.project_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    for group in groups {
        let detail = get(&pool, &f, &format!("/api/v1/runtime-groups/{group}")).await;
        assert!(detail["representative_event"].is_null());
        let snapshots = get(
            &pool,
            &f,
            &format!("/api/v1/runtime-groups/{group}/snapshots"),
        )
        .await;
        assert_eq!(snapshots["granularity"], "utc_day");
        assert!(!snapshots["items"].as_array().unwrap().is_empty());
        assert!(snapshots["items"][0]["occurrence_count"].as_i64().unwrap() > 0);
        assert!(snapshots["items"][0]["day"].is_string());
        assert!(snapshots["coverage"]["closed_before"].is_string());
    }
    sqlx::query("UPDATE organizations SET runtime_retention_history_days=10 WHERE id=$1")
        .bind(f.ids.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    compact(&pool, &f).await;
    let expired = get(&pool, &f, &diff_path(&f)).await;
    let items = expired["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|item| item["classification"] == "unknown"));
    assert!(expired["coverage"]["history_expired_before"].is_string());
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn inventory_detail_is_raw_only_after_compaction(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let item:Uuid=sqlx::query_scalar("SELECT id FROM runtime_inventory_items WHERE project_id=$1 AND semantic_summary::text LIKE '%shared%' LIMIT 1").bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    let fresh = event(&f.ids, Some("target"), "/shared", f.now);
    assert_eq!(persist_batch(&pool, f.context, &[fresh]).await.unwrap(), 1);
    assert_eq!(compact(&pool, &f).await, 4);
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory/{item}",
        f.ids.project_id, f.ids.application_id
    );
    let occurrences = get(&pool, &f, &format!("{base}/occurrences")).await;
    assert_eq!(occurrences["items"].as_array().unwrap().len(), 1);
    assert_eq!(occurrences["coverage"]["detail_scope"], "raw");
    assert!(occurrences["coverage"]["closed_before"].is_string());
    let count: i64 =
        sqlx::query_scalar("SELECT occurrence_count FROM runtime_inventory_items WHERE id=$1")
            .bind(item)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let reconciliation = server::inventory_operations::reconcile(
        &pool,
        f.ids.organization_id,
        f.ids.project_id,
        f.ids.application_id,
        1,
    )
    .await
    .unwrap();
    assert!(reconciliation.is_consistent());
    assert_eq!(reconciliation.group_evidence_count, 5);
    assert_eq!(reconciliation.item_occurrence_count, 1);
    let releases = get(&pool, &f, &format!("{base}/releases")).await;
    let baseline = releases["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["release_id"] == f.baseline.to_string())
        .unwrap();
    assert_eq!(baseline["presence"], "unknown");
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn failed_delete_rolls_back_snapshots_then_retry_is_exact(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    sqlx::raw_sql("CREATE FUNCTION fail_retention_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected deletion failure'; END $$; CREATE TRIGGER fail_retention_delete BEFORE DELETE ON runtime_events FOR EACH ROW EXECUTE FUNCTION fail_retention_delete();").execute(&pool).await.unwrap();
    assert!(
        worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 2)
            .await
            .is_err()
    );
    let raw: i64 = sqlx::query_scalar("SELECT count(*) FROM runtime_events WHERE project_id=$1")
        .bind(f.ids.project_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let snapshots: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runtime_history_snapshots WHERE project_id=$1")
            .bind(f.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((raw, snapshots), (4, 0));
    let refs:i64=sqlx::query_scalar("SELECT count(*) FROM runtime_event_groups WHERE project_id=$1 AND representative_event_id IS NOT NULL").bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    assert_eq!(refs, 3);
    sqlx::query("DROP TRIGGER fail_retention_delete ON runtime_events")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(compact(&pool, &f).await, 4);
    assert_eq!(compact(&pool, &f).await, 0);
    let total: i64 = sqlx::query_scalar(
        "SELECT sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE project_id=$1",
    )
    .bind(f.ids.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, 4);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn concurrent_batches_forever_replay_and_tenant_isolation(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let other = fixture(&pool).await;
    sqlx::query("UPDATE organizations SET runtime_retention_history_days=NULL WHERE id=$1")
        .bind(f.ids.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 2),
        worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 2)
    );
    assert_eq!(a.unwrap() + b.unwrap(), 4);
    let other_raw: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runtime_events WHERE project_id=$1")
            .bind(other.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(other_raw, 4);
    worker::process_project(
        &pool,
        f.ids.organization_id,
        f.ids.project_id,
        f.now + Duration::days(4000),
        100,
    )
    .await
    .unwrap();
    let total: i64 = sqlx::query_scalar(
        "SELECT sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE project_id=$1",
    )
    .bind(f.ids.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, 4);
    let late = event(
        &f.ids,
        Some("baseline"),
        "/shared",
        f.now - Duration::days(20),
    );
    assert_eq!(persist_batch(&pool, f.context, &[late]).await.unwrap(), 0);
    let raw: i64 = sqlx::query_scalar("SELECT count(*) FROM runtime_events WHERE project_id=$1")
        .bind(f.ids.project_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(raw, 0);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn equal_horizons_and_exact_boundary(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    sqlx::query("UPDATE organizations SET runtime_retention_history_days=1 WHERE id=$1")
        .bind(f.ids.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    let boundary = (f.now - Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let events = [
        event(&f.ids, None, "/boundary", boundary),
        event(
            &f.ids,
            None,
            "/before",
            boundary - Duration::nanoseconds(1000),
        ),
    ];
    persist_batch(&pool, f.context, &events).await.unwrap();
    assert_eq!(compact(&pool, &f).await, 5);
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM runtime_events),(SELECT count(*) FROM runtime_history_snapshots)").fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 0));
    let closed: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT runtime_closed_before FROM projects WHERE id=$1")
            .bind(f.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(closed, boundary);
    sqlx::query("UPDATE organizations SET runtime_retention_enabled=false,runtime_retention_raw_days=365,runtime_retention_history_days=NULL WHERE id=$1").bind(f.ids.organization_id).execute(&pool).await.unwrap();
    assert_eq!(compact(&pool, &f).await, 0);
    assert_eq!(
        persist_batch(&pool, f.context, &events[1..]).await.unwrap(),
        0
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn null_release_buckets_and_ingestion_serialization(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let old = event(&f.ids, None, "/unattributed", f.now - Duration::days(8));
    let second = event(&f.ids, None, "/unattributed", f.now - Duration::days(8));
    persist_batch(&pool, f.context, &[old, second])
        .await
        .unwrap();
    let fresh = event(&f.ids, None, "/fresh", f.now);
    let (worker_result, ingestion_result) = tokio::join!(
        compact(&pool, &f),
        persist_batch(&pool, f.context, std::slice::from_ref(&fresh))
    );
    assert_eq!(worker_result, 6);
    assert_eq!(ingestion_result.unwrap(), 1);
    let counts:(i64,i64)=sqlx::query_as("SELECT count(*),sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE release_id IS NULL").fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 2));
    let mut tx = pool.begin().await.unwrap();
    let credential = server::application_credentials::issue(
        &mut tx,
        f.ids.organization_id,
        f.ids.project_id,
        f.ids.application_id,
        "retention-test",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let scope = server::application_credentials::authenticate(&pool, credential.token())
        .await
        .unwrap()
        .unwrap();
    let mut mixed = [
        event(&f.ids, None, "/expired", f.now - Duration::days(8)),
        event(&f.ids, None, "/accepted", f.now),
    ];
    let outcome = server::ingestion::persist_application_batch_outcome(
        &pool,
        f.context.scope,
        scope,
        f.context.agent_id,
        &mut mixed,
    )
    .await
    .unwrap();
    assert_eq!(outcome, (1, 1));
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn measured_bounded_compaction_workload(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let events: Vec<_> = (0..1000)
        .map(|_| event(&f.ids, None, "/bulk", f.now - Duration::days(8)))
        .collect();
    persist_batch(&pool, f.context, &events).await.unwrap();
    let started = std::time::Instant::now();
    let mut batches = 0;
    let mut deleted = 0;
    loop {
        let count =
            worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 100)
                .await
                .unwrap();
        assert!(count <= 100);
        if count == 0 {
            break;
        }
        deleted += count;
        batches += 1;
    }
    let buckets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_history_snapshots WHERE release_id IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(buckets, 1);
    assert_eq!(deleted, 1004);
    eprintln!(
        "retention workload: {deleted} events, {batches} bounded batches, {:?}, {buckets} bulk bucket",
        started.elapsed()
    );
    let plan:Vec<(String,)>=sqlx::query_as("EXPLAIN SELECT id FROM runtime_events WHERE project_id=$1 AND observed_at<now() ORDER BY observed_at,id LIMIT 100 FOR UPDATE").bind(f.ids.project_id).fetch_all(&pool).await.unwrap();
    eprintln!("retention selection plan: {plan:?}");
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "measured retention workload; requires isolated PostgreSQL DATABASE_URL"]
async fn measured_single_group_retention_workload(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let copies = 20_000_i64;
    let source: (Uuid, Uuid, Uuid) = sqlx::query_as("SELECT e.id,g.group_id,i.item_id FROM runtime_events e JOIN runtime_event_group_memberships g ON g.event_id=e.id JOIN runtime_inventory_event_memberships i ON i.event_id=e.id WHERE e.project_id=$1 LIMIT 1")
        .bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO runtime_events SELECT (jsonb_populate_record(NULL::runtime_events,to_jsonb(e)||jsonb_build_object('id',gen_random_uuid(),'event_id',gen_random_uuid()))).* FROM runtime_events e CROSS JOIN generate_series(1,$2) WHERE e.id=$1")
        .bind(source.0).bind(copies).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO runtime_event_group_memberships(organization_id,project_id,application_id,event_id,group_id,fingerprint_version,release_id) SELECT e.organization_id,e.project_id,e.application_id,e.id,$2,1,e.release_id FROM runtime_events e WHERE e.project_id=$1 AND NOT EXISTS(SELECT 1 FROM runtime_event_group_memberships m WHERE m.event_id=e.id)")
        .bind(f.ids.project_id).bind(source.1).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO runtime_inventory_event_memberships(organization_id,project_id,application_id,event_id,item_id,identity_version) SELECT e.organization_id,e.project_id,e.application_id,e.id,$2,1 FROM runtime_events e WHERE e.project_id=$1 AND NOT EXISTS(SELECT 1 FROM runtime_inventory_event_memberships m WHERE m.event_id=e.id)")
        .bind(f.ids.project_id).bind(source.2).execute(&pool).await.unwrap();
    sqlx::query("ANALYZE runtime_events")
        .execute(&pool)
        .await
        .unwrap();
    let plan: serde_json::Value = sqlx::query_scalar("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id FROM runtime_events WHERE project_id=$1 AND observed_at<$2 ORDER BY observed_at,id LIMIT 500")
        .bind(f.ids.project_id).bind(f.now-Duration::days(1)).fetch_one(&pool).await.unwrap();
    let mut durations = Vec::new();
    let mut total = 0;
    loop {
        let started = std::time::Instant::now();
        let count =
            worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 500)
                .await
                .unwrap();
        if count == 0 {
            break;
        }
        durations.push(started.elapsed().as_millis());
        assert!(count <= 500);
        total += count;
    }
    assert_eq!(total, u64::try_from(copies).unwrap() + 4);
    let stats: (i64,i64) = sqlx::query_as("SELECT count(*),sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE project_id=$1")
        .bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    assert!(stats.0 <= 4);
    assert_eq!(stats.1, copies + 4);
    durations.sort_unstable();
    println!(
        "RETENTION_BENCH {}",
        serde_json::json!({"events":copies+4,"batch_limit":500,"batches":durations.len(),"snapshot_rows":stats.0,"batch_ms_p50":durations[durations.len()/2],"batch_ms_p95":durations[durations.len()*95/100],"batch_ms_max":durations.last(),"total_batch_ms":durations.iter().sum::<u128>(),"candidate_query_plan":plan})
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn policy_shells_pending_notifications_and_orphan_cleanup(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let (item, group): (Uuid, Uuid) = sqlx::query_as(
        "SELECT item_id,group_id FROM runtime_inventory_group_links WHERE project_id=$1 LIMIT 1",
    )
    .bind(f.ids.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO runtime_policy_suppressions(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,behavior_matcher,reason,expires_at,source_inventory_item_id,source_runtime_group_id,created_by_user_id) SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.identity_digest,'{}'::jsonb,'test',now()+interval '1 day',i.id,$2,(SELECT user_id FROM organization_memberships WHERE organization_id=i.organization_id LIMIT 1) FROM runtime_inventory_items i WHERE i.id=$1").bind(item).bind(group).execute(&pool).await.unwrap();
    sqlx::query("UPDATE organizations SET runtime_retention_history_days=1 WHERE id=$1")
        .bind(f.ids.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    compact(&pool, &f).await;
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT occurrence_count FROM runtime_inventory_items WHERE id=$1),(SELECT occurrence_count FROM runtime_event_groups WHERE id=$2)").bind(item).bind(group).fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (0, 0));
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_messages WHERE project_id=$1 AND processed_at IS NULL",
    )
    .bind(f.ids.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(pending > 0);
    sqlx::query("UPDATE outbox_messages SET processed_at=now() WHERE project_id=$1")
        .bind(f.ids.project_id)
        .execute(&pool)
        .await
        .unwrap();
    compact(&pool, &f).await;
    let groups: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runtime_event_groups WHERE project_id=$1")
            .bind(f.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(groups, 1);
    let outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox_messages WHERE project_id=$1")
            .bind(f.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox, 0);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn derived_restart_counts_survive_without_payload_archive(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let events: Vec<_> = (0..3)
        .map(|index| {
            let mut value = event(
                &f.ids,
                None,
                "/restart",
                f.now - Duration::days(8) + Duration::seconds(index),
            );
            value.attribution.pod_uid = "restart-pod".into();
            value.attribution.container_id = "container".into();
            value.payload = EventPayload::ContainerRestart(
                event_model::ContainerRestart::new(
                    "container",
                    u32::try_from(index + 1).unwrap(),
                    1,
                    None,
                    None,
                )
                .unwrap(),
            );
            value
        })
        .collect();
    persist_batch(&pool, f.context, &events).await.unwrap();
    let group:Uuid=sqlx::query_scalar("SELECT id FROM runtime_event_groups WHERE project_id=$1 AND event_kind='container.restart_loop'").bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    assert_eq!(compact(&pool, &f).await, 7);
    let row:(i64,Option<Uuid>,serde_json::Value)=sqlx::query_as("SELECT occurrence_count,representative_event_id,semantic_summary FROM runtime_event_groups WHERE id=$1").bind(group).fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, 1);
    assert!(row.1.is_none());
    assert!(row.2.get("latest_termination").is_none());
    let snapshot: i64 = sqlx::query_scalar(
        "SELECT sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE group_id=$1",
    )
    .bind(group)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(snapshot, 1);
    let projections: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_restart_loop_projections WHERE project_id=$1",
    )
    .bind(f.ids.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(projections, 0);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn counterpart_expiry_marks_incomplete_instead_of_absent(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM runtime_events WHERE project_id=$1 ORDER BY observed_at,id LIMIT 2",
    )
    .bind(f.ids.project_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO runtime_event_correlations(organization_id,project_id,lifecycle_event_id,kernel_event_id,correlation_kind) VALUES($1,$2,$3,$4,'qualified')").bind(f.ids.organization_id).bind(f.ids.project_id).bind(ids[0]).bind(ids[1]).execute(&pool).await.unwrap();
    assert_eq!(
        worker::process_project(&pool, f.ids.organization_id, f.ids.project_id, f.now, 1)
            .await
            .unwrap(),
        1
    );
    let incomplete: bool = sqlx::query_scalar(
        "SELECT retention_incomplete FROM runtime_event_correlation_outcomes WHERE event_id=$1",
    )
    .bind(ids[1])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(incomplete);
    let links: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runtime_event_correlations WHERE project_id=$1")
            .bind(f.ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(links, 0);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires isolated PostgreSQL DATABASE_URL"]
async fn ungrouped_history_waits_for_serialized_backfill(pool: sqlx::PgPool) {
    let f = fixture(&pool).await;
    sqlx::query("DELETE FROM runtime_event_groups WHERE project_id=$1")
        .bind(f.ids.project_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(compact(&pool, &f).await, 0);
    let options = server::backfill::BackfillOptions {
        organization_id: f.ids.organization_id,
        project_id: f.ids.project_id,
        fingerprint_version: 1,
        batch_size: 10,
        throttle: std::time::Duration::ZERO,
    };
    let (backfill, worker) =
        tokio::join!(server::backfill::run(&pool, options), compact(&pool, &f));
    assert_eq!(backfill.unwrap().grouped, 4);
    assert_eq!(worker + compact(&pool, &f).await, 4);
    let total:i64=sqlx::query_scalar("SELECT sum(occurrence_count)::bigint FROM runtime_history_snapshots WHERE project_id=$1 AND release_id IS NOT NULL").bind(f.ids.project_id).fetch_one(&pool).await.unwrap();
    assert_eq!(total, 4);
}
