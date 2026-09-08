use std::{collections::VecDeque, sync::Arc};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header::COOKIE},
    routing::post,
};
use chrono::Utc;
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    RuntimeEvent, SyscallEvent,
};
use server::{
    auth::{SessionScope, SessionToken, hash_password},
    bootstrap::{BootstrapConfig, bootstrap},
    ingestion::{IngestionContext, persist_batch},
    notification::{
        NotificationService,
        health::{NotificationHealthResponse, NotificationHealthState, load_project_snapshot},
        webhook::{WebhookEnvelope, signature},
        worker::{claim_due, materialize_once, process_claim, test_destination},
    },
    notification_config::NotificationArgs,
};
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ReceiverState {
    responses: Arc<Mutex<VecDeque<StatusCode>>>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

async fn receiver(
    State(state): State<ReceiverState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    state.requests.lock().await.push(CapturedRequest {
        headers,
        body: body.to_vec(),
    });
    state
        .responses
        .lock()
        .await
        .pop_front()
        .unwrap_or(StatusCode::OK)
}

async fn spawn_receiver(
    responses: Vec<StatusCode>,
) -> (String, ReceiverState, tokio::task::JoinHandle<()>) {
    let state = ReceiverState {
        responses: Arc::new(Mutex::new(responses.into())),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/hook", post(receiver))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/hook"), state, task)
}

fn config(name: &str) -> BootstrapConfig {
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: name.into(),
        organization_name: name.into(),
        project_slug: "payments".into(),
        project_name: "Payments".into(),
        cluster_external_id: "local".into(),
        cluster_name: "Local".into(),
        application_slug: "payment-api".into(),
        application_name: "Payment API".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn service(pool: sqlx::PgPool) -> NotificationService {
    let args = NotificationArgs {
        enabled: true,
        encryption_key: Some(hex::encode([9_u8; 32])),
        poll_ms: 50,
        claim_size: 10,
        concurrency: 2,
        lease_seconds: 5,
        request_timeout_seconds: 2,
        max_attempts: 3,
        backoff_min_seconds: 1,
        backoff_max_seconds: 2,
        max_response_bytes: 1024,
        shutdown_drain_seconds: 3,
        allow_http: true,
        allow_private_ips: true,
        ..NotificationArgs::default()
    };
    NotificationService::new(pool, args.build(true).unwrap()).unwrap()
}

fn disabled_service(pool: sqlx::PgPool) -> NotificationService {
    let args = NotificationArgs {
        enabled: false,
        encryption_key: Some(hex::encode([9_u8; 32])),
        ..NotificationArgs::default()
    };
    NotificationService::new(pool, args.build(true).unwrap()).unwrap()
}

fn event(project_id: Uuid, application_id: Uuid, payload: EventPayload) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at: Utc::now(),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id,
            application_id,
            node_name: "node-1".into(),
            namespace: "production".into(),
            pod_uid: "pod-uid".into(),
            pod_name: "payment-api-1".into(),
            container_id: "container".into(),
            container_name: "payment-api".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "payment-api".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 10,
            tgid: 10,
            command: "sh".into(),
        },
        payload,
    }
}

async fn tenant(
    pool: &sqlx::PgPool,
    name: &str,
) -> (server::bootstrap::BootstrapIds, IngestionContext) {
    let ids = bootstrap(pool, &config(name)).await.unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id,organization_id,cluster_id,node_name,agent_version) VALUES ($1,$2,$3,'node-1','test')")
        .bind(agent_id).bind(ids.organization_id).bind(ids.cluster_id).execute(pool).await.unwrap();
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        },
        agent_id,
    };
    (ids, context)
}

async fn user_session(pool: &sqlx::PgPool, organization_id: Uuid, email: &str) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(email)
        .bind(hash_password("correct horse battery staple").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(organization_id)
        .bind(token.digest().to_vec())
        .execute(pool)
        .await
        .unwrap();
    token.expose().to_owned()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn destination_schema_lifecycle_and_tenant_ownership(pool: sqlx::PgPool) {
    let (first, context) = tenant(&pool, "notify-first").await;
    let (second, _) = tenant(&pool, "notify-second").await;
    let service = service(pool.clone());
    let (destination, secret) = service
        .destinations
        .create(
            first.organization_id,
            first.project_id,
            "primary",
            "http://127.0.0.1:12345/hook",
            false,
        )
        .await
        .unwrap();
    assert_eq!(secret.len(), 64);
    assert_eq!(
        service
            .destinations
            .list(first.organization_id, first.project_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        service
            .destinations
            .get(second.organization_id, second.project_id, destination.id)
            .await
            .unwrap()
            .is_none()
    );
    let conflict = service
        .destinations
        .update(
            first.organization_id,
            first.project_id,
            destination.id,
            server::notification::repository::DestinationUpdate {
                name: Some("renamed"),
                url: None,
                deliver_backfill: None,
                enabled: None,
                expected_revision: 99,
            },
        )
        .await;
    assert!(matches!(
        conflict,
        Err(server::notification::repository::DestinationError::RevisionConflict)
    ));
    let (_, rotated) = service
        .destinations
        .rotate_secret(first.organization_id, first.project_id, destination.id)
        .await
        .unwrap();
    assert_ne!(*secret, *rotated);
    let disabled = service
        .destinations
        .disable(first.organization_id, first.project_id, destination.id)
        .await
        .unwrap();
    assert!(!disabled.enabled);
    persist_batch(
        &pool,
        context,
        &[event(
            first.project_id,
            first.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/echo".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    assert_eq!(materialize_once(&service).await.unwrap().no_destinations, 1);
    let ownership_error = sqlx::query("INSERT INTO webhook_destinations (id,organization_id,project_id,name,url,encrypted_secret,secret_nonce) VALUES ($1,$2,$3,'bad','https://example.com',decode('00','hex'),decode(repeat('00',24),'hex'))")
        .bind(Uuid::new_v4()).bind(first.organization_id).bind(second.project_id).execute(&pool).await;
    assert!(ownership_error.is_err());
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn disabled_then_enabled_preserves_and_delivers_backlog(pool: sqlx::PgPool) {
    let (url, _receiver, task) = spawn_receiver(vec![StatusCode::OK]).await;
    let (ids, context) = tenant(&pool, "notify-reactivate").await;
    let disabled = disabled_service(pool.clone());
    disabled
        .destinations
        .create(ids.organization_id, ids.project_id, "primary", &url, false)
        .await
        .unwrap();
    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::Syscall(SyscallEvent {
                name: "ptrace".into(),
            }),
        )],
    )
    .await
    .unwrap();
    assert!(!disabled.config.enabled);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox_messages WHERE processed_at IS NULL"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    let enabled = service(pool.clone());
    assert!(claim_due(&enabled).await.unwrap().is_empty());
    assert_eq!(materialize_once(&enabled).await.unwrap().deliveries, 1);
    process_claim(&enabled, claim_due(&enabled).await.unwrap().remove(0))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "succeeded"
    );
    task.abort();
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn project_health_snapshot_covers_durable_states(pool: sqlx::PgPool) {
    let (ids, _) = tenant(&pool, "notify-health-states").await;
    let service = service(pool.clone());
    let (destination, _) = service
        .destinations
        .create(
            ids.organization_id,
            ids.project_id,
            "health",
            "http://127.0.0.1:12345/hook",
            false,
        )
        .await
        .unwrap();
    let empty = load_project_snapshot(&pool, ids.organization_id, ids.project_id)
        .await
        .unwrap();
    assert_eq!(empty.enabled_destination_count, 1);
    assert_eq!(
        NotificationHealthResponse::from_snapshot(true, false, &empty).state,
        NotificationHealthState::Idle
    );

    let delivery_id = Uuid::new_v4();
    sqlx::query("INSERT INTO notification_deliveries(id,organization_id,project_id,destination_id,origin,source,event_name,payload,status,available_at,attempt_count,max_attempts) VALUES($1,$2,$3,$4,'test','test','okoscope.test','{}','pending',now()+interval '1 minute',0,3)")
        .bind(delivery_id).bind(ids.organization_id).bind(ids.project_id).bind(destination.id).execute(&pool).await.unwrap();
    let future = load_project_snapshot(&pool, ids.organization_id, ids.project_id)
        .await
        .unwrap();
    assert_eq!(future.pending_count, 1);
    assert_eq!(future.due_count, 0);
    assert_eq!(future.oldest_due_age_seconds, None);
    assert_eq!(
        NotificationHealthResponse::from_snapshot(true, false, &future).state,
        NotificationHealthState::Backlogged
    );
    sqlx::query("UPDATE notification_deliveries SET available_at=now()-interval '5 seconds',attempt_count=1 WHERE id=$1")
        .bind(delivery_id).execute(&pool).await.unwrap();
    let retrying = load_project_snapshot(&pool, ids.organization_id, ids.project_id)
        .await
        .unwrap();
    assert_eq!(retrying.pending_count, 1);
    assert_eq!(retrying.due_count, 1);
    assert_eq!(retrying.retrying_count, 1);
    assert!(retrying.oldest_due_age_seconds.is_some_and(|age| age >= 5));
    assert_eq!(
        NotificationHealthResponse::from_snapshot(true, false, &retrying).state,
        NotificationHealthState::Retrying
    );

    sqlx::query("UPDATE notification_deliveries SET status='in_flight',lease_owner=$2,lease_expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(delivery_id).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
    let draining = load_project_snapshot(&pool, ids.organization_id, ids.project_id)
        .await
        .unwrap();
    assert_eq!(draining.expired_lease_count, 1);
    assert_eq!(
        NotificationHealthResponse::from_snapshot(false, false, &draining).state,
        NotificationHealthState::Draining
    );

    sqlx::query("UPDATE notification_deliveries SET status='failed',lease_owner=NULL,lease_expires_at=NULL,terminal_at=now() WHERE id=$1")
        .bind(delivery_id).execute(&pool).await.unwrap();
    let failed = load_project_snapshot(&pool, ids.organization_id, ids.project_id)
        .await
        .unwrap();
    assert_eq!(
        NotificationHealthResponse::from_snapshot(true, false, &failed).state,
        NotificationHealthState::Failing
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn live_delivery_is_signed_idempotent_and_completes_outbox(pool: sqlx::PgPool) {
    let (url, receiver, task) = spawn_receiver(vec![StatusCode::OK]).await;
    let (ids, context) = tenant(&pool, "notify-live").await;
    let service = service(pool.clone());
    let (_destination, secret) = service
        .destinations
        .create(ids.organization_id, ids.project_id, "primary", &url, false)
        .await
        .unwrap();
    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/sh".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    let (first, second) = tokio::join!(materialize_once(&service), materialize_once(&service));
    assert_eq!(first.unwrap().deliveries + second.unwrap().deliveries, 1);
    let claims = claim_due(&service).await.unwrap();
    assert_eq!(claims.len(), 1);
    sqlx::query(
        "UPDATE notification_deliveries SET lease_expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(claims[0].id)
    .execute(&pool)
    .await
    .unwrap();
    let reclaimed = claim_due(&service).await.unwrap();
    assert_eq!(reclaimed[0].id, claims[0].id);
    assert_ne!(reclaimed[0].lease_owner, claims[0].lease_owner);
    process_claim(&service, reclaimed[0].clone()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM notification_deliveries WHERE status='succeeded'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_delivery_attempts")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM outbox_messages WHERE processed_at IS NOT NULL"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/sh".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    materialize_once(&service).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT occurrence_count FROM runtime_event_groups")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    let captured = receiver.requests.lock().await;
    assert_eq!(captured.len(), 1);
    let envelope: WebhookEnvelope = serde_json::from_slice(&captured[0].body).unwrap();
    let timestamp = captured[0].headers["okoscope-timestamp"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        captured[0].headers["okoscope-delivery"],
        envelope.delivery_id.to_string()
    );
    assert_eq!(
        captured[0].headers["okoscope-signature"],
        signature(secret.as_bytes(), timestamp, &captured[0].body).unwrap()
    );
    task.abort();
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn retries_suppresses_backfill_and_test_is_outbox_independent(pool: sqlx::PgPool) {
    let (url, receiver, task) = spawn_receiver(vec![
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::OK,
        StatusCode::BAD_REQUEST,
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::INTERNAL_SERVER_ERROR,
    ])
    .await;
    let (ids, context) = tenant(&pool, "notify-retry").await;
    let service = service(pool.clone());
    let (destination, _) = service
        .destinations
        .create(ids.organization_id, ids.project_id, "primary", &url, false)
        .await
        .unwrap();
    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::Syscall(SyscallEvent {
                name: "ptrace".into(),
            }),
        )],
    )
    .await
    .unwrap();
    materialize_once(&service).await.unwrap();
    process_claim(&service, claim_due(&service).await.unwrap().remove(0))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "pending"
    );
    sqlx::query("UPDATE notification_deliveries SET available_at=now() WHERE status='pending'")
        .execute(&pool)
        .await
        .unwrap();
    process_claim(&service, claim_due(&service).await.unwrap().remove(0))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_delivery_attempts")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );

    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/zsh".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    materialize_once(&service).await.unwrap();
    process_claim(&service, claim_due(&service).await.unwrap().remove(0))
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM notification_deliveries WHERE status='failed'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/bash".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE outbox_messages SET source='backfill' WHERE materialized_at IS NULL")
        .execute(&pool)
        .await
        .unwrap();
    materialize_once(&service).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM notification_deliveries WHERE status='suppressed'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let updated = service
        .destinations
        .update(
            ids.organization_id,
            ids.project_id,
            destination.id,
            server::notification::repository::DestinationUpdate {
                name: None,
                url: None,
                deliver_backfill: Some(true),
                enabled: None,
                expected_revision: 1,
            },
        )
        .await
        .unwrap();
    assert!(updated.deliver_backfill);
    persist_batch(
        &pool,
        context,
        &[event(
            ids.project_id,
            ids.application_id,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/usr/bin/id".into(),
                parent_command: None,
            }),
        )],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE outbox_messages SET source='backfill' WHERE materialized_at IS NULL")
        .execute(&pool)
        .await
        .unwrap();
    materialize_once(&service).await.unwrap();
    process_claim(&service, claim_due(&service).await.unwrap().remove(0))
        .await
        .unwrap();
    let outbox_before: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    let test = test_destination(
        &service,
        ids.organization_id,
        ids.project_id,
        destination.id,
    )
    .await
    .unwrap();
    assert_eq!(test.origin, "test");
    assert_eq!(test.status, "succeeded");
    let failed_test = test_destination(
        &service,
        ids.organization_id,
        ids.project_id,
        destination.id,
    )
    .await
    .unwrap();
    assert_eq!(failed_test.origin, "test");
    assert_eq!(failed_test.status, "failed");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_messages")
            .fetch_one(&pool)
            .await
            .unwrap(),
        outbox_before
    );
    assert_eq!(receiver.requests.lock().await.len(), 6);
    task.abort();
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn destination_and_delivery_apis_are_secret_safe_and_tenant_scoped(pool: sqlx::PgPool) {
    let (url, _receiver, task) = spawn_receiver(vec![StatusCode::OK]).await;
    let (first, _) = tenant(&pool, "notify-api-first").await;
    let (second, _) = tenant(&pool, "notify-api-second").await;
    let first_session = user_session(&pool, first.organization_id, "first@example.com").await;
    let second_session = user_session(&pool, second.organization_id, "second@example.com").await;
    let service = service(pool.clone());
    let app = server::notification::api::router(pool, service);
    let create_uri = format!("/api/v1/projects/{}/webhook-destinations", first.project_id);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&create_uri)
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"name":"primary","url":url}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(created["secret"].as_str().unwrap().len(), 64);
    let destination_id = created["id"].as_str().unwrap();

    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&create_uri)
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed_body = to_bytes(listed.into_body(), usize::MAX).await.unwrap();
    let listed_text = String::from_utf8(listed_body.to_vec()).unwrap();
    assert!(!listed_text.contains("secret"));
    assert!(!listed_text.contains("encrypted"));

    let foreign = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&create_uri)
                .header(COOKIE, format!("okoscope_session={second_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

    let detail_uri = format!("{create_uri}/{destination_id}");
    let conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&detail_uri)
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"changed","revision":99}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let tested = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{detail_uri}/test"))
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tested.status(), StatusCode::OK);
    let deliveries = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/projects/{}/notification-deliveries?origin=test&limit=1",
                    first.project_id
                ))
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deliveries.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(deliveries.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    let health_uri = format!("/api/v1/projects/{}/notification-health", first.project_id);
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&health_uri)
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let health_text = String::from_utf8(
        to_bytes(health.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!health_text.contains("secret"));
    assert!(!health_text.contains(&url));
    let health: serde_json::Value = serde_json::from_str(&health_text).unwrap();
    assert_eq!(health["delivery_enabled"], true);
    assert_eq!(health["state"], "idle");
    assert!(health["observed_at"].is_string());

    let foreign_health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/projects/{}/notification-health",
                    second.project_id
                ))
                .header(COOKIE, format!("okoscope_session={first_session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign_health.status(), StatusCode::NOT_FOUND);
    let unauthorized_health = app
        .oneshot(
            Request::builder()
                .uri(&health_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized_health.status(), StatusCode::UNAUTHORIZED);
    task.abort();
}
