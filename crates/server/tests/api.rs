use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::COOKIE},
};
use chrono::Utc;
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, NetworkAccept, NetworkAddressFamily,
    NetworkConnect, NetworkConnectOutcome, ProcessExec, ProcessIdentity, RuntimeEvent,
};
use server::{
    api,
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    ingestion::{IngestionContext, persist_batch},
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
        project_slug: "payments".into(),
        project_name: "Payments".into(),
        cluster_external_id: "test".into(),
        cluster_name: "Test".into(),
        application_slug: "payment-api".into(),
        application_name: "Payment API".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn event(project_id: Uuid, application_id: Uuid) -> RuntimeEvent {
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
            container_id: "container-id".into(),
            container_name: "payment-api".into(),
            workload_uid: "workload-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "payment-api".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 42,
            pid: 10,
            tgid: 10,
            command: "sh".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: "/bin/sh".into(),
            parent_command: None,
        }),
    }
}

async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("api-test-password").unwrap())
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

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn list_and_detail_are_authenticated_paginated_and_tenant_safe(pool: sqlx::PgPool) {
    let mut first_config = config("first-api");
    let first = bootstrap(&pool, &first_config).await.unwrap();
    first_config.api_credential = owner_session(&pool, &first).await;
    let mut second_config = config("second-api");
    let second = bootstrap(&pool, &second_config).await.unwrap();
    second_config.api_credential = owner_session(&pool, &second).await;
    let release_id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases (id,organization_id,project_id,application_id,version,deployed_at) VALUES ($1,$2,$3,$4,'v1',now())")
        .bind(release_id)
        .bind(first.organization_id)
        .bind(first.project_id)
        .bind(first.application_id)
        .execute(&pool)
        .await
        .unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id,organization_id,cluster_id,node_name,agent_version) VALUES ($1,$2,$3,'node-1','test')")
        .bind(agent_id).bind(first.organization_id).bind(first.cluster_id).execute(&pool).await.unwrap();
    let mut first_event = event(first.project_id, first.application_id);
    first_event.attribution.release = Some("v1".into());
    first_event.payload = EventPayload::NetworkConnect(
        NetworkConnect::new(
            NetworkAddressFamily::Ipv4,
            "203.0.113.7".parse().unwrap(),
            443,
            NetworkConnectOutcome::Succeeded,
            None,
        )
        .unwrap(),
    );
    let mut second_event = first_event.clone();
    second_event.id = Uuid::new_v4();
    persist_batch(
        &pool,
        IngestionContext {
            scope: SessionScope {
                organization_id: first.organization_id,
                cluster_id: first.cluster_id,
            },
            agent_id,
        },
        &[first_event, second_event],
    )
    .await
    .unwrap();
    let group_id: Uuid = sqlx::query_scalar("SELECT id FROM runtime_event_groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    let app = api::router(pool.clone());

    let unauthorized = app.clone().oneshot(Request::builder().uri("/api/v1/runtime-groups?project_id=00000000-0000-0000-0000-000000000000&application_id=00000000-0000-0000-0000-000000000000").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let list_uri = format!(
        "/api/v1/runtime-groups?project_id={}&application_id={}&event_kind=network.connect&status=open&release_id={}&first_seen_from=2020-01-01T00:00:00Z&first_seen_to=2100-01-01T00:00:00Z&last_seen_to=2100-01-01T00:00:00Z&limit=1",
        first.project_id, first.application_id, release_id
    );
    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(list_uri)
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(listed_body["items"].as_array().unwrap().len(), 1);
    assert_eq!(listed_body["items"][0]["event_kind"], "network.connect");
    assert_eq!(
        listed_body["items"][0]["semantic_summary"]["destination_address"],
        "203.0.113.7"
    );

    let detail = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/runtime-groups/{group_id}"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(detail.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(detail_body["occurrence_count"], 2);
    assert_eq!(detail_body["status"], "open");
    assert_eq!(detail_body["notification"]["state"], "pending");
    assert!(detail_body["first_seen_event_id"].is_string());
    assert_eq!(
        detail_body["representative_event"]["payload"]["data"]["outcome"],
        "succeeded"
    );
    sqlx::query("UPDATE outbox_messages SET materialized_at=now(),processed_at=now(),completion_reason='no_destinations' WHERE aggregate_id=$1")
        .bind(group_id)
        .execute(&pool)
        .await
        .unwrap();
    let no_destination = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/runtime-groups/{group_id}"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let no_destination_body: serde_json::Value = serde_json::from_slice(
        &to_bytes(no_destination.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        no_destination_body["notification"]["state"],
        "not_configured"
    );

    sqlx::query(
        "DELETE FROM outbox_messages WHERE aggregate_id=$1 AND topic='runtime_group.first_seen'",
    )
    .bind(group_id)
    .execute(&pool)
    .await
    .unwrap();
    let missing_outbox = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/runtime-groups/{group_id}"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_outbox.status(), StatusCode::OK);
    let missing_outbox_body: serde_json::Value = serde_json::from_slice(
        &to_bytes(missing_outbox.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        missing_outbox_body["notification"],
        serde_json::json!({
            "state": "not_configured",
            "delivery_count": 0,
            "succeeded_count": 0,
            "failed_count": 0,
        })
    );

    let occurrences = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/runtime-groups/{group_id}/occurrences?limit=1"
                ))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(occurrences.status(), StatusCode::OK);
    let occurrences_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(occurrences.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(occurrences_body["items"].as_array().unwrap().len(), 1);
    assert!(occurrences_body["next_cursor"].is_string());

    for (action, expected_status) in [
        ("acknowledge", "acknowledged"),
        ("resolve", "resolved"),
        ("reopen", "open"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/runtime-groups/{group_id}/{action}"))
                    .header(
                        COOKIE,
                        format!("{SESSION_COOKIE}={}", first_config.api_credential),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["status"], expected_status);
        assert!(body["status_changed_at"].is_string());
        assert!(body["status_changed_by"].is_string());
    }

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/runtime-groups/{group_id}/reopen"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        invalid.status(),
        StatusCode::OK,
        "target-state retry is idempotent"
    );

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/runtime-groups/{group_id}/reopen"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::OK);

    let lifecycle_request = || {
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/runtime-groups/{group_id}/acknowledge"))
            .header(
                COOKIE,
                format!("{SESSION_COOKIE}={}", first_config.api_credential),
            )
            .body(Body::empty())
            .unwrap()
    };
    let (concurrent_one, concurrent_two) = tokio::join!(
        app.clone().oneshot(lifecycle_request()),
        app.clone().oneshot(lifecycle_request())
    );
    assert_eq!(concurrent_one.unwrap().status(), StatusCode::OK);
    assert_eq!(concurrent_two.unwrap().status(), StatusCode::OK);

    let resolved = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/runtime-groups/{group_id}/resolve"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resolved.status(), StatusCode::OK);
    let mut repeated_after_resolution = event(first.project_id, first.application_id);
    repeated_after_resolution.attribution.release = Some("v1".into());
    repeated_after_resolution.payload = EventPayload::NetworkConnect(
        NetworkConnect::new(
            NetworkAddressFamily::Ipv4,
            "203.0.113.7".parse().unwrap(),
            443,
            NetworkConnectOutcome::Failed,
            Some(111),
        )
        .unwrap(),
    );
    persist_batch(
        &pool,
        IngestionContext {
            scope: SessionScope {
                organization_id: first.organization_id,
                cluster_id: first.cluster_id,
            },
            agent_id,
        },
        &[repeated_after_resolution],
    )
    .await
    .unwrap();
    let (status_after_occurrence, count_after_occurrence): (String, i64) =
        sqlx::query_as("SELECT status,occurrence_count FROM runtime_event_groups WHERE id=$1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status_after_occurrence, "resolved");
    assert_eq!(count_after_occurrence, 3);
    let invalid_transition = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/runtime-groups/{group_id}/acknowledge"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", first_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_transition.status(), StatusCode::BAD_REQUEST);

    let hidden_lifecycle = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/runtime-groups/{group_id}/reopen"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", second_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hidden_lifecycle.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_messages WHERE aggregate_id=$1")
            .bind(group_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    let hidden = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/runtime-groups/{group_id}"))
                .header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", second_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    assert_ne!(first.organization_id, second.organization_id);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn accepted_connection_summary_is_safe_and_occurrences_are_bounded(pool: sqlx::PgPool) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cfg = config("inbound-api");
    let ids = bootstrap(&pool, &cfg).await.unwrap();
    let session = owner_session(&pool, &ids).await;
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-1','test')")
        .bind(agent_id).bind(ids.organization_id).bind(ids.cluster_id)
        .execute(&pool).await.unwrap();
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        },
        agent_id,
    };
    let mut first = event(ids.project_id, ids.application_id);
    first.payload = EventPayload::NetworkAccept(
        NetworkAccept::new(
            NetworkAddressFamily::Ipv4,
            "0.0.0.0".parse().unwrap(),
            8443,
            "203.0.113.7".parse().unwrap(),
            51_000,
        )
        .unwrap(),
    );
    let mut second = first.clone();
    second.id = Uuid::new_v4();
    second.payload = EventPayload::NetworkAccept(
        NetworkAccept::new(
            NetworkAddressFamily::Ipv4,
            "0.0.0.0".parse().unwrap(),
            8443,
            "198.51.100.8".parse().unwrap(),
            52_000,
        )
        .unwrap(),
    );
    assert_eq!(
        persist_batch(&pool, context, &[first, second])
            .await
            .unwrap(),
        2
    );
    let group_id: Uuid = sqlx::query_scalar("SELECT id FROM runtime_event_groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    let app = api::router(pool.clone());
    let list = app.clone().oneshot(
        Request::builder()
            .uri(format!("/api/v1/runtime-groups?project_id={}&application_id={}&event_kind=network.accept", ids.project_id, ids.application_id))
            .header(COOKIE, format!("{SESSION_COOKIE}={session}"))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list: serde_json::Value =
        serde_json::from_slice(&to_bytes(list.into_body(), usize::MAX).await.unwrap()).unwrap();
    let summary = &list["items"][0]["semantic_summary"];
    assert_eq!(summary["local_address"], "0.0.0.0");
    assert_eq!(summary["local_port"], 8443);
    assert!(summary.get("remote_address").is_none());
    assert!(summary.get("remote_port").is_none());

    let occurrences = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/runtime-groups/{group_id}/occurrences?limit=1"
                ))
                .header(COOKIE, format!("{SESSION_COOKIE}={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = occurrences.status();
    let occurrences: serde_json::Value =
        serde_json::from_slice(&to_bytes(occurrences.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(status, StatusCode::OK, "{occurrences}");
    assert_eq!(occurrences["items"].as_array().unwrap().len(), 1);
    assert!(occurrences["next_cursor"].is_string());
    assert!(occurrences["items"][0]["payload"]["data"]["remote_address"].is_string());
}
