use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use server::{
    bootstrap::{BootstrapConfig, bootstrap},
    health,
    notification::NotificationService,
    notification_config::NotificationArgs,
    web_api::WebApiConfig,
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

fn request(uri: &str, credential: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(value) = credential {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {value}"));
    }
    builder.body(Body::empty()).unwrap()
}

fn notifications(pool: sqlx::PgPool, enabled: bool) -> NotificationService {
    let args = NotificationArgs {
        enabled,
        encryption_key: Some(hex::encode([7_u8; 32])),
        ..NotificationArgs::default()
    };
    NotificationService::new(pool, args.build(false).unwrap()).unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn browser_foundation_is_correlated_cors_safe_and_tenant_scoped(pool: sqlx::PgPool) {
    let first_config = config("web-first");
    let first = bootstrap(&pool, &first_config).await.unwrap();
    let second_config = config("web-second");
    let second = bootstrap(&pool, &second_config).await.unwrap();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,'1.0.0',now())")
        .bind(Uuid::new_v4()).bind(first.organization_id).bind(first.project_id).bind(first.application_id).execute(&pool).await.unwrap();
    let app = health::router(
        pool.clone(),
        true,
        Some(notifications(pool.clone(), false)),
        &WebApiConfig::new(vec!["https://ui.example.com".into()]).unwrap(),
    );

    let build = app
        .clone()
        .oneshot(request("/api/v1/build-info", None))
        .await
        .unwrap();
    assert_eq!(build.status(), StatusCode::OK);
    let request_id = build
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!request_id.is_empty());
    assert_eq!(build.headers()[header::CACHE_CONTROL], "no-store");
    let build = json(build).await;
    assert_eq!(build["api_version"], "v1");
    assert_eq!(build["required_database_migration"], 26);
    assert!(build.get("database_url").is_none());

    let notification_health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/projects/{}/notification-health",
                    first.project_id
                ))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", first_config.api_credential),
                )
                .header("x-request-id", "notification-health-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(notification_health.status(), StatusCode::OK);
    assert_eq!(
        notification_health.headers()["x-request-id"],
        "notification-health-1"
    );
    assert_eq!(
        notification_health.headers()[header::CACHE_CONTROL],
        "no-store"
    );
    let notification_health = json(notification_health).await;
    assert_eq!(notification_health["state"], "disabled");
    assert_eq!(notification_health["delivery_enabled"], false);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organization")
                .header("x-request-id", "ui-request-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.headers()["x-request-id"], "ui-request-1");
    assert_eq!(json(unauthorized).await["request_id"], "ui-request-1");

    let organization = app
        .clone()
        .oneshot(request(
            "/api/v1/organization",
            Some(&first_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(organization.status(), StatusCode::OK);
    assert_eq!(
        json(organization).await["id"],
        first.organization_id.to_string()
    );

    let projects = app
        .clone()
        .oneshot(request(
            "/api/v1/projects?limit=1",
            Some(&first_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(projects.status(), StatusCode::OK);
    let projects = json(projects).await;
    assert_eq!(projects["items"][0]["application_count"], 1);

    let application = app
        .clone()
        .oneshot(request(
            &format!(
                "/api/v1/projects/{}/applications/{}",
                first.project_id, first.application_id
            ),
            Some(&first_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(application.status(), StatusCode::OK);
    assert_eq!(json(application).await["release_count"], 1);

    let foreign = app
        .clone()
        .oneshot(request(
            &format!("/api/v1/projects/{}", first.project_id),
            Some(&second_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

    let preflight = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/v1/projects")
                .header(header::ORIGIN, "https://ui.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,x-request-id",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preflight.status(), StatusCode::OK);
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://ui.example.com"
    );
    assert!(
        preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/v1/projects")
                .header(header::ORIGIN, "https://evil.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        denied
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    assert_ne!(first.organization_id, second.organization_id);

    pool.close().await;
    let database_failure = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/projects/{}/notification-health",
                    first.project_id
                ))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", first_config.api_credential),
                )
                .header("x-request-id", "notification-health-db-failure")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(database_failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        json(database_failure).await["request_id"],
        "notification-health-db-failure"
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn navigation_pagination_is_stable_and_cursor_is_scoped(pool: sqlx::PgPool) {
    let owner_config = config("navigation-owner");
    let owner = bootstrap(&pool, &owner_config).await.unwrap();
    let empty_config = config("navigation-empty");
    let empty = bootstrap(&pool, &empty_config).await.unwrap();
    sqlx::query("DELETE FROM projects WHERE organization_id=$1")
        .bind(empty.organization_id)
        .execute(&pool)
        .await
        .unwrap();

    let mut project_ids = [Uuid::new_v4(), Uuid::new_v4()];
    project_ids.sort();
    for (index, project_id) in project_ids.into_iter().enumerate() {
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name,created_at) VALUES($1,$2,$3,$3,'2026-01-01T00:00:00Z')")
            .bind(project_id)
            .bind(owner.organization_id)
            .bind(format!("tied-{index}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    let app = health::router(pool, true, None, &WebApiConfig::default());

    let empty_page = json(
        app.clone()
            .oneshot(request(
                "/api/v1/projects",
                Some(&empty_config.api_credential),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(empty_page["items"].as_array().unwrap().len(), 0);

    let first_page = json(
        app.clone()
            .oneshot(request(
                "/api/v1/projects?limit=1",
                Some(&owner_config.api_credential),
            ))
            .await
            .unwrap(),
    )
    .await;
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = json(
        app.clone()
            .oneshot(request(
                &format!("/api/v1/projects?limit=1&cursor={cursor}"),
                Some(&owner_config.api_credential),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_ne!(first_page["items"][0]["id"], second_page["items"][0]["id"]);

    let foreign_cursor = app
        .clone()
        .oneshot(request(
            &format!("/api/v1/projects?cursor={}", empty.project_id),
            Some(&owner_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(foreign_cursor.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(foreign_cursor).await["error"], "invalid_request");

    let wrong_owner = app
        .oneshot(request(
            &format!(
                "/api/v1/projects/{}/applications/{}",
                project_ids[0], owner.application_id
            ),
            Some(&owner_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_owner.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn recovery_api_is_tenant_scoped_idempotent_and_correlated(pool: sqlx::PgPool) {
    let owner_config = config("recovery-api-owner");
    let owner = bootstrap(&pool, &owner_config).await.unwrap();
    let foreign_config = config("recovery-api-foreign");
    bootstrap(&pool, &foreign_config).await.unwrap();
    let destination_id = Uuid::new_v4();
    let delivery_id = Uuid::new_v4();
    sqlx::query("INSERT INTO webhook_destinations(id,organization_id,project_id,name,url,encrypted_secret,secret_nonce) VALUES($1,$2,$3,'receiver','https://receiver.example/hook',$4,$5)")
        .bind(destination_id).bind(owner.organization_id).bind(owner.project_id)
        .bind(vec![1_u8; 48]).bind(vec![2_u8; 24]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO notification_deliveries(id,organization_id,project_id,destination_id,origin,source,event_name,payload,status,attempt_count,max_attempts,terminal_at,last_error_class) VALUES($1,$2,$3,$4,'test','test','okoscope.test','{}','failed',1,3,now(),'timeout')")
        .bind(delivery_id).bind(owner.organization_id).bind(owner.project_id).bind(destination_id).execute(&pool).await.unwrap();
    let notification_service = notifications(pool.clone(), false);
    let app = health::router(
        pool,
        true,
        Some(notification_service),
        &WebApiConfig::default(),
    );

    let uri = format!(
        "/api/v1/projects/{}/notification-deliveries/{delivery_id}/retry",
        owner.project_id
    );
    let missing_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", owner_config.api_credential),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);

    let malformed_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", owner_config.api_credential),
                )
                .header("idempotency-key", "short")
                .header("x-request-id", "recovery-invalid-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        malformed_key.headers()["x-request-id"],
        "recovery-invalid-key"
    );

    let invalid_bearer = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(header::AUTHORIZATION, "Bearer invalid")
                .header("idempotency-key", "recovery-api-invalid-bearer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_bearer.status(), StatusCode::UNAUTHORIZED);

    let command = || {
        Request::builder()
            .method("POST")
            .uri(&uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", owner_config.api_credential),
            )
            .header("idempotency-key", "recovery-api-command-0001")
            .header("x-request-id", "recovery-api-request-1")
            .body(Body::empty())
            .unwrap()
    };
    let first = app.clone().oneshot(command()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
    let first = json(first).await;
    assert_eq!(first["replayed"], false);
    let repeated = json(app.clone().oneshot(command()).await.unwrap()).await;
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["operation_id"], first["operation_id"]);

    let foreign = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", foreign_config.api_credential),
                )
                .header("idempotency-key", "recovery-api-command-0002")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let operations = app
        .oneshot(request(
            &format!(
                "/api/v1/projects/{}/notification-recovery-operations?limit=1",
                owner.project_id
            ),
            Some(&owner_config.api_credential),
        ))
        .await
        .unwrap();
    assert_eq!(operations.status(), StatusCode::OK);
    assert_eq!(json(operations).await["items"].as_array().unwrap().len(), 1);
}
