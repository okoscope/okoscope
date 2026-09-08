use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use server::{health, onboarding::AgentInstallationMetadata, web_api::WebApiConfig};
use tower::ServiceExt;

const SETUP_TOKEN: &str = "a-setup-token-with-at-least-thirty-two-bytes";

fn metadata() -> AgentInstallationMetadata {
    AgentInstallationMetadata {
        chart_reference: "oci://registry.example/okoscope-agent".into(),
        chart_version: "1.2.3".into(),
        recommended_agent_version: "1.2.3".into(),
        minimum_agent_version: "1.1.0".into(),
        configuration_schema_version: 1,
        grpc_endpoint: "grpc.example.com:443".into(),
        tls_mode: "system".into(),
        ca_secret_name: None,
        ca_secret_key: None,
        namespace: "okoscope-system".into(),
        credential_secret_name: "okoscope-agent-credentials".into(),
        credential_secret_key: "application-token".into(),
        supported_workload_kinds: vec!["Deployment".into()],
    }
}

fn app(pool: sqlx::PgPool) -> axum::Router {
    let config = WebApiConfig::default()
        .with_setup_token(Some(SETUP_TOKEN))
        .with_agent_installation(Some(metadata()))
        .with_user_auth(false, false, std::time::Duration::from_secs(3600));
    health::router(pool, true, None, &config)
}

fn expired_app(pool: sqlx::PgPool) -> axum::Router {
    let config = WebApiConfig::default()
        .with_setup_token(Some(SETUP_TOKEN))
        .with_setup_token_expiry(Some(chrono::Utc::now() - chrono::Duration::seconds(1)))
        .with_user_auth(false, false, std::time::Duration::from_secs(3600));
    health::router(pool, true, None, &config)
}

fn public_registration_app(pool: sqlx::PgPool) -> axum::Router {
    let config = WebApiConfig::default()
        .with_setup_token(Some(SETUP_TOKEN))
        .with_user_auth(true, false, std::time::Duration::from_secs(3600));
    health::router(pool, true, None, &config)
}

fn setup_body(token: &str, suffix: &str) -> String {
    format!(
        r#"{{"setup_token":"{token}","email":"owner{suffix}@example.com","password":"correct horse battery staple","organization_slug":"org{suffix}","organization_name":"Org {suffix}","project_slug":"default","project_name":"Default"}}"#
    )
}

async fn call(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap()
}

fn post_json(uri: &str, body: String, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, "http://localhost")
            .header(header::HOST, "localhost");
    }
    request.body(Body::from(body)).unwrap()
}

async fn claim(app: &axum::Router, suffix: &str) -> (String, serde_json::Value) {
    let response = call(
        app,
        post_json(
            "/api/v1/setup/complete",
            setup_body(SETUP_TOKEN, suffix),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (cookie, json(response).await)
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn setup_is_atomic_single_use_and_secret_safe(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    let invalid = call(
        &app,
        post_json(
            "/api/v1/setup/complete",
            setup_body("invalid-invalid-invalid-invalid-invalid", "bad"),
            None,
        ),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert!(
        !String::from_utf8(
            to_bytes(invalid.into_body(), 1_048_576)
                .await
                .unwrap()
                .to_vec()
        )
        .unwrap()
        .contains("invalid-invalid")
    );

    let (cookie, body) = claim(&app, "one").await;
    assert_eq!(body["role"], "owner");
    assert!(!cookie.contains(SETUP_TOKEN));
    let counts: (i64, i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM organizations),(SELECT count(*) FROM organization_memberships WHERE role='owner'),(SELECT count(*) FROM projects)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 1, 1, 1));

    let replay = call(
        &app,
        post_json(
            "/api/v1/setup/complete",
            setup_body(SETUP_TOKEN, "two"),
            None,
        ),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(json(replay).await["error"], "setup_already_completed");
    let status = call(
        &app,
        Request::builder()
            .uri("/api/v1/setup/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(json(status).await["state"], "ready");
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn public_registration_skips_private_first_owner_gate(pool: sqlx::PgPool) {
    let app = public_registration_app(pool);
    let status = call(
        &app,
        Request::builder()
            .uri("/api/v1/setup/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(json(status).await["state"], "ready");
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn concurrent_setup_creates_exactly_one_owner(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    let first = call(
        &app,
        post_json(
            "/api/v1/setup/complete",
            setup_body(SETUP_TOKEN, "alpha"),
            None,
        ),
    );
    let second = call(
        &app,
        post_json(
            "/api/v1/setup/complete",
            setup_body(SETUP_TOKEN, "beta"),
            None,
        ),
    );
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.status(), second.status()];
    assert!(statuses.contains(&StatusCode::CREATED));
    assert!(statuses.contains(&StatusCode::CONFLICT));
    let owners: i64 =
        sqlx::query_scalar("SELECT count(*) FROM organization_memberships WHERE role='owner'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(owners, 1);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn expired_setup_is_bounded_and_creates_nothing(pool: sqlx::PgPool) {
    let app = expired_app(pool.clone());
    let status = call(
        &app,
        Request::builder()
            .uri("/api/v1/setup/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(json(status).await["state"], "setup_unavailable");
    let completion = call(
        &app,
        post_json(
            "/api/v1/setup/complete",
            setup_body(SETUP_TOKEN, "expired"),
            None,
        ),
    )
    .await;
    assert_eq!(completion.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(completion).await["error"], "invalid_setup_token");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

fn installation_body(cluster: &str, name: &str) -> String {
    format!(
        r#"{{"cluster_name":"{cluster}","workload":{{"namespace":"production","kind":"Deployment","name":"{name}"}}}}"#
    )
}

fn installation_uri(body: &serde_json::Value) -> String {
    format!(
        "/api/v1/projects/{}/applications/{}/installations",
        body["project_id"].as_str().unwrap(),
        body["application_id"]
            .as_str()
            .unwrap_or("00000000-0000-0000-0000-000000000000")
    )
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn installation_resume_update_replace_and_readiness_are_safe(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    let (cookie, setup) = claim(&app, "install").await;
    let application_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'app','App')")
        .bind(application_id).bind(setup["organization_id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap()).bind(setup["project_id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap()).execute(&pool).await.unwrap();
    let uri = installation_uri(
        &serde_json::json!({"project_id":setup["project_id"],"application_id":application_id}),
    );
    let create = call(
        &app,
        Request::builder()
            .method("POST")
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "http://localhost")
            .header(header::HOST, "localhost")
            .header("idempotency-key", "one")
            .body(Body::from(installation_body("Cluster A", "payments")))
            .unwrap(),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let created = json(create).await;
    assert!(created["command"]["ca_secret_name"].is_null());
    assert!(created["command"]["ca_secret_key"].is_null());
    let token = created["credential"]["token"].as_str().unwrap();
    assert!(!token.is_empty());
    let replay = call(
        &app,
        Request::builder()
            .method("POST")
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "http://localhost")
            .header(header::HOST, "localhost")
            .header("idempotency-key", "one")
            .body(Body::from(installation_body("Cluster A", "payments")))
            .unwrap(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert!(json(replay).await["credential"].is_null());

    let item_uri = format!(
        "{}/{}",
        uri,
        created["installation"]["id"].as_str().unwrap()
    );
    let update = call(
        &app,
        Request::builder()
            .method("PATCH")
            .uri(&item_uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "http://localhost")
            .header(header::HOST, "localhost")
            .body(Body::from(installation_body("Cluster B", "payments-v2")))
            .unwrap(),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let updated = json(update).await;
    assert_eq!(updated["cluster_name"], "Cluster B");
    assert_eq!(
        updated["credential_id"],
        created["installation"]["credential_id"]
    );

    let replacement = call(
        &app,
        post_json(
            &format!("{item_uri}/replace-credential"),
            "{}".into(),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(replacement.status(), StatusCode::OK);
    assert_eq!(replacement.headers()[header::CACHE_CONTROL], "no-store");
    let replacement = json(replacement).await;
    assert_ne!(replacement["id"], created["installation"]["credential_id"]);

    let readiness = call(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/projects/{}/applications/{application_id}/connection-readiness",
                setup["project_id"].as_str().unwrap()
            ))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(json(readiness).await["state"], "waiting_for_agent");
}
