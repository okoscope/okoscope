use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use server::{
    auth::{SessionToken, hash_password},
    notification::retention_settings::{self, RetentionPolicy},
};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn tenant(pool: &PgPool) -> (Uuid, Uuid) {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Retention')")
        .bind(organization)
        .bind(organization.to_string())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','Project')")
        .bind(project)
        .bind(organization)
        .execute(pool)
        .await
        .unwrap();
    (organization, project)
}

async fn session(pool: &PgPool, org: Uuid, role: &str) -> String {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .bind(hash_password("retention settings password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(org)
    .bind(user)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user).bind(org).bind(token.digest().to_vec()).execute(pool).await.unwrap();
    token.expose().to_owned()
}

fn app(pool: PgPool) -> Router {
    server::health::router(
        pool,
        true,
        None,
        &server::web_api::WebApiConfig::new(vec!["https://ui.example.test".into()]).unwrap(),
    )
}

async fn call(
    app: &Router,
    token: &str,
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", format!("okoscope_session={token}"))
                .header("origin", "https://ui.example.test")
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inheritance_override_reset_and_authorization(pool: PgPool) {
    let (org, project) = tenant(&pool).await;
    let (other, other_project) = tenant(&pool).await;
    let owner = session(&pool, org, "owner").await;
    let member = session(&pool, org, "member").await;
    let app = app(pool.clone());
    let org_path = format!("/api/v1/organizations/{org}/notification-retention");
    let path = format!("/api/v1/projects/{project}/notification-retention");
    let (status, initial) = call(&app, &member, "GET", &path, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial["effective"]["enabled"], false);
    assert_eq!(initial["effective"]["history_days"], 90);
    assert!(initial["override"].is_null());
    assert_eq!(
        call(
            &app,
            &owner,
            "PUT",
            &org_path,
            r#"{"enabled":true,"history_days":30}"#
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, &member, "GET", &path, "").await.1["effective"]["history_days"],
        30
    );
    assert_eq!(
        call(
            &app,
            &owner,
            "PUT",
            &path,
            r#"{"enabled":false,"history_days":7}"#
        )
        .await
        .1["source"],
        "project"
    );
    call(
        &app,
        &owner,
        "PUT",
        &org_path,
        r#"{"enabled":true,"history_days":60}"#,
    )
    .await;
    assert_eq!(
        call(&app, &owner, "GET", &path, "").await.1["effective"]["history_days"],
        7
    );
    assert_eq!(
        call(&app, &owner, "GET", &path, "").await.1["inherited"]["history_days"],
        60
    );
    let reset = call(&app, &owner, "DELETE", &path, "").await;
    assert_eq!(reset.0, StatusCode::OK);
    assert_eq!(reset.1["source"], "organization");
    assert_eq!(reset.1["effective"]["history_days"], 60);
    for target in [&path, &org_path] {
        assert_eq!(
            call(
                &app,
                &member,
                "PUT",
                target,
                r#"{"enabled":true,"history_days":1}"#
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        for body in [
            r#"{"enabled":true,"history_days":0}"#,
            r#"{"enabled":true,"history_days":3651}"#,
            r#"{"enabled":true,"history_days":1.5}"#,
            r#"{"enabled":true}"#,
        ] {
            assert!(
                call(&app, &owner, "PUT", target, body)
                    .await
                    .0
                    .is_client_error()
            );
        }
    }
    assert_eq!(
        call(&app, &member, "DELETE", &path, "").await.0,
        StatusCode::FORBIDDEN
    );
    for target in [
        format!("/api/v1/organizations/{other}/notification-retention"),
        format!("/api/v1/projects/{other_project}/notification-retention"),
    ] {
        for method in ["GET", "PUT"] {
            assert_eq!(
                call(
                    &app,
                    &owner,
                    method,
                    &target,
                    r#"{"enabled":true,"history_days":1}"#
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
        }
    }
    let audited: bool = sqlx::query_scalar("SELECT notification_retention_updated_by IS NOT NULL AND notification_retention_updated_at IS NOT NULL FROM projects WHERE id=$1")
        .bind(project).fetch_one(&pool).await.unwrap();
    assert!(audited);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn legacy_import_is_once_and_new_organizations_keep_defaults(pool: PgPool) {
    let (old, _) = tenant(&pool).await;
    sqlx::query("UPDATE organizations SET notification_retention_initialized=false WHERE id=$1")
        .bind(old)
        .execute(&pool)
        .await
        .unwrap();
    let legacy = RetentionPolicy {
        enabled: true,
        history_days: 365,
    };
    let (a, b) = tokio::join!(
        retention_settings::initialize(&pool, legacy),
        retention_settings::initialize(&pool, legacy)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        retention_settings::organization(&pool, old).await.unwrap(),
        Some(legacy)
    );
    sqlx::query("UPDATE organizations SET notification_retention_enabled=false,notification_retention_days=7 WHERE id=$1")
        .bind(old).execute(&pool).await.unwrap();
    let (new, _) = tenant(&pool).await;
    retention_settings::initialize(&pool, legacy).await.unwrap();
    assert_eq!(
        retention_settings::organization(&pool, old).await.unwrap(),
        Some(RetentionPolicy {
            enabled: false,
            history_days: 7
        })
    );
    assert_eq!(
        retention_settings::organization(&pool, new).await.unwrap(),
        Some(RetentionPolicy {
            enabled: false,
            history_days: 90
        })
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn settings_put_requires_trusted_origin_and_allows_preflight(pool: PgPool) {
    let (org, _) = tenant(&pool).await;
    let token = session(&pool, org, "owner").await;
    let app = app(pool);
    let path = format!("/api/v1/organizations/{org}/notification-retention");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&path)
                .header("cookie", format!("okoscope_session={token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true,"history_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri(&path)
                .header("origin", "https://ui.example.test")
                .header("access-control-request-method", "PUT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.headers()["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("PUT")
    );
}
