use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use server::{
    auth::{SESSION_COOKIE, SessionToken},
    health,
    web_api::WebApiConfig,
};
use tower::ServiceExt;
use uuid::Uuid;

async fn super_admin(pool: &sqlx::PgPool, suffix: &str) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
    )
    .bind(user_id)
    .bind(format!("admin-{suffix}@example.test"))
    .bind("x".repeat(32))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO platform_role_assignments(user_id,role) VALUES($1,'super_admin')")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,token_hash,expires_at,privileged_until) VALUES($1,$2,$3,now()+interval '1 hour',now()+interval '15 minutes')")
        .bind(Uuid::new_v4()).bind(user_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    (user_id, token.expose().to_owned())
}

fn revoke_request(target: Uuid, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/platform/users/{target}/roles/super-admin"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={token}"))
        .header(header::ORIGIN, "https://ui.example.com")
        .body(Body::empty())
        .unwrap()
}

async fn tenant_user(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    email: &str,
    organization_role: &str,
) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash,email_verified_at,display_name) VALUES($1,$2,$3,now(),$2)")
        .bind(user_id).bind(email).bind("x".repeat(32)).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(organization_role)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(organization_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    (user_id, token.expose().to_owned())
}

fn eligible_request(project_id: Uuid, token: &str) -> Request<Body> {
    Request::builder()
        .uri(format!(
            "/api/v1/projects/{project_id}/eligible-organization-members"
        ))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={token}"))
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn concurrent_revocation_preserves_one_super_admin(pool: sqlx::PgPool) {
    let (first_id, first_token) = super_admin(&pool, "first").await;
    let (second_id, second_token) = super_admin(&pool, "second").await;
    let config = WebApiConfig::new(vec!["https://ui.example.com".into()]).unwrap();
    let app = health::router(pool.clone(), true, None, &config);
    let first = app.clone().oneshot(revoke_request(second_id, &first_token));
    let second = app.oneshot(revoke_request(first_id, &second_token));
    let (first, second) = tokio::join!(first, second);
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert!(statuses.contains(&StatusCode::NO_CONTENT));
    assert!(
        statuses
            .iter()
            .any(|status| { matches!(status, &StatusCode::CONFLICT | &StatusCode::UNAUTHORIZED) })
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform_role_assignments WHERE revoked_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 1);

    let surviving_token = if statuses[0] == StatusCode::NO_CONTENT {
        &first_token
    } else {
        &second_token
    };
    let audit = health::router(pool.clone(), true, None, &config)
        .oneshot(
            Request::builder()
                .uri("/api/v1/platform/audit")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={surviving_token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(audit.status(), StatusCode::OK);
    let body = to_bytes(audit.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    for secret in [
        surviving_token.as_str(),
        "password",
        "password_hash",
        "token_digest",
        "recipient_email",
    ] {
        assert!(!body.contains(secret), "audit response exposed {secret}");
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn project_admin_lists_only_eligible_organization_members(pool: sqlx::PgPool) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,'eligible-org','Eligible Org')")
        .bind(organization_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'eligible-project','Eligible Project')")
        .bind(project_id).bind(organization_id).execute(&pool).await.unwrap();
    let (actor_id, actor_token) =
        tenant_user(&pool, organization_id, "actor@example.test", "member").await;
    let (eligible_id, _) =
        tenant_user(&pool, organization_id, "eligible@example.test", "member").await;
    sqlx::query("INSERT INTO project_memberships(organization_id,project_id,user_id,role) VALUES($1,$2,$3,'admin')")
        .bind(organization_id).bind(project_id).bind(actor_id).execute(&pool).await.unwrap();

    let config = WebApiConfig::new(vec!["https://ui.example.com".into()]).unwrap();
    let app = health::router(pool.clone(), true, None, &config);
    let response = app
        .clone()
        .oneshot(eligible_request(project_id, &actor_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["user_id"], eligible_id.to_string());

    sqlx::query("UPDATE project_memberships SET role='member' WHERE project_id=$1 AND user_id=$2")
        .bind(project_id)
        .bind(actor_id)
        .execute(&pool)
        .await
        .unwrap();
    let denied = app
        .oneshot(eligible_request(project_id, &actor_token))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}
