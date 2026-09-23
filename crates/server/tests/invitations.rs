use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use server::{
    auth::{SessionToken, hash_password},
    invitation_api,
    transactional_mail::{CapturingSender, MailConfig, MailService, process_once},
    web_api::{InvitationConfig, WebApiConfig},
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

fn config() -> WebApiConfig {
    WebApiConfig::new(vec!["https://ui.example.com".into()])
        .unwrap()
        .with_user_auth(false, false, std::time::Duration::from_secs(3600))
        .with_access_policy(
            server::web_api::OrganizationMode::Multiple,
            InvitationConfig {
                lifetime: std::time::Duration::from_secs(7 * 86_400),
                create_limit_per_hour: 20,
                resend_limit_per_hour: 5,
            },
        )
        .with_mail(MailConfig {
            enabled: true,
            public_web_url: url::Url::parse("https://ui.example.com").unwrap(),
            encryption_key: [11; 32],
            ..MailConfig::default()
        })
}

fn app(pool: sqlx::PgPool, config: &WebApiConfig) -> Router {
    server::web_api::router(invitation_api::router(pool, config), config)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap()
}

async fn fixture_user(
    pool: &sqlx::PgPool,
    organization_id: Option<Uuid>,
    email: &str,
    role: &str,
) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash,email_verified_at,display_name) VALUES($1,$2,$3,now(),$4)")
        .bind(user_id).bind(email)
        .bind(hash_password("correct horse battery staple").unwrap())
        .bind(email.split('@').next().unwrap()).execute(pool).await.unwrap();
    if let Some(organization_id) = organization_id {
        sqlx::query(
            "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(organization_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    (user_id, token.expose().to_owned())
}

async fn fixture_organization(pool: &sqlx::PgPool, slug: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,$3)")
        .bind(id)
        .bind(slug)
        .bind(format!("{slug} org"))
        .execute(pool)
        .await
        .unwrap();
    id
}

fn authenticated(method: &str, uri: String, token: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("okoscope_session={token}"))
        .header(header::ORIGIN, "https://ui.example.com")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

async fn invitation_token(
    pool: sqlx::PgPool,
    config: &WebApiConfig,
    sender: Arc<CapturingSender>,
    message_index: usize,
) -> String {
    process_once(&MailService::with_sender(
        pool,
        config.mail.clone(),
        sender.clone(),
    ))
    .await
    .unwrap();
    sender.messages()[message_index]
        .text
        .split("#token=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn organization_invitation_inspection_and_new_user_acceptance_are_atomic(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "atomic").await;
    let (_, owner_token) =
        fixture_user(&pool, Some(organization_id), "owner@example.com", "owner").await;
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations"),
            &owner_token,
            r#"{"email":" New@Example.COM ","role":"member","locale":"ru"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        created.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        created.status(),
        StatusCode::CREATED,
        "{}",
        json(created).await
    );
    let state: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM invitations),(SELECT count(*) FROM transactional_mail_outbox)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(state, (1, 1));
    let sender = Arc::new(CapturingSender::default());
    let token = invitation_token(pool.clone(), &config, sender, 0).await;
    let inspected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invitations/inspections")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspected.status(), StatusCode::OK);
    assert_eq!(
        inspected.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let inspection = json(inspected).await;
    assert_eq!(inspection["account_state"], "new_user");
    assert_eq!(inspection["role"], "member");
    let accepted = app.clone().oneshot(
        Request::builder().method("POST").uri("/api/v1/invitations/acceptances/new-user")
            .header(header::ORIGIN, "https://ui.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"token":"{token}","password":"correct horse battery staple","display_name":"New User","locale":"ru"}}"#))).unwrap(),
    ).await.unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::CREATED,
        "{}",
        json(accepted).await
    );
    assert!(accepted.headers().get(header::SET_COOKIE).is_some());
    assert_eq!(
        accepted.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let granted: (bool, bool, i64) = sqlx::query_as("SELECT u.email_verified_at IS NOT NULL,EXISTS(SELECT 1 FROM organization_memberships m WHERE m.user_id=u.id AND m.organization_id=$1 AND m.role='member'),(SELECT count(*) FROM access_audit_records WHERE action='invitation.accepted') FROM users u WHERE u.email='new@example.com'")
        .bind(organization_id).fetch_one(&pool).await.unwrap();
    assert_eq!(granted, (true, true, 1));
    let replay = app.oneshot(
        Request::builder().method("POST").uri("/api/v1/invitations/acceptances/new-user")
            .header(header::ORIGIN, "https://ui.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"token":"{token}","password":"correct horse battery staple","display_name":"New User","locale":"ru"}}"#))).unwrap(),
    ).await.unwrap();
    assert_eq!(replay.status(), StatusCode::GONE);
    assert_eq!(
        replay.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn project_invitation_grants_only_base_organization_and_target_project(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "project-grant").await;
    let (_, owner_token) = fixture_user(
        &pool,
        Some(organization_id),
        "project-owner@example.com",
        "owner",
    )
    .await;
    let project_id = Uuid::new_v4();
    let other_project_id = Uuid::new_v4();
    sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$3,'target','Target'),($2,$3,'other','Other')")
        .bind(project_id).bind(other_project_id).bind(organization_id).execute(&pool).await.unwrap();
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/projects/{project_id}/invitations"),
            &owner_token,
            r#"{"email":"project-member@example.com","role":"member","locale":"en"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = invitation_token(
        pool.clone(),
        &config,
        Arc::new(CapturingSender::default()),
        0,
    )
    .await;
    let accepted = app.oneshot(
        Request::builder().method("POST").uri("/api/v1/invitations/acceptances/new-user")
            .header(header::ORIGIN, "https://ui.example.com").header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"token":"{token}","password":"correct horse battery staple","display_name":"Project Member","locale":"en"}}"#))).unwrap(),
    ).await.unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::CREATED,
        "{}",
        json(accepted).await
    );
    let grants: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE u.email='project-member@example.com' AND m.organization_id=$1 AND m.role='member'),(SELECT count(*) FROM project_memberships m JOIN users u ON u.id=m.user_id WHERE u.email='project-member@example.com' AND m.project_id=$2 AND m.role='member'),(SELECT count(*) FROM project_memberships m JOIN users u ON u.id=m.user_id WHERE u.email='project-member@example.com' AND m.project_id=$3)")
        .bind(organization_id).bind(project_id).bind(other_project_id).fetch_one(&pool).await.unwrap();
    assert_eq!(grants, (1, 1, 0));
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn resend_rotates_token_and_revoke_is_immediate(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "rotation").await;
    let (_, owner_token) = fixture_user(
        &pool,
        Some(organization_id),
        "rotation-owner@example.com",
        "owner",
    )
    .await;
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations"),
            &owner_token,
            r#"{"email":"rotate@example.com","role":"member","locale":"en"}"#,
        ))
        .await
        .unwrap();
    let created_body = json(created).await;
    let first_id = created_body["id"].as_str().unwrap();
    let sender = Arc::new(CapturingSender::default());
    let first_token = invitation_token(pool.clone(), &config, sender.clone(), 0).await;
    let resent = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations/{first_id}/resend"),
            &owner_token,
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(resent.status(), StatusCode::CREATED);
    let resent_body = json(resent).await;
    let replacement_id = resent_body["id"].as_str().unwrap();
    let second_token = invitation_token(pool.clone(), &config, sender, 1).await;
    assert_ne!(first_token, second_token);
    assert_eq!(inspect_status(&app, &first_token).await, StatusCode::GONE);
    assert_eq!(inspect_status(&app, &second_token).await, StatusCode::OK);
    let revoked = app
        .clone()
        .oneshot(authenticated(
            "DELETE",
            format!("/api/v1/organizations/{organization_id}/invitations/{replacement_id}"),
            &owner_token,
            "{}",
        ))
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert_eq!(inspect_status(&app, &second_token).await, StatusCode::GONE);
}

async fn inspect_status(app: &Router, token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/invitations/inspections")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn existing_user_requires_matching_verified_identity_and_replay_is_idempotent(
    pool: sqlx::PgPool,
) {
    let organization_id = fixture_organization(&pool, "existing").await;
    let (_, owner_token) = fixture_user(
        &pool,
        Some(organization_id),
        "existing-owner@example.com",
        "owner",
    )
    .await;
    let (recipient_id, recipient_token) =
        fixture_user(&pool, None, "recipient@example.com", "member").await;
    let (_, other_token) = fixture_user(&pool, None, "other@example.com", "member").await;
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations"),
            &owner_token,
            r#"{"email":"recipient@example.com","role":"admin","locale":"en"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = invitation_token(
        pool.clone(),
        &config,
        Arc::new(CapturingSender::default()),
        0,
    )
    .await;
    let mismatch = accept_existing(&app, &other_token, &token).await;
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let unchanged: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id=$1 AND user_id=$2)",
    )
    .bind(organization_id)
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(unchanged);
    assert_eq!(
        accept_existing(&app, &recipient_token, &token)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        accept_existing(&app, &recipient_token, &token)
            .await
            .status(),
        StatusCode::OK
    );
    let role: String = sqlx::query_scalar(
        "SELECT role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",
    )
    .bind(organization_id)
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role, "admin");
}

async fn accept_existing(app: &Router, session: &str, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(authenticated(
            "POST",
            "/api/v1/invitations/acceptances/existing-user".into(),
            session,
            format!(r#"{{"token":"{token}"}}"#),
        ))
        .await
        .unwrap()
}

fn canonical_token(byte: u8) -> (String, Vec<u8>) {
    let token = format!("oko_invitation_v1_{}", URL_SAFE_NO_PAD.encode([byte; 32]));
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    (token, digest)
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn unusable_tokens_are_non_enumerating_and_disabled_mail_is_atomic(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "unusable").await;
    let (owner_id, owner_token) = fixture_user(
        &pool,
        Some(organization_id),
        "unusable-owner@example.com",
        "owner",
    )
    .await;
    let disabled_config = WebApiConfig::new(vec!["https://ui.example.com".into()]).unwrap();
    let disabled_app = app(pool.clone(), &disabled_config);
    let unavailable = disabled_app
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations"),
            &owner_token,
            r#"{"email":"no-mail@example.com","role":"member","locale":"en"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM invitations),(SELECT count(*) FROM transactional_mail_outbox)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (0, 0));
    let config = config();
    let live_app = app(pool.clone(), &config);
    let (expired_token, digest) = canonical_token(31);
    let invitation_id = Uuid::new_v4();
    sqlx::query("INSERT INTO invitations(id,organization_id,recipient_email,role,inviter_user_id,locale,token_digest,expires_at,retain_until) VALUES($1,$2,'expired@example.com','member',$3,'en',$4,now()+interval '1 day',now()+interval '366 days')")
        .bind(invitation_id).bind(organization_id).bind(owner_id).bind(digest)
        .execute(&pool).await.unwrap();
    sqlx::query("UPDATE invitations SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE id=$1")
        .bind(invitation_id).execute(&pool).await.unwrap();
    let (unknown_token, _) = canonical_token(32);
    for token in ["malformed".to_owned(), unknown_token, expired_token] {
        let response = live_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/invitations/inspections")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(json(response).await["error"], "invitation_unusable");
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn concurrent_acceptance_consumes_once_without_duplicate_membership(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "concurrent").await;
    let (_, owner_token) = fixture_user(
        &pool,
        Some(organization_id),
        "concurrent-owner@example.com",
        "owner",
    )
    .await;
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/organizations/{organization_id}/invitations"),
            &owner_token,
            r#"{"email":"race@example.com","role":"member","locale":"en"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = invitation_token(
        pool.clone(),
        &config,
        Arc::new(CapturingSender::default()),
        0,
    )
    .await;
    let body = format!(
        r#"{{"token":"{token}","password":"correct horse battery staple","display_name":"Race User","locale":"en"}}"#
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/invitations/acceptances/new-user")
            .header(header::ORIGIN, "https://ui.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let (first, second) = tokio::join!(
        app.clone().oneshot(request()),
        app.clone().oneshot(request())
    );
    let mut statuses = [first.unwrap().status(), second.unwrap().status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::CREATED, StatusCode::GONE]);
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM users WHERE email='race@example.com'),(SELECT count(*) FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE u.email='race@example.com' AND m.organization_id=$1)")
        .bind(organization_id).fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 1));
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn first_owner_acceptance_activates_pending_organization(pool: sqlx::PgPool) {
    let organization_id = fixture_organization(&pool, "pending-owner").await;
    sqlx::query("UPDATE organizations SET status='pending_owner' WHERE id=$1")
        .bind(organization_id)
        .execute(&pool)
        .await
        .unwrap();
    let (super_id, super_token) = fixture_user(&pool, None, "platform@example.com", "member").await;
    sqlx::query("INSERT INTO platform_role_assignments(user_id,role) VALUES($1,'super_admin')")
        .bind(super_id)
        .execute(&pool)
        .await
        .unwrap();
    let config = config();
    let app = app(pool.clone(), &config);
    let created = app
        .clone()
        .oneshot(authenticated(
            "POST",
            format!("/api/v1/platform/organizations/{organization_id}/invitations"),
            &super_token,
            r#"{"email":"first-owner@example.com","role":"owner","locale":"en"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(
        created.status(),
        StatusCode::CREATED,
        "{}",
        json(created).await
    );
    let token = invitation_token(
        pool.clone(),
        &config,
        Arc::new(CapturingSender::default()),
        0,
    )
    .await;
    let accepted = app.oneshot(
        Request::builder().method("POST").uri("/api/v1/invitations/acceptances/new-user")
            .header(header::ORIGIN, "https://ui.example.com").header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"token":"{token}","password":"correct horse battery staple","display_name":"First Owner","locale":"en"}}"#))).unwrap(),
    ).await.unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::CREATED,
        "{}",
        json(accepted).await
    );
    let state: (String, i64) = sqlx::query_as("SELECT status,(SELECT count(*) FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='owner' AND u.email='first-owner@example.com') FROM organizations WHERE id=$1")
        .bind(organization_id).fetch_one(&pool).await.unwrap();
    assert_eq!(state, ("active".into(), 1));
}
