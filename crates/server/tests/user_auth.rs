use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use server::auth::{SessionToken, hash_password};
use server::{user_auth, web_api::WebApiConfig};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

fn app(pool: sqlx::PgPool) -> Router {
    let mail = server::transactional_mail::MailConfig {
        enabled: true,
        public_web_url: url::Url::parse("https://ui.example.com").unwrap(),
        encryption_key: [3; 32],
        ..server::transactional_mail::MailConfig::default()
    };
    let config = WebApiConfig::new(vec!["https://ui.example.com".into()])
        .unwrap()
        .with_user_auth(true, true, std::time::Duration::from_secs(3600))
        .with_mail(mail);
    server::web_api::router(user_auth::router(pool, &config), &config)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap()
}

fn action_token(purpose: &str, byte: u8) -> (String, Vec<u8>) {
    let token = format!("oko_{purpose}_v1_{}", URL_SAFE_NO_PAD.encode([byte; 32]));
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    (token, digest)
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn registration_login_me_logout_and_revocation(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    let registration = app.clone().oneshot(
        Request::builder().method("POST").uri("/api/v1/auth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"email":" Owner@Example.COM ","password":"correct horse battery staple","organization_slug":"acme","organization_name":"Acme","locale":"ru"}"#)).unwrap()
    ).await.unwrap();
    assert_eq!(registration.status(), StatusCode::ACCEPTED);
    assert!(registration.headers().get(header::SET_COOKIE).is_none());
    let registration_body = json(registration).await;
    assert_eq!(registration_body["status"], "accepted");
    let pending_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"owner@example.com","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pending_login.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(pending_login).await["error"],
        "email_verification_required"
    );
    sqlx::query("UPDATE users SET email_verified_at=now() WHERE email='owner@example.com'")
        .execute(&pool)
        .await
        .unwrap();

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"owner@example.com","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let rotated_cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let me = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &rotated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(json(me).await["organization"]["slug"], "acme");

    sqlx::query(
        "UPDATE user_sessions \
         SET created_at=now()-interval '2 seconds', expires_at=now()-interval '1 second' \
         WHERE revoked_at IS NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    let expired = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &rotated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    let relogin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"owner@example.com","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let active_cookie = relogin.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &active_cookie)
                .header(header::ORIGIN, "https://ui.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert!(
        logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    let repeated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &active_cookie)
                .header(header::ORIGIN, "https://ui.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::NO_CONTENT);

    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, active_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

    sqlx::query("UPDATE users SET disabled_at=now() WHERE email='owner@example.com'")
        .execute(&pool)
        .await
        .unwrap();
    let disabled_login = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"owner@example.com","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disabled_login.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn verification_reset_password_change_and_locale_are_authoritative(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    let registration = app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"email":"owner@example.com","password":"correct horse battery staple","organization_slug":"secure","organization_name":"Secure","locale":"en"}"#)).unwrap()).await.unwrap();
    assert_eq!(registration.status(), StatusCode::ACCEPTED);
    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email='owner@example.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (verify_token, verify_digest) = action_token("verify_email", 1);
    sqlx::query("DELETE FROM user_email_actions WHERE user_id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_email_actions(id,user_id,purpose,token_digest,expires_at) VALUES($1,$2,'verify_email',$3,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(verify_digest).execute(&pool).await.unwrap();
    let confirm = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/email-verifications")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"token":"{verify_token}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirm.status(), StatusCode::NO_CONTENT);
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/email-verifications")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"token":"{verify_token}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"owner@example.com","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let locale = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/auth/preferences")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, "https://ui.example.com")
                .body(Body::from(r#"{"locale":"ru"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json(locale).await["user"]["preferred_locale"], "ru");

    let changed = app.clone().oneshot(Request::builder().method("PUT").uri("/api/v1/auth/password")
        .header(header::CONTENT_TYPE, "application/json").header(header::COOKIE, &cookie).header(header::ORIGIN, "https://ui.example.com")
        .body(Body::from(r#"{"current_password":"correct horse battery staple","new_password":"new correct horse battery staple"}"#)).unwrap()).await.unwrap();
    assert_eq!(changed.status(), StatusCode::OK);
    let rotated = changed.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_ne!(cookie, rotated);
    let old = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);

    let generic = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/password-reset-requests")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"unknown@example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(generic.status(), StatusCode::ACCEPTED);
    let (reset_token, reset_digest) = action_token("reset_password", 2);
    sqlx::query("INSERT INTO user_email_actions(id,user_id,purpose,token_digest,expires_at) VALUES($1,$2,'reset_password',$3,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(reset_digest).execute(&pool).await.unwrap();
    let reset = app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/auth/password-resets")
        .header(header::CONTENT_TYPE, "application/json").body(Body::from(format!(r#"{{"token":"{reset_token}","new_password":"reset correct horse battery staple"}}"#))).unwrap()).await.unwrap();
    assert_eq!(reset.status(), StatusCode::NO_CONTENT);
    let revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, rotated)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let relogin = app.oneshot(Request::builder().method("POST").uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json").body(Body::from(r#"{"email":"owner@example.com","password":"reset correct horse battery staple"}"#)).unwrap()).await.unwrap();
    assert_eq!(relogin.status(), StatusCode::OK);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn login_failure_is_uniform_and_registration_is_atomic(pool: sqlx::PgPool) {
    let app = app(pool.clone());
    for payload in [
        r#"{"email":"unknown@example.com","password":"wrong password value"}"#,
        r#"{"email":"malformed","password":"wrong password value"}"#,
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json(response).await["error"], "invalid_credentials");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
    let unavailable = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"unknown@example.com","password":"wrong password value"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json(unavailable).await;
    assert_eq!(body["error"], "internal_error");
    assert!(!body.to_string().contains("wrong password value"));
}

async fn fixture_session(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    email: &str,
    role: &str,
) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(email)
        .bind(hash_password("correct horse battery staple").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(organization_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    token.expose().to_owned()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn owner_member_and_cross_tenant_authorization_is_consistent(pool: sqlx::PgPool) {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organizations(id,slug,name) VALUES($1,'first','First'),($2,'second','Second')",
    )
    .bind(first)
    .bind(second)
    .execute(&pool)
    .await
    .unwrap();
    let owner = fixture_session(&pool, first, "owner@example.com", "owner").await;
    let member = fixture_session(&pool, first, "member@example.com", "member").await;
    let foreign = fixture_session(&pool, second, "foreign@example.com", "owner").await;
    let config = WebApiConfig::new(vec!["https://ui.example.com".into()]).unwrap();
    let routes = server::navigation::router(pool.clone()).merge(server::provisioning::router(
        pool,
        None,
        server::transactional_mail::MailConfig::default(),
    ));
    let app = server::web_api::router(routes, &config);

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{first}/projects"))
                .header(header::COOKIE, format!("okoscope_session={owner}"))
                .header(header::ORIGIN, "https://ui.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "00000000-0000-4000-8000-000000000001")
                .body(Body::from(r#"{"slug":"owned","name":"Owned"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let created_status = created.status();
    let created_body = json(created).await;
    assert_eq!(created_status, StatusCode::CREATED, "{created_body}");
    let project_id = created_body["id"].as_str().unwrap().to_owned();

    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/organizations/{first}/projects"))
                .header(header::COOKIE, format!("okoscope_session={member}"))
                .header(header::ORIGIN, "https://ui.example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "00000000-0000-4000-8000-000000000002")
                .body(Body::from(r#"{"slug":"denied","name":"Denied"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let hidden = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/projects/{project_id}"))
                .header(header::COOKIE, format!("okoscope_session={foreign}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}
