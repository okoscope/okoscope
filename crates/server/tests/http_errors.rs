//! How every route outside policies and notifications (which have their own
//! tests) answers each kind of caller, through the production router.
//!
//! Each case is sent five times, as: no session, an owner of another
//! organization, a member of the organization without a project role, the
//! organization's owner, and a privileged super administrator. Each caller
//! gets a fresh session per case, because some routes replace or end the
//! session they are called with. An error must match status, `error` code and
//! `message`, and carry the response's `x-request-id` as its `request_id`; a
//! success must match its status.
//!
//! Cases run in order against one database, so a success early in the table
//! (a created project, a release) is what a later conflict refers to.

use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use server::{
    auth::{SESSION_COOKIE, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    health,
    web_api::{REQUEST_ID_HEADER, WebApiConfig},
};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum Expect {
    Ok(u16),
    Error(u16, &'static str, &'static str),
}

use Expect::{Error, Ok};

struct Case {
    method: &'static str,
    uri: &'static str,
    body: Option<&'static str>,
    /// No session, foreign owner, plain member, owner, super administrator.
    expect: [Expect; 5],
}

const CALLERS: [&str; 5] = [
    "no session",
    "foreign owner",
    "member",
    "owner",
    "super admin",
];

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
        application_name: "Application".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: String::new(),
    }
}

async fn user(pool: &sqlx::PgPool) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash,email_verified_at,display_name) VALUES($1,$2,$3,now(),$2)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind("x".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    user_id
}

async fn member_session(pool: &sqlx::PgPool, ids: &BootstrapIds, role: &str) -> String {
    let user_id = user(pool).await;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(ids.organization_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user_id).bind(ids.organization_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    token.expose().to_owned()
}

async fn super_admin_session(pool: &sqlx::PgPool, user_id: Uuid) -> String {
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,token_hash,expires_at,privileged_until) VALUES($1,$2,$3,now()+interval '1 hour',now()+interval '15 minutes')")
        .bind(Uuid::new_v4()).bind(user_id).bind(token.digest().to_vec())
        .execute(pool).await.unwrap();
    token.expose().to_owned()
}

/// Fills the organization, project and application of the tested tenant in;
/// any other path parameter is an id nothing has.
fn fill(template: &str, ids: &BootstrapIds) -> String {
    let named = template
        .replace("{organization_id}", &ids.organization_id.to_string())
        .replace("{project_id}", &ids.project_id.to_string())
        .replace("{application_id}", &ids.application_id.to_string())
        .replace("{facet}", "executable")
        .replace("{group_token}", "token");
    named
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                Uuid::new_v4().to_string()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn every_route_answers_each_caller_with_its_error_envelope(pool: sqlx::PgPool) {
    run(pool, ROUTES).await;
}

/// Page limits, request fields and conflicts, per route. Every list refuses an
/// out-of-range limit with `400 invalid_request`.
#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn invalid_requests_name_what_is_wrong(pool: sqlx::PgPool) {
    run(pool, INVALID).await;
}

/// Sends every case as each caller, in order, and checks the answers.
async fn run(pool: sqlx::PgPool, cases: &[Case]) {
    let tenant = bootstrap(&pool, &config("envelope-tenant")).await.unwrap();
    let foreign = bootstrap(&pool, &config("envelope-foreign")).await.unwrap();
    let administrator = user(&pool).await;
    sqlx::query("INSERT INTO platform_role_assignments(user_id,role) VALUES($1,'super_admin')")
        .bind(administrator)
        .execute(&pool)
        .await
        .unwrap();
    let app = health::router(pool.clone(), true, None, &WebApiConfig::default());
    for case in cases {
        let uri = fill(case.uri, &tenant);
        let body = case.body.map(|body| {
            body.replace("{organization_id}", &tenant.organization_id.to_string())
                .replace("{uuid}", &Uuid::new_v4().to_string())
        });
        let sessions = [
            None,
            Some(member_session(&pool, &foreign, "owner").await),
            Some(member_session(&pool, &tenant, "member").await),
            Some(member_session(&pool, &tenant, "owner").await),
            Some(super_admin_session(&pool, administrator).await),
        ];
        for ((caller, session), expect) in CALLERS.iter().zip(sessions).zip(case.expect) {
            let route = format!("{} {} as {caller}", case.method, case.uri);
            let mut request = Request::builder()
                .method(case.method)
                .uri(&uri)
                .header(header::HOST, "ui.test")
                .header(header::ORIGIN, "https://ui.test")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(session) = session {
                request = request.header(header::COOKIE, format!("{SESSION_COOKIE}={session}"));
            }
            let response = app
                .clone()
                .oneshot(
                    request
                        .body(body.clone().map_or_else(Body::empty, Body::from))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status().as_u16();
            let request_id = response.headers()[REQUEST_ID_HEADER]
                .to_str()
                .unwrap()
                .to_owned();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
            let json: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            match expect {
                Ok(expected) => assert_eq!(status, expected, "{route}: {json}"),
                Error(expected, code, message) => {
                    assert_eq!(status, expected, "{route}: {json}");
                    assert_eq!(json["error"], code, "{route}");
                    assert_eq!(json["message"], message, "{route}");
                    assert_eq!(json["request_id"], request_id, "{route}");
                }
            }
        }
    }
}

#[rustfmt::skip]
const ROUTES: &[Case] = &[
    // access_api.rs
    Case {
        method: "POST",
        uri: "/api/v1/auth/organization-selections",
        body: Some(r#"{"organization_id":"{organization_id}"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Ok(200), Ok(200), Error(404, "organization_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/auth/policy",
        body: None,
        expect: [Ok(200), Ok(200), Ok(200), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/privilege-confirmations",
        body: Some(r#"{"current_password":"wrong-password-123"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "current_password_invalid", "current password is incorrect")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/users",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations",
        body: Some(r#"{"slug":"new-org","name":"New","ownership":{"kind":"self_owner"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(409, "organization_limit_reached", "access mutation conflicts with current authority")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/organizations/{organization_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(409, "organization_not_deletable", "access mutation conflicts with current authority")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/projects",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations/{organization_id}/projects",
        body: Some(r#"{"slug":"new-project","name":"New"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(201)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/applications",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/applications",
        body: Some(r#"{"slug":"new-app","name":"New"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(201)],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/platform/users/{user_id}/status",
        body: Some(r#"{"status":"disabled"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/platform/users/{user_id}/roles/super-admin",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(409, "user_not_eligible", "user is not eligible")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/users/{user_id}/roles/super-admin",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/audit",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/organizations/{organization_id}/members/{user_id}",
        body: Some(r#"{"role":"admin"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/organizations/{organization_id}/members/{user_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/platform/organizations/{organization_id}/members/{user_id}",
        body: Some(r#"{"role":"admin"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/organizations/{organization_id}/members/{user_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/audit",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/members",
        body: Some(r#"{"user_id":"{uuid}","role":"member"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/projects/{project_id}/members/{user_id}",
        body: Some(r#"{"role":"admin"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/members/{user_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/eligible-organization-members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/members",
        body: Some(r#"{"user_id":"{uuid}","role":"member"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/eligible-organization-members",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/platform/projects/{project_id}/members/{user_id}",
        body: Some(r#"{"role":"admin"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/projects/{project_id}/members/{user_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "user_not_found", "resource not found"), Error(404, "user_not_found", "resource not found")],
    },
    // agent_health.rs
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/agent-health",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    // api.rs
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups?project_id={project_id}&application_id={application_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups/{group_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups/{group_id}/snapshots",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups/{group_id}/occurrences",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/runtime-groups/{group_id}/acknowledge",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/runtime-groups/{group_id}/resolve",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/runtime-groups/{group_id}/reopen",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found")],
    },
    // attention.rs
    Case {
        method: "GET",
        uri: "/api/v1/attention-summary",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Ok(200), Ok(200), Ok(200), Error(404, "not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/attention-summary",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Ok(200)],
    },
    // dns_group_api.rs
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/distribution",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/{group_token}/variants",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Error(400, "invalid_request", "token is invalid"), Error(400, "invalid_request", "token is invalid")],
    },
    // inventory_api.rs
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/summary",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution?kind=process",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/facets/{facet}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "unsupported inventory facet"), Error(400, "invalid_request", "unsupported inventory facet")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/user-label",
        body: Some(r#"{"display_name":"Label"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/user-label",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/releases",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/sightings",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/groups",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/occurrences",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found")],
    },
    // invitation_api.rs
    Case {
        method: "GET",
        uri: "/api/v1/platform/invitations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations",
        body: Some(r#"{"email":"invitee@example.test","role":"member","locale":"en"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations/{invitation_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(404, "invitation_not_found", "resource not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations/{invitation_id}/resend",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/invitations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/invitations",
        body: Some(r#"{"email":"invitee@example.test","role":"member","locale":"en"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/projects/{project_id}/invitations/{invitation_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(404, "invitation_not_found", "resource not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/invitations/{invitation_id}/resend",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/invitations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "insufficient permission"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/organizations/{organization_id}/invitations",
        body: Some(r#"{"email":"invitee@example.test","role":"member","locale":"en"}"#),
        expect: [Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "insufficient permission"), Error(404, "invitation_not_found", "resource not found"), Error(404, "invitation_not_found", "resource not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/organizations/{organization_id}/invitations/{invitation_id}/resend",
        body: None,
        expect: [Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/invitations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/invitations",
        body: Some(r#"{"email":"invitee@example.test","role":"member","locale":"en"}"#),
        expect: [Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/invitations/{invitation_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(404, "invitation_not_found", "resource not found"), Error(404, "invitation_not_found", "resource not found")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/invitations/{invitation_id}/resend",
        body: None,
        expect: [Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable"), Error(503, "mail_unavailable", "invitation mail is unavailable")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/invitations/inspections",
        body: Some(r#"{"token":"unknown-token"}"#),
        expect: [Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/invitations/acceptances/new-user",
        body: Some(r#"{"token":"unknown-token","password":"correct horse battery staple","display_name":"New","locale":"en"}"#),
        expect: [Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/invitations/acceptances/existing-user",
        body: Some(r#"{"token":"unknown-token"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable"), Error(410, "invitation_unusable", "invitation is unavailable")],
    },
    // navigation.rs
    Case {
        method: "GET",
        uri: "/api/v1/organization",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Ok(200), Ok(200), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Ok(200), Ok(200), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/workers",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    // notification/retention_api.rs
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/notification-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/organizations/{organization_id}/notification-retention",
        body: Some(r#"{"enabled":true,"history_days":30}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(403, "forbidden", "owner role is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/notification-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/notification-retention",
        body: Some(r#"{"enabled":true,"history_days":30}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/notification-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    // onboarding.rs
    Case {
        method: "GET",
        uri: "/api/v1/setup/status",
        body: None,
        expect: [Ok(200), Ok(200), Ok(200), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/setup/complete",
        body: Some(r#"{"setup_token":"unknown","email":"setup@example.test","password":"correct horse battery staple","display_name":"Setup","locale":"en"}"#),
        expect: [Error(401, "invalid_setup_token", "setup authorization is invalid"), Error(401, "invalid_setup_token", "setup authorization is invalid"), Error(401, "invalid_setup_token", "setup authorization is invalid"), Error(401, "invalid_setup_token", "setup authorization is invalid"), Error(401, "invalid_setup_token", "setup authorization is invalid")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/agent-installation-metadata",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(503, "installation_metadata_unavailable", "agent installation metadata is unavailable"), Error(503, "installation_metadata_unavailable", "agent installation metadata is unavailable"), Error(503, "installation_metadata_unavailable", "agent installation metadata is unavailable"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        body: Some(r#"{"cluster_name":"cluster","workload":{"namespace":"production","kind":"Deployment","name":"app"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(503, "installation_metadata_unavailable", "agent installation metadata is unavailable"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}",
        body: Some(r#"{"cluster_name":"cluster","workload":{"namespace":"production","kind":"Deployment","name":"app"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}/replace-credential",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/connection-readiness",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Ok(200), Error(401, "unauthorized", "authentication required")],
    },
    // provisioning.rs
    Case {
        method: "POST",
        uri: "/api/v1/organizations",
        body: Some(r#"{"slug":"created-org","name":"Created"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(201)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/admin/organizations",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/admin/organizations/{organization_id}/projects",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/admin/projects/{project_id}/applications",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/admin/projects/{project_id}/applications/{application_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/organizations/{organization_id}/projects",
        body: Some(r#"{"slug":"created-project","name":"Created"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Ok(201), Error(409, "project_slug_conflict", "resource already exists")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications",
        body: Some(r#"{"slug":"created-app","name":"Created"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "project_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Ok(201), Error(409, "application_slug_conflict", "resource already exists")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
        body: Some(r#"{"name":"ci"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Ok(201), Error(409, "credential_name_conflict", "resource already exists")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Error(404, "credential_not_found", "resource not found"), Error(404, "credential_not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/applications/{application_id}/credentials",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/applications/{application_id}/credentials",
        body: Some(r#"{"name":"ci"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Error(409, "credential_name_conflict", "resource already exists"), Error(409, "credential_name_conflict", "resource already exists")],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/platform/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "application_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Error(404, "credential_not_found", "resource not found"), Error(404, "credential_not_found", "resource not found")],
    },
    // releases.rs
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        body: Some(r#"{"version":"v9","deployed_at":"2026-09-01T00:00:00Z"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Ok(201), Error(409, "release_exists", "release version already exists")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}/episodes",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found")],
    },
    // resources.rs
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/resources?metric=cpu&from=2026-09-01T00:00:00Z&to=2026-09-02T00:00:00Z&step=1h&mode=release",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "application or release not found"), Error(404, "not_found", "application or release not found"), Error(400, "invalid_request", "unsupported resource metric"), Error(400, "invalid_request", "unsupported resource metric")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/resource-comparison",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "application or release not found"), Error(404, "not_found", "application or release not found"), Error(404, "not_found", "application or release not found"), Error(404, "not_found", "application or release not found")],
    },
    // runtime_retention/api.rs
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/runtime-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/organizations/{organization_id}/runtime-retention",
        body: Some(r#"{"enabled":true,"raw_days":30,"history_days":365}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(403, "forbidden", "owner role is required"), Ok(200), Ok(200)],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/runtime-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/runtime-retention",
        body: Some(r#"{"enabled":true,"raw_days":30,"history_days":365}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    Case {
        method: "DELETE",
        uri: "/api/v1/projects/{project_id}/runtime-retention",
        body: None,
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Ok(200), Ok(200)],
    },
    // user_auth.rs
    Case {
        method: "POST",
        uri: "/api/v1/auth/register",
        body: Some(r#"{"email":"reg@example.test","password":"correct horse battery staple","display_name":"Reg","organization_slug":"reg-org","organization_name":"Reg","locale":"en"}"#),
        expect: [Error(404, "registration_disabled", "registration is disabled"), Error(404, "registration_disabled", "registration is disabled"), Error(404, "registration_disabled", "registration is disabled"), Error(404, "registration_disabled", "registration is disabled"), Error(404, "registration_disabled", "registration is disabled")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/login",
        body: Some(r#"{"email":"nobody@example.test","password":"wrong-password-123"}"#),
        expect: [Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/auth/me",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Ok(200), Ok(200), Ok(200), Ok(200)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/logout",
        body: None,
        expect: [Ok(204), Ok(204), Ok(204), Ok(204), Ok(204)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/email-verification-requests",
        body: Some(r#"{"email":"nobody@example.test"}"#),
        expect: [Ok(202), Ok(202), Ok(202), Ok(202), Ok(202)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/email-verifications",
        body: Some(r#"{"token":"unknown-token"}"#),
        expect: [Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/password-reset-requests",
        body: Some(r#"{"email":"nobody@example.test"}"#),
        expect: [Ok(202), Ok(202), Ok(202), Ok(202), Ok(202)],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/password-resets",
        body: Some(r#"{"token":"unknown-token","new_password":"correct horse battery staple"}"#),
        expect: [Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired"), Error(400, "action_token_invalid", "action token is invalid or expired")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/auth/password",
        body: Some(r#"{"current_password":"wrong-password-123","new_password":"correct horse battery staple"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(400, "current_password_invalid", "current password is incorrect"), Error(400, "current_password_invalid", "current password is incorrect"), Error(400, "current_password_invalid", "current password is incorrect"), Error(400, "current_password_invalid", "current password is incorrect")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/auth/preferences",
        body: Some(r#"{"locale":"ru"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Ok(200), Ok(200), Ok(200), Ok(200)],
    },
];

#[rustfmt::skip]
const INVALID: &[Case] = &[
    Case {
        method: "GET",
        uri: "/api/v1/platform/users?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/users?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/projects?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/projects?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/applications?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/applications?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/audit?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/audit?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/audit?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/audit?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "Organization administration is required"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/eligible-organization-members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/eligible-organization-members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/eligible-organization-members?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/eligible-organization-members?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/agent-health?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 20"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/agent-health?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 20"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups?project_id={project_id}&application_id={application_id}&limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups?project_id={project_id}&application_id={application_id}&limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/attention-summary?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(404, "not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/attention-summary?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(404, "not_found", "resource not found")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/attention-summary?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/attention-summary?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 50"), Error(400, "invalid_request", "limit must be between 1 and 50")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/distribution?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/distribution?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "logical DNS group not found"), Error(404, "not_found", "logical DNS group not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution?kind=process&limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution?kind=process&limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/invitations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/invitations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/organizations/{organization_id}/invitations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/invitations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/platform/projects/{project_id}/invitations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/invitations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "insufficient permission"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/organizations/{organization_id}/invitations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "insufficient permission"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/invitations?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/invitations?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "project_not_found", "resource not found"), Error(404, "project_not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 100"), Error(400, "invalid_request", "limit must be between 1 and 100")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/workers?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/workers?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(401, "unauthorized", "invalid or missing bearer credential")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary?limit=1000",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 10"), Error(400, "invalid_request", "limit must be between 1 and 10")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations",
        body: Some(r#"{"slug":"Bad Slug","name":"New","ownership":{"kind":"self_owner"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "validation_failed", "organization is invalid")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations/{organization_id}/projects",
        body: Some(r#"{"slug":"Bad Slug","name":"New"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "validation_failed", "resource is invalid")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/organizations/{organization_id}/projects",
        body: Some(r#"{"slug":"fine-slug","name":""}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "validation_failed", "resource is invalid")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/platform/projects/{project_id}/applications",
        body: Some(r#"{"slug":"Bad Slug","name":"New"}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "validation_failed", "resource is invalid")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/organizations/{organization_id}/projects",
        body: Some(r#"{"slug":"Bad Slug","name":"New"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "organization_not_found", "resource not found"), Error(403, "forbidden", "owner role is required"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications",
        body: Some(r#"{"slug":"Bad Slug","name":"New"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/organizations",
        body: Some(r#"{"slug":"Bad Slug","name":"New"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(403, "forbidden", "super administrator role is required"), Error(400, "validation_failed", "the request contains invalid fields")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
        body: Some(r#"{"name":""}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields"), Error(400, "validation_failed", "the request contains invalid fields")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/organizations/{organization_id}/notification-retention",
        body: Some(r#"{"enabled":true,"history_days":0}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(403, "forbidden", "owner role is required"), Error(400, "invalid_request", "history_days must be between 1 and 3650"), Error(400, "invalid_request", "history_days must be between 1 and 3650")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/notification-retention",
        body: Some(r#"{"enabled":true,"history_days":4000}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Error(400, "invalid_request", "history_days must be between 1 and 3650"), Error(400, "invalid_request", "history_days must be between 1 and 3650")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/organizations/{organization_id}/runtime-retention",
        body: Some(r#"{"enabled":true,"raw_days":0,"history_days":null}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(403, "forbidden", "owner role is required"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/runtime-retention",
        body: Some(r#"{"enabled":true,"raw_days":30,"history_days":10}"#),
        expect: [Error(401, "unauthorized", "user session required"), Error(404, "not_found", "retention settings not found"), Error(404, "not_found", "retention settings not found"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/projects/{project_id}/runtime-retention",
        body: Some(r#"{"enabled":true}"#),
        expect: [Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650"), Error(400, "invalid_request", "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        body: Some(r#"{"version":"","deployed_at":"2026-09-01T00:00:00Z"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "version must contain 1..=200 bytes after trimming"), Error(400, "invalid_request", "version must contain 1..=200 bytes after trimming")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        body: Some(r#"{"version":"v1","deployed_at":"2026-09-01T00:00:00Z"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Ok(201), Error(409, "release_exists", "release version already exists")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        body: Some(r#"{"version":"v1","deployed_at":"2026-09-01T00:00:00Z"}"#),
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(409, "release_exists", "release version already exists"), Error(409, "release_exists", "release version already exists")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        body: Some(r#"{"cluster_name":"","workload":{"namespace":"production","kind":"Deployment","name":"app"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "validation_failed", "cluster or workload identity is invalid"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        body: Some(r#"{"cluster_name":"cluster","workload":{"namespace":"production","kind":"CronJob","name":"app"}}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(404, "not_found", "resource not found"), Error(404, "not_found", "resource not found"), Error(400, "validation_failed", "cluster or workload identity is invalid"), Error(401, "unauthorized", "authentication required")],
    },
    Case {
        method: "PATCH",
        uri: "/api/v1/organizations/{organization_id}/members/{user_id}",
        body: Some(r#"{"role":"emperor"}"#),
        expect: [Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/projects/{project_id}/members",
        body: Some(r#"{"user_id":"{uuid}","role":"emperor"}"#),
        expect: [Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/auth/preferences",
        body: Some(r#"{"locale":"de"}"#),
        expect: [Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity"), Error(422, "unprocessable_entity", "Unprocessable Entity")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/auth/preferences",
        body: Some(r#"{"locale":"en","display_name":""}"#),
        expect: [Error(401, "unauthorized", "authentication required"), Error(400, "validation_failed", "display name must contain 1-120 characters"), Error(400, "validation_failed", "display name must contain 1-120 characters"), Error(400, "validation_failed", "display name must contain 1-120 characters"), Error(400, "validation_failed", "display name must contain 1-120 characters")],
    },
    Case {
        method: "PUT",
        uri: "/api/v1/auth/password",
        body: Some(r#"{"current_password":"x","new_password":"short"}"#),
        expect: [Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/login",
        body: Some(r#"{"email":"not-an-email","password":"x"}"#),
        expect: [Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password"), Error(401, "invalid_credentials", "invalid email or password")],
    },
    Case {
        method: "POST",
        uri: "/api/v1/auth/password-resets",
        body: Some(r#"{"token":"unknown","new_password":"short"}"#),
        expect: [Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters"), Error(400, "validation_failed", "password must contain between 12 and 256 characters")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution?kind=unknown",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle"), Error(400, "invalid_request", "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory?kind=unknown",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime inventory resource not found"), Error(404, "not_found", "runtime inventory resource not found"), Error(400, "invalid_request", "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle"), Error(400, "invalid_request", "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory?cursor=not-a-uuid",
        body: None,
        expect: [Error(400, "bad_request", "Bad Request"), Error(400, "bad_request", "Bad Request"), Error(400, "bad_request", "Bad Request"), Error(400, "bad_request", "Bad Request"), Error(400, "bad_request", "Bad Request")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/runtime-groups?project_id={project_id}&application_id={application_id}&status=unknown",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "runtime group not found"), Error(404, "not_found", "runtime group not found"), Error(400, "invalid_request", "unsupported status"), Error(400, "invalid_request", "unsupported status")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/resources?metric=cpu_usage&from=2026-09-02T00:00:00Z&to=2026-09-01T00:00:00Z&step=1h&mode=release",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "application or release not found"), Error(404, "not_found", "application or release not found"), Error(400, "invalid_request", "unsupported resource metric"), Error(400, "invalid_request", "unsupported resource metric")],
    },
    Case {
        method: "GET",
        uri: "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff?limit=0",
        body: None,
        expect: [Error(401, "unauthorized", "invalid or missing bearer credential"), Error(404, "not_found", "release or application not found"), Error(404, "not_found", "release or application not found"), Error(400, "invalid_request", "limit must be between 1 and 200"), Error(400, "invalid_request", "limit must be between 1 and 200")],
    },
];
