use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use super::settings::{self as settings, ProjectRetention, RetentionPolicy};
use crate::auth::{UserPrincipal, UserSessionAuthenticator};

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    Invalid,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "user session required",
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "owner role is required"),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "retention settings not found",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650",
            ),
            Self::Database(error) => {
                tracing::error!(%error, "retention settings database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                )
            }
        };
        (
            status,
            Json(serde_json::json!({"error": code, "message": message})),
        )
            .into_response()
    }
}

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/runtime-retention",
            get(get_organization).put(put_organization),
        )
        .route(
            "/api/v1/projects/{project_id}/runtime-retention",
            get(get_project).put(put_project).delete(delete_project),
        )
        .with_state(pool)
}

async fn principal(pool: &PgPool, headers: &HeaderMap) -> Result<UserPrincipal, ApiError> {
    UserSessionAuthenticator::new(pool.clone())
        .authenticate_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

fn owner(principal: UserPrincipal) -> Result<(), ApiError> {
    if principal.role.is_owner() {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn validate(policy: RetentionPolicy) -> Result<(), ApiError> {
    if policy.valid() {
        Ok(())
    } else {
        Err(ApiError::Invalid)
    }
}

async fn owned_organization(
    pool: &PgPool,
    user: UserPrincipal,
    id: Uuid,
) -> Result<RetentionPolicy, ApiError> {
    if id != user.organization_id {
        return Err(ApiError::NotFound);
    }
    settings::organization(pool, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn owned_project(
    pool: &PgPool,
    user: UserPrincipal,
    id: Uuid,
) -> Result<ProjectRetention, ApiError> {
    settings::project(pool, user.organization_id, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn get_organization(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&pool, &headers).await?;
    Ok(Json(owned_organization(&pool, user, id).await?))
}

async fn put_organization(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<RetentionPolicy>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&pool, &headers).await?;
    owned_organization(&pool, user, id).await?;
    owner(user)?;
    let Json(policy) = payload.map_err(|_| ApiError::Invalid)?;
    validate(policy)?;
    settings::set_organization(&pool, id, user.user_id, policy).await?;
    Ok(Json(policy))
}

async fn get_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&pool, &headers).await?;
    Ok(Json(owned_project(&pool, user, id).await?))
}

async fn change_project(
    pool: &PgPool,
    headers: &HeaderMap,
    id: Uuid,
    policy: Option<RetentionPolicy>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(pool, headers).await?;
    owned_project(pool, user, id).await?;
    owner(user)?;
    if let Some(policy) = policy {
        validate(policy)?;
    }
    settings::set_project(pool, user.organization_id, id, user.user_id, policy).await?;
    Ok(Json(owned_project(pool, user, id).await?))
}

async fn put_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<RetentionPolicy>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let Json(policy) = payload.map_err(|_| ApiError::Invalid)?;
    change_project(&pool, &headers, id, Some(policy)).await
}

async fn delete_project(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    change_project(&pool, &headers, id, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{SessionToken, hash_password};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    async fn tenant(pool: &PgPool) -> (Uuid, Uuid) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Retention')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','Project')",
        )
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
        crate::health::router(
            pool,
            true,
            None,
            &crate::web_api::WebApiConfig::new(vec!["https://ui.example.test".into()]).unwrap(),
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

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn settings_put_requires_trusted_origin_and_allows_preflight(pool: PgPool) {
        let (org, _) = tenant(&pool).await;
        let token = session(&pool, org, "owner").await;
        let app = app(pool);
        let path = format!("/api/v1/organizations/{org}/runtime-retention");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&path)
                    .header("cookie", format!("okoscope_session={token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"enabled":true,"raw_days":1,"history_days":1}"#,
                    ))
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

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn policy_inheritance_and_forever(pool: PgPool) {
        let (org, project) = tenant(&pool).await;
        let owner = session(&pool, org, "owner").await;
        let app = app(pool.clone());
        let org_path = format!("/api/v1/organizations/{org}/runtime-retention");
        let path = format!("/api/v1/projects/{project}/runtime-retention");
        let initial = call(&app, &owner, "GET", &path, "").await;
        assert_eq!(initial.0, StatusCode::OK);
        assert_eq!(
            initial.1["effective"],
            serde_json::json!({"enabled":false,"raw_days":30,"history_days":365})
        );
        assert!(initial.1["override"].is_null());
        let finite = r#"{"enabled":true,"raw_days":7,"history_days":60}"#;
        let forever = r#"{"enabled":false,"raw_days":1,"history_days":null}"#;
        assert_eq!(
            call(&app, &owner, "PUT", &org_path, finite).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, &owner, "GET", &path, "").await.1["effective"]["history_days"],
            60
        );
        let saved = call(&app, &owner, "PUT", &path, forever).await;
        assert_eq!(saved.0, StatusCode::OK);
        assert_eq!(saved.1["source"], "project");
        assert!(saved.1["effective"]["history_days"].is_null());
        assert_eq!(saved.1["effective"]["enabled"], false);
        assert_eq!(saved.1["inherited"]["history_days"], 60);
        for target in [&path, &org_path] {
            for invalid in [
                r#"{"enabled":true,"raw_days":7}"#,
                r#"{"enabled":true,"raw_days":7,"history_days":6}"#,
            ] {
                let response = call(&app, &owner, "PUT", target, invalid).await;
                assert_eq!(response.0, StatusCode::BAD_REQUEST);
                assert_eq!(response.1["error"], "invalid_request");
            }
        }
        assert_eq!(
            call(&app, &owner, "GET", &path, "").await.1["override"],
            saved.1["override"]
        );
        let reset = call(&app, &owner, "DELETE", &path, "").await;
        assert_eq!(reset.0, StatusCode::OK);
        assert!(reset.1["override"].is_null());
        assert_eq!(reset.1["source"], "organization");
        assert_eq!(reset.1["effective"]["history_days"], 60);
        let audited: bool = sqlx::query_scalar(
            "SELECT runtime_retention_updated_by IS NOT NULL FROM projects WHERE id=$1",
        )
        .bind(project)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audited);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn policy_authorization(pool: PgPool) {
        let (org, project) = tenant(&pool).await;
        let (other, other_project) = tenant(&pool).await;
        let owner = session(&pool, org, "owner").await;
        let member = session(&pool, org, "member").await;
        let app = app(pool);
        let finite = r#"{"enabled":true,"raw_days":7,"history_days":60}"#;
        let org_path = format!("/api/v1/organizations/{org}/runtime-retention");
        let path = format!("/api/v1/projects/{project}/runtime-retention");
        for target in [&path, &org_path] {
            assert_eq!(
                call(&app, &member, "GET", target, "").await.0,
                StatusCode::OK
            );
            assert_eq!(
                call(&app, &member, "PUT", target, finite).await.0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                call(&app, "", "GET", target, "").await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            call(&app, &member, "DELETE", &path, "").await.0,
            StatusCode::FORBIDDEN
        );
        for target in [
            format!("/api/v1/organizations/{other}/runtime-retention"),
            format!("/api/v1/projects/{other_project}/runtime-retention"),
        ] {
            for method in ["GET", "PUT"] {
                assert_eq!(
                    call(&app, &owner, method, &target, finite).await.0,
                    StatusCode::NOT_FOUND
                );
            }
        }
    }
}
