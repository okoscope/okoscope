use crate::error_code::ErrorCode;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, UserSessionAuthenticator};
use crate::runtime_retention::settings::{ProjectRetention, RetentionPolicy};
use crate::service::runtime_retention::{RetentionServiceError, RuntimeRetentionService};

#[derive(Clone, Debug)]
struct ApiState {
    auth: UserSessionAuthenticator,
    service: RuntimeRetentionService,
}

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
                ErrorCode::UNAUTHORIZED,
                "user session required",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorCode::FORBIDDEN,
                "owner role is required",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "retention settings not found",
            ),
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                ErrorCode::INVALID_REQUEST,
                "raw_days must be between 1 and 3650; history_days must be null or between raw_days and 3650",
            ),
            Self::Database(error) => {
                tracing::error!(%error, "retention settings database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error",
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, code, message)
    }
}

impl From<RetentionServiceError> for ApiError {
    fn from(error: RetentionServiceError) -> Self {
        match error {
            RetentionServiceError::Forbidden => Self::Forbidden,
            RetentionServiceError::NotFound => Self::NotFound,
            RetentionServiceError::Invalid => Self::Invalid,
            RetentionServiceError::Database(error) => Self::Database(error),
        }
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
        .with_state(ApiState {
            auth: UserSessionAuthenticator::new(pool.clone()),
            service: RuntimeRetentionService::new(pool),
        })
}

async fn principal(state: &ApiState, headers: &HeaderMap) -> Result<IdentityPrincipal, ApiError> {
    state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ApiError::Unauthorized)
}

async fn get_organization(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.organization(user, id).await?))
}

async fn put_organization(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<RetentionPolicy>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RetentionPolicy>, ApiError> {
    let user = principal(&state, &headers).await?;
    // A body that is not a policy is refused after the authority checks.
    let policy = payload.ok().map(|Json(policy)| policy);
    Ok(Json(
        state.service.set_organization(user, id, policy).await?,
    ))
}

async fn get_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.project(user, id).await?))
}

async fn put_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<RetentionPolicy>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ProjectRetention>, ApiError> {
    let Json(policy) = payload.map_err(|_| ApiError::Invalid)?;
    let user = principal(&state, &headers).await?;
    Ok(Json(
        state.service.change_project(user, id, Some(policy)).await?,
    ))
}

async fn delete_project(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ProjectRetention>, ApiError> {
    let user = principal(&state, &headers).await?;
    Ok(Json(state.service.change_project(user, id, None).await?))
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

    /// Creates a user with the given organization role and returns both the
    /// user id and an active session token. The id is needed to grant project
    /// membership, which an organization role below admin does not confer.
    async fn session_for(pool: &PgPool, org: Uuid, role: &str) -> (Uuid, String) {
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
        (user, token.expose().to_owned())
    }

    async fn session(pool: &PgPool, org: Uuid, role: &str) -> String {
        session_for(pool, org, role).await.1
    }

    /// Grants the user a role on the project. An organization `member` does not
    /// inherit project access, so a test acting as one needs this row.
    async fn project_membership(pool: &PgPool, org: Uuid, project: Uuid, user: Uuid, role: &str) {
        sqlx::query(
            "INSERT INTO project_memberships(organization_id,project_id,user_id,role) VALUES($1,$2,$3,$4)",
        )
        .bind(org)
        .bind(project)
        .bind(user)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
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
                assert_eq!(response.1["error"], ErrorCode::INVALID_REQUEST.as_str());
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
        let (member_id, member) = session_for(&pool, org, "member").await;
        project_membership(&pool, org, project, member_id, "member").await;
        let app = app(pool);
        let finite = r#"{"enabled":true,"raw_days":7,"history_days":60}"#;
        let org_path = format!("/api/v1/organizations/{org}/runtime-retention");
        let path = format!("/api/v1/projects/{project}/runtime-retention");
        for target in [&path, &org_path] {
            assert_eq!(
                call(&app, "", "GET", target, "").await.0,
                StatusCode::UNAUTHORIZED
            );
        }

        // A project member reads its project's retention but cannot change it.
        assert_eq!(
            call(&app, &member, "GET", &path, "").await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, &member, "PUT", &path, finite).await.0,
            StatusCode::FORBIDDEN
        );

        // Organization retention is owner and admin territory. A member is not
        // told it exists, so the read is a 404 rather than a 403.
        assert_eq!(
            call(&app, &member, "GET", &org_path, "").await.0,
            StatusCode::NOT_FOUND
        );
        // The write path answers 403 where the read answers 404: put_organization
        // checks the active organization before the owner role, so it confirms
        // the resource exists to a member who may not read it.
        assert_eq!(
            call(&app, &member, "PUT", &org_path, finite).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, &owner, "GET", &org_path, "").await.0,
            StatusCode::OK
        );
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
