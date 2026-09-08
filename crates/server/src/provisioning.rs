use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    admin_auth::AdminAuthenticator,
    application_credentials::{
        ApplicationCredentialSummary, issue, list as list_credentials, revoke,
    },
    auth::{UserPrincipal, UserSessionAuthenticator, session_token},
    transactional_mail::{Locale, MailConfig, MailError, TemplateData, enqueue},
    web_api::RequestId,
};

#[derive(Clone, Debug)]
struct ProvisioningState {
    pool: PgPool,
    admin: Option<AdminAuthenticator>,
    tenant: UserSessionAuthenticator,
    mail: MailConfig,
}

pub fn router(pool: PgPool, admin: Option<AdminAuthenticator>, mail: MailConfig) -> Router {
    Router::new()
        .route("/api/v1/organizations", post(create_organization))
        .route("/api/v1/admin/organizations", get(list_organizations))
        .route(
            "/api/v1/admin/organizations/{organization_id}/projects",
            get(list_projects),
        )
        .route(
            "/api/v1/admin/projects/{project_id}/applications",
            get(list_applications),
        )
        .route(
            "/api/v1/admin/projects/{project_id}/applications/{application_id}",
            get(get_application),
        )
        .route(
            "/api/v1/organizations/{organization_id}/projects",
            post(create_project),
        )
        .route(
            "/api/v1/projects/{project_id}/applications",
            post(create_application),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
            axum::routing::get(list_application_credentials).post(issue_application_credential),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
            axum::routing::delete(revoke_application_credential),
        )
        .with_state(ProvisioningState {
            tenant: UserSessionAuthenticator::new(pool.clone()),
            pool,
            admin,
            mail,
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProvisioningPrincipal {
    SystemAdmin,
    Tenant(UserPrincipal),
}

#[derive(Debug)]
struct ProvisioningError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: RequestId,
    fields: Option<std::collections::BTreeMap<&'static str, String>>,
}

impl ProvisioningError {
    fn unauthorized(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_admin_credential",
            message: "invalid or missing admin bearer credential".into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    fn invalid_credential(request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_credential",
            message: "invalid or missing bearer credential".into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    fn invalid(field: &'static str, detail: impl Into<String>, request_id: &RequestId) -> Self {
        let detail = detail.into();
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "validation_failed",
            message: "the request contains invalid fields".into(),
            request_id: request_id.clone(),
            fields: Some(std::collections::BTreeMap::from([(field, detail)])),
        }
    }

    fn not_found(code: &'static str, request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message: "resource not found".into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    fn conflict(code: &'static str, request_id: &RequestId) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: "resource already exists".into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    fn database(error: &sqlx::Error, conflict_code: &'static str, request_id: &RequestId) -> Self {
        if error
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            return Self::conflict(conflict_code, request_id);
        }
        tracing::error!(error=%error, request_id=%request_id.0, "provisioning database error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "internal server error".into(),
            request_id: request_id.clone(),
            fields: None,
        }
    }

    fn completed(request_id: &RequestId) -> Self {
        Self::conflict("operation_already_completed", request_id)
    }

    fn idempotency_reused(request_id: &RequestId) -> Self {
        Self::conflict("idempotency_key_reused", request_id)
    }
}

impl IntoResponse for ProvisioningError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: &'static str,
            message: String,
            request_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            fields: Option<std::collections::BTreeMap<&'static str, String>>,
        }
        (
            self.status,
            Json(Body {
                error: self.code,
                message: self.message,
                request_id: self.request_id.0,
                fields: self.fields,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateNamedResource {
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCredentialRequest {
    name: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct OrganizationResponse {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct ProjectResponse {
    id: Uuid,
    organization_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct ApplicationResponse {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct IssuedCredentialResponse {
    id: Uuid,
    name: String,
    token: String,
    token_hint: String,
    created_at: DateTime<Utc>,
    shown_once: bool,
}

#[derive(Debug, Serialize)]
struct CreatedApplicationResponse {
    application: ApplicationResponse,
    credential: IssuedCredentialResponse,
}

#[derive(Debug, Serialize)]
struct CredentialPage {
    items: Vec<ApplicationCredentialSummary>,
}

#[derive(Debug, Serialize)]
struct OrganizationPage {
    items: Vec<OrganizationResponse>,
}

#[derive(Debug, Serialize)]
struct ProjectPage {
    items: Vec<ProjectResponse>,
}

#[derive(Debug, Serialize)]
struct ApplicationPage {
    items: Vec<ApplicationResponse>,
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn authorize_system_admin(
    state: &ProvisioningState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<(), ProvisioningError> {
    let presented = bearer(headers);
    if state
        .admin
        .as_ref()
        .zip(presented)
        .is_some_and(|(admin, credential)| admin.authenticate(credential))
    {
        Ok(())
    } else {
        Err(ProvisioningError::unauthorized(request_id))
    }
}

async fn resolve_principal(
    state: &ProvisioningState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<ProvisioningPrincipal, ProvisioningError> {
    if let Some(presented) = bearer(headers)
        && state
            .admin
            .as_ref()
            .is_some_and(|admin| admin.authenticate(presented))
    {
        return Ok(ProvisioningPrincipal::SystemAdmin);
    }
    let presented =
        session_token(headers).ok_or_else(|| ProvisioningError::invalid_credential(request_id))?;
    state
        .tenant
        .authenticate(presented)
        .await
        .map_err(|error| ProvisioningError::database(&error, "credential_conflict", request_id))?
        .map(ProvisioningPrincipal::Tenant)
        .ok_or_else(|| ProvisioningError::invalid_credential(request_id))
}

fn authorize_organization(
    principal: ProvisioningPrincipal,
    organization_id: Uuid,
    not_found_code: &'static str,
    request_id: &RequestId,
) -> Result<(), ProvisioningError> {
    match principal {
        ProvisioningPrincipal::SystemAdmin => Ok(()),
        ProvisioningPrincipal::Tenant(tenant)
            if tenant.organization_id == organization_id && tenant.role.is_owner() =>
        {
            Ok(())
        }
        ProvisioningPrincipal::Tenant(tenant) if tenant.organization_id == organization_id => {
            Err(ProvisioningError {
                status: StatusCode::FORBIDDEN,
                code: "forbidden",
                message: "owner role is required".into(),
                request_id: request_id.clone(),
                fields: None,
            })
        }
        ProvisioningPrincipal::Tenant(_) => {
            Err(ProvisioningError::not_found(not_found_code, request_id))
        }
    }
}

fn validate_slug(value: &str, request_id: &RequestId) -> Result<(), ProvisioningError> {
    let valid = (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--");
    if valid {
        Ok(())
    } else {
        Err(ProvisioningError::invalid(
            "slug",
            "slug must contain 1-63 lowercase letters, digits, or single hyphens",
            request_id,
        ))
    }
}

fn validate_name(value: &str, request_id: &RequestId) -> Result<(), ProvisioningError> {
    if value.trim() == value && (1..=120).contains(&value.chars().count()) {
        Ok(())
    } else {
        Err(ProvisioningError::invalid(
            "name",
            "name must contain 1-120 characters without surrounding whitespace",
            request_id,
        ))
    }
}

fn validate_credential_name(value: &str, request_id: &RequestId) -> Result<(), ProvisioningError> {
    let valid = (1..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(ProvisioningError::invalid(
            "name",
            "credential name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
            request_id,
        ))
    }
}

enum Idempotency {
    Disabled,
    Fresh(Uuid),
    Replay(Uuid),
}

async fn reserve_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    operation: &'static str,
    fingerprint_parts: &[&str],
    request_id: &RequestId,
) -> Result<Idempotency, ProvisioningError> {
    let Some(raw_key) = headers.get("idempotency-key") else {
        return Ok(Idempotency::Disabled);
    };
    let key = raw_key.to_str().ok().and_then(|value| {
        Uuid::parse_str(value)
            .ok()
            .filter(|parsed| parsed.to_string() == value)
    });
    let Some(key) = key else {
        return Err(ProvisioningError::invalid(
            "idempotency_key",
            "Idempotency-Key must be a canonical UUID",
            request_id,
        ));
    };
    let key_hash = Sha256::digest(format!("okoscope.provisioning.v1\0{key}").as_bytes());
    let mut fingerprint = Sha256::new();
    fingerprint.update(operation.as_bytes());
    for part in fingerprint_parts {
        fingerprint.update([0]);
        fingerprint.update(part.as_bytes());
    }
    let fingerprint = fingerprint.finalize();
    let reservation_id = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO provisioning_idempotency_keys(id,operation,key_hash,request_fingerprint) VALUES($1,$2,$3,$4) ON CONFLICT(operation,key_hash) DO NOTHING RETURNING id",
    )
    .bind(reservation_id)
    .bind(operation)
    .bind(key_hash.as_slice())
    .bind(fingerprint.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| ProvisioningError::database(&error, "idempotency_key_reused", request_id))?;
    if inserted.is_some() {
        return Ok(Idempotency::Fresh(reservation_id));
    }
    let existing: (Vec<u8>, Option<Uuid>) = sqlx::query_as(
        "SELECT request_fingerprint,resource_id FROM provisioning_idempotency_keys WHERE operation=$1 AND key_hash=$2",
    )
    .bind(operation)
    .bind(key_hash.as_slice())
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| ProvisioningError::database(&error, "idempotency_key_reused", request_id))?;
    if existing.0.as_slice() != fingerprint.as_slice() {
        return Err(ProvisioningError::idempotency_reused(request_id));
    }
    existing
        .1
        .map(Idempotency::Replay)
        .ok_or_else(|| ProvisioningError::idempotency_reused(request_id))
}

async fn complete_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    state: &Idempotency,
    resource_id: Uuid,
    request_id: &RequestId,
) -> Result<(), ProvisioningError> {
    if let Idempotency::Fresh(reservation_id) = state {
        sqlx::query("UPDATE provisioning_idempotency_keys SET resource_id=$1 WHERE id=$2")
            .bind(resource_id)
            .bind(reservation_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| {
                ProvisioningError::database(&error, "idempotency_key_reused", request_id)
            })?;
    }
    Ok(())
}

async fn list_organizations(
    State(state): State<ProvisioningState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<OrganizationPage>, ProvisioningError> {
    authorize_system_admin(&state, &headers, &request_id)?;
    let items = sqlx::query_as(
        "SELECT id,slug,name,created_at FROM organizations ORDER BY created_at,id LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        ProvisioningError::database(&error, "organization_slug_conflict", &request_id)
    })?;
    Ok(Json(OrganizationPage { items }))
}

async fn list_projects(
    State(state): State<ProvisioningState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ProjectPage>, ProvisioningError> {
    authorize_system_admin(&state, &headers, &request_id)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)")
        .bind(organization_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| {
            ProvisioningError::database(&error, "project_slug_conflict", &request_id)
        })?;
    if !exists {
        return Err(ProvisioningError::not_found(
            "organization_not_found",
            &request_id,
        ));
    }
    let items = sqlx::query_as(
        "SELECT id,organization_id,slug,name,created_at FROM projects WHERE organization_id=$1 ORDER BY created_at,id LIMIT 200",
    )
    .bind(organization_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| ProvisioningError::database(&error, "project_slug_conflict", &request_id))?;
    Ok(Json(ProjectPage { items }))
}

async fn list_applications(
    State(state): State<ProvisioningState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ApplicationPage>, ProvisioningError> {
    authorize_system_admin(&state, &headers, &request_id)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1)")
        .bind(project_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| {
            ProvisioningError::database(&error, "application_slug_conflict", &request_id)
        })?;
    if !exists {
        return Err(ProvisioningError::not_found(
            "project_not_found",
            &request_id,
        ));
    }
    let items = sqlx::query_as(
        "SELECT id,organization_id,project_id,slug,name,created_at FROM applications WHERE project_id=$1 ORDER BY created_at,id LIMIT 200",
    )
    .bind(project_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        ProvisioningError::database(&error, "application_slug_conflict", &request_id)
    })?;
    Ok(Json(ApplicationPage { items }))
}

async fn get_application(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<ApplicationResponse>, ProvisioningError> {
    authorize_system_admin(&state, &headers, &request_id)?;
    let application = sqlx::query_as(
        "SELECT id,organization_id,project_id,slug,name,created_at FROM applications WHERE project_id=$1 AND id=$2",
    )
    .bind(project_id)
    .bind(application_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| {
        ProvisioningError::database(&error, "application_slug_conflict", &request_id)
    })?
    .ok_or_else(|| ProvisioningError::not_found("application_not_found", &request_id))?;
    Ok(Json(application))
}

async fn create_organization(
    State(state): State<ProvisioningState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<OrganizationResponse>), ProvisioningError> {
    authorize_system_admin(&state, &headers, &request_id)?;
    validate_slug(&input.slug, &request_id)?;
    validate_name(&input.name, &request_id)?;
    let mut tx = state.pool.begin().await.map_err(|error| {
        ProvisioningError::database(&error, "organization_slug_conflict", &request_id)
    })?;
    let idempotency = reserve_idempotency(
        &mut tx,
        &headers,
        "create_organization",
        &[&input.slug, &input.name],
        &request_id,
    )
    .await?;
    if let Idempotency::Replay(resource_id) = idempotency {
        let organization =
            sqlx::query_as("SELECT id,slug,name,created_at FROM organizations WHERE id=$1")
                .bind(resource_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| {
                    ProvisioningError::database(&error, "organization_slug_conflict", &request_id)
                })?;
        return Ok((StatusCode::OK, Json(organization)));
    }
    let organization: OrganizationResponse = sqlx::query_as(
        "INSERT INTO organizations(id,slug,name) VALUES($1,$2,$3) RETURNING id,slug,name,created_at",
    )
    .bind(Uuid::new_v4())
    .bind(input.slug)
    .bind(input.name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| ProvisioningError::database(&error, "organization_slug_conflict", &request_id))?;
    complete_idempotency(&mut tx, &idempotency, organization.id, &request_id).await?;
    tx.commit().await.map_err(|error| {
        ProvisioningError::database(&error, "organization_slug_conflict", &request_id)
    })?;
    Ok((StatusCode::CREATED, Json(organization)))
}

async fn create_project(
    State(state): State<ProvisioningState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<ProjectResponse>), ProvisioningError> {
    let principal = resolve_principal(&state, &headers, &request_id).await?;
    authorize_organization(
        principal,
        organization_id,
        "organization_not_found",
        &request_id,
    )?;
    validate_slug(&input.slug, &request_id)?;
    validate_name(&input.name, &request_id)?;
    let mut tx = state.pool.begin().await.map_err(|error| {
        ProvisioningError::database(&error, "project_slug_conflict", &request_id)
    })?;
    let organization_id_text = organization_id.to_string();
    let idempotency = reserve_idempotency(
        &mut tx,
        &headers,
        "create_project",
        &[&organization_id_text, &input.slug, &input.name],
        &request_id,
    )
    .await?;
    if let Idempotency::Replay(resource_id) = idempotency {
        let project = sqlx::query_as(
            "SELECT id,organization_id,slug,name,created_at FROM projects WHERE id=$1 AND organization_id=$2",
        )
        .bind(resource_id)
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| ProvisioningError::database(&error, "project_slug_conflict", &request_id))?;
        return Ok((StatusCode::OK, Json(project)));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)")
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| {
            ProvisioningError::database(&error, "project_slug_conflict", &request_id)
        })?;
    if !exists {
        return Err(ProvisioningError::not_found(
            "organization_not_found",
            &request_id,
        ));
    }
    let project: ProjectResponse = sqlx::query_as("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,$4) RETURNING id,organization_id,slug,name,created_at")
        .bind(Uuid::new_v4()).bind(organization_id).bind(input.slug).bind(input.name)
        .fetch_one(&mut *tx).await.map_err(|error| ProvisioningError::database(&error,"project_slug_conflict",&request_id))?;
    complete_idempotency(&mut tx, &idempotency, project.id, &request_id).await?;
    tx.commit().await.map_err(|error| {
        ProvisioningError::database(&error, "project_slug_conflict", &request_id)
    })?;
    Ok((StatusCode::CREATED, Json(project)))
}

async fn create_application(
    State(state): State<ProvisioningState>,
    Path(project_id): Path<Uuid>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<CreateNamedResource>,
) -> Result<(StatusCode, Json<CreatedApplicationResponse>), ProvisioningError> {
    let principal = resolve_principal(&state, &headers, &request_id).await?;
    validate_slug(&input.slug, &request_id)?;
    validate_name(&input.name, &request_id)?;
    let mut tx = state.pool.begin().await.map_err(|error| {
        ProvisioningError::database(&error, "application_slug_conflict", &request_id)
    })?;
    let (organization_id, project_name): (Uuid, String) =
        sqlx::query_as("SELECT organization_id,name FROM projects WHERE id=$1")
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| {
                ProvisioningError::database(&error, "application_slug_conflict", &request_id)
            })?
            .ok_or_else(|| ProvisioningError::not_found("project_not_found", &request_id))?;
    authorize_organization(principal, organization_id, "project_not_found", &request_id)?;
    let project_id_text = project_id.to_string();
    let idempotency = reserve_idempotency(
        &mut tx,
        &headers,
        "create_application",
        &[&project_id_text, &input.slug, &input.name],
        &request_id,
    )
    .await?;
    if matches!(idempotency, Idempotency::Replay(_)) {
        return Err(ProvisioningError::completed(&request_id));
    }
    let application: ApplicationResponse = sqlx::query_as("INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,$4,$5) RETURNING id,organization_id,project_id,slug,name,created_at")
        .bind(Uuid::new_v4()).bind(organization_id).bind(project_id).bind(input.slug).bind(input.name)
        .fetch_one(&mut *tx).await.map_err(|error| ProvisioningError::database(&error,"application_slug_conflict",&request_id))?;
    let credential = issue(
        &mut tx,
        organization_id,
        project_id,
        application.id,
        "default",
    )
    .await
    .map_err(|error| {
        ProvisioningError::database(&error, "credential_name_conflict", &request_id)
    })?;
    let response = CreatedApplicationResponse {
        application,
        credential: issued_response(&credential),
    };
    enqueue_application_mail(
        &mut tx,
        &state.mail,
        organization_id,
        &project_name,
        &response.application,
        &request_id,
    )
    .await?;
    complete_idempotency(&mut tx, &idempotency, response.application.id, &request_id).await?;
    tx.commit().await.map_err(|error| {
        ProvisioningError::database(&error, "application_slug_conflict", &request_id)
    })?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn enqueue_application_mail(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    organization_id: Uuid,
    project_name: &str,
    application: &ApplicationResponse,
    request_id: &RequestId,
) -> Result<(), ProvisioningError> {
    if !mail.enabled {
        return Ok(());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT u.email,u.preferred_locale FROM organization_memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='owner' AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL ORDER BY u.email LIMIT 101",
    )
    .bind(organization_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| ProvisioningError::database(&error, "application_slug_conflict", request_id))?;
    if rows.len() > crate::transactional_mail::MAX_RECIPIENTS {
        return Err(ProvisioningError::invalid(
            "owners",
            "verified owner recipient limit exceeded",
            request_id,
        ));
    }
    let recipients = rows
        .into_iter()
        .map(|(email, locale)| (email, locale.parse().unwrap_or(Locale::En)))
        .collect::<Vec<_>>();
    let payload = TemplateData::ApplicationCreated {
        application_name: application.name.clone(),
        project_name: project_name.to_owned(),
    };
    enqueue(
        tx,
        mail,
        &format!("application-created:{}", application.id),
        &recipients,
        &payload,
        None,
        None,
    )
    .await
    .map_err(|error| mail_error(error, request_id))
}

fn mail_error(error: MailError, request_id: &RequestId) -> ProvisioningError {
    match error {
        MailError::TooManyRecipients => ProvisioningError::invalid(
            "owners",
            "verified owner recipient limit exceeded",
            request_id,
        ),
        MailError::Database(error) => {
            ProvisioningError::database(&error, "application_slug_conflict", request_id)
        }
        MailError::InvalidPayload => {
            tracing::error!(request_id=%request_id.0, "application mail payload rejected");
            ProvisioningError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: "internal server error".into(),
                request_id: request_id.clone(),
                fields: None,
            }
        }
    }
}

async fn owned_application(
    state: &ProvisioningState,
    project_id: Uuid,
    application_id: Uuid,
    request_id: &RequestId,
) -> Result<Uuid, ProvisioningError> {
    sqlx::query_scalar("SELECT organization_id FROM applications WHERE project_id=$1 AND id=$2")
        .bind(project_id)
        .bind(application_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| {
            ProvisioningError::database(&error, "application_slug_conflict", request_id)
        })?
        .ok_or_else(|| ProvisioningError::not_found("application_not_found", request_id))
}

async fn list_application_credentials(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<CredentialPage>, ProvisioningError> {
    let principal = resolve_principal(&state, &headers, &request_id).await?;
    let organization_id =
        owned_application(&state, project_id, application_id, &request_id).await?;
    authorize_organization(
        principal,
        organization_id,
        "application_not_found",
        &request_id,
    )?;
    let items = list_credentials(&state.pool, organization_id, project_id, application_id)
        .await
        .map_err(|error| {
            ProvisioningError::database(&error, "credential_name_conflict", &request_id)
        })?;
    Ok(Json(CredentialPage { items }))
}

async fn issue_application_credential(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<IssueCredentialRequest>,
) -> Result<(StatusCode, Json<IssuedCredentialResponse>), ProvisioningError> {
    let principal = resolve_principal(&state, &headers, &request_id).await?;
    validate_credential_name(&input.name, &request_id)?;
    let organization_id =
        owned_application(&state, project_id, application_id, &request_id).await?;
    authorize_organization(
        principal,
        organization_id,
        "application_not_found",
        &request_id,
    )?;
    let mut tx = state.pool.begin().await.map_err(|error| {
        ProvisioningError::database(&error, "credential_name_conflict", &request_id)
    })?;
    let project_id_text = project_id.to_string();
    let application_id_text = application_id.to_string();
    let idempotency = reserve_idempotency(
        &mut tx,
        &headers,
        "issue_application_credential",
        &[&project_id_text, &application_id_text, &input.name],
        &request_id,
    )
    .await?;
    if matches!(idempotency, Idempotency::Replay(_)) {
        return Err(ProvisioningError::completed(&request_id));
    }
    let credential = issue(
        &mut tx,
        organization_id,
        project_id,
        application_id,
        &input.name,
    )
    .await
    .map_err(|error| {
        ProvisioningError::database(&error, "credential_name_conflict", &request_id)
    })?;
    let response = issued_response(&credential);
    complete_idempotency(&mut tx, &idempotency, response.id, &request_id).await?;
    tx.commit().await.map_err(|error| {
        ProvisioningError::database(&error, "credential_name_conflict", &request_id)
    })?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn revoke_application_credential(
    State(state): State<ProvisioningState>,
    Path((project_id, application_id, credential_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, ProvisioningError> {
    let principal = resolve_principal(&state, &headers, &request_id).await?;
    let organization_id =
        owned_application(&state, project_id, application_id, &request_id).await?;
    authorize_organization(
        principal,
        organization_id,
        "application_not_found",
        &request_id,
    )?;
    revoke(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        credential_id,
    )
    .await
    .map_err(|error| ProvisioningError::database(&error, "credential_name_conflict", &request_id))?
    .ok_or_else(|| ProvisioningError::not_found("credential_not_found", &request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

fn issued_response(
    credential: &crate::application_credentials::IssuedApplicationCredential,
) -> IssuedCredentialResponse {
    IssuedCredentialResponse {
        id: credential.summary.id,
        name: credential.summary.name.clone(),
        token: credential.token().to_owned(),
        token_hint: credential.summary.token_hint.clone(),
        created_at: credential.summary.created_at,
        shown_once: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id() -> RequestId {
        RequestId("provisioning-unit-test".into())
    }

    #[test]
    fn validation_codes_and_fields_are_stable() {
        let slug = validate_slug("Invalid--slug", &request_id()).unwrap_err();
        assert_eq!(slug.code, "validation_failed");
        assert!(slug.fields.unwrap().contains_key("slug"));

        let credential = validate_credential_name("rotation 1", &request_id()).unwrap_err();
        assert_eq!(credential.code, "validation_failed");
        assert!(credential.fields.unwrap().contains_key("name"));
    }

    #[test]
    fn credential_names_use_a_bounded_ascii_operator_safe_format() {
        for valid in ["default", "rotation-2026-08", "blue_green.v2"] {
            validate_credential_name(valid, &request_id()).unwrap();
        }
        for invalid in ["", " leading", "two words", "юникод", "_leading"] {
            assert!(validate_credential_name(invalid, &request_id()).is_err());
        }
    }
}
