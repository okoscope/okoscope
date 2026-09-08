use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    application_credentials,
    auth::{
        OrganizationRole, UserPrincipal, UserSessionAuthenticator, hash_password, normalize_email,
        validate_password,
    },
    user_auth::{insert_session, session_cookie, valid_name, valid_slug},
    web_api::{RequestId, WebApiConfig},
};

const STATUS_FRESH_SECONDS: i64 = 300;

#[derive(Clone, Debug, Serialize)]
pub struct AgentInstallationMetadata {
    pub chart_reference: String,
    pub chart_version: String,
    pub recommended_agent_version: String,
    pub minimum_agent_version: String,
    pub configuration_schema_version: i32,
    pub grpc_endpoint: String,
    pub tls_mode: String,
    pub ca_secret_name: Option<String>,
    pub ca_secret_key: Option<String>,
    pub namespace: String,
    pub credential_secret_name: String,
    pub credential_secret_key: String,
    pub supported_workload_kinds: Vec<String>,
}

impl AgentInstallationMetadata {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chart_reference.starts_with("oci://")
            && !self.chart_version.is_empty()
            && !self.grpc_endpoint.is_empty()
            && self.valid_tls_metadata()
            && self.configuration_schema_version > 0
            && self.supported_workload_kinds == ["Deployment"]
        {
            Ok(())
        } else {
            Err("agent installation metadata is incomplete")
        }
    }

    fn valid_tls_metadata(&self) -> bool {
        match self.tls_mode.as_str() {
            "system" => self.ca_secret_name.is_none() && self.ca_secret_key.is_none(),
            "custom_ca" => {
                self.ca_secret_name
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    && self
                        .ca_secret_key
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
struct OnboardingState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
    registration_enabled: bool,
    setup_digest: Option<[u8; 32]>,
    setup_expires_at: Option<DateTime<Utc>>,
    secure_cookie: bool,
    session_lifetime: Duration,
    metadata: Option<AgentInstallationMetadata>,
    setup_attempts: Arc<Semaphore>,
    recent_setup_attempts: Arc<tokio::sync::Mutex<VecDeque<Instant>>>,
}

pub fn router(pool: PgPool, config: &WebApiConfig) -> Router {
    let state = OnboardingState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        pool,
        registration_enabled: config.registration_enabled,
        setup_digest: config.setup_token_digest,
        setup_expires_at: config.setup_token_expires_at,
        secure_cookie: config.secure_session_cookie,
        session_lifetime: config.session_lifetime,
        metadata: config.agent_installation.clone(),
        setup_attempts: Arc::new(Semaphore::new(4)),
        recent_setup_attempts: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
    };
    Router::new()
        .route("/api/v1/setup/status", get(setup_status))
        .route("/api/v1/setup/complete", post(complete_setup))
        .route("/api/v1/agent-installation-metadata", get(installation_metadata))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations", get(list_installations).post(create_installation))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}", get(get_installation).patch(update_installation))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}/replace-credential", post(replace_credential))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/connection-readiness", get(connection_readiness))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct SetupStatus {
    state: &'static str,
}

async fn owner_exists(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE role='owner')")
        .fetch_one(pool)
        .await
}

async fn setup_status(State(state): State<OnboardingState>) -> Result<Json<SetupStatus>, ApiError> {
    let exists = owner_exists(&state.pool)
        .await
        .map_err(ApiError::database)?;
    let expired = state
        .setup_expires_at
        .is_some_and(|value| value <= Utc::now());
    Ok(Json(SetupStatus {
        state: if exists || state.registration_enabled {
            "ready"
        } else if expired {
            "setup_unavailable"
        } else {
            "owner_required"
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    setup_token: String,
    email: String,
    password: String,
    organization_slug: String,
    organization_name: String,
    project_slug: String,
    project_name: String,
}

#[derive(Serialize)]
struct SetupResponse {
    user_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    role: OrganizationRole,
}

fn validate_setup(
    input: &SetupRequest,
    expected: Option<[u8; 32]>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<String, ApiError> {
    let email = normalize_email(&input.email).map_err(ApiError::validation)?;
    validate_password(&input.password).map_err(ApiError::validation)?;
    if !valid_slug(&input.organization_slug)
        || !valid_name(&input.organization_name)
        || !valid_slug(&input.project_slug)
        || !valid_name(&input.project_name)
    {
        return Err(ApiError::validation(
            "organization or Project name is invalid",
        ));
    }
    let candidate: [u8; 32] = Sha256::digest(input.setup_token.as_bytes()).into();
    if expires_at.is_some_and(|value| value <= Utc::now())
        || input.setup_token.len() < 32
        || !expected.is_some_and(|digest| bool::from(digest.ct_eq(&candidate)))
    {
        return Err(ApiError::unauthorized(
            "invalid_setup_token",
            "setup authorization is invalid",
        ));
    }
    Ok(email)
}

async fn complete_setup(
    State(state): State<OnboardingState>,
    Extension(request_id): Extension<RequestId>,
    Json(input): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    enforce_setup_rate(&state).await?;
    let _permit = state
        .setup_attempts
        .try_acquire()
        .map_err(|_| ApiError::unavailable("setup_rate_limited", "too many setup attempts"))?;
    let email = validate_setup(&input, state.setup_digest, state.setup_expires_at)?;
    let password_hash = hash_password(&input.password).map_err(|_| ApiError::internal())?;
    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    sqlx::query("SELECT pg_advisory_xact_lock(1869373291)")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    let has_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE role='owner')",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::database)?;
    if has_owner {
        return Err(ApiError::conflict(
            "setup_already_completed",
            "setup is already complete",
        ));
    }
    let user_id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    insert_setup_rows(
        &mut tx,
        &input,
        &email,
        &password_hash,
        user_id,
        organization_id,
        project_id,
    )
    .await?;
    let (_, token) = insert_session(&mut tx, user_id, organization_id, state.session_lifetime)
        .await
        .map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;
    tracing::info!(request_id=%request_id.0, "first-owner setup completed");
    let mut response = (
        StatusCode::CREATED,
        Json(SetupResponse {
            user_id,
            organization_id,
            project_id,
            role: OrganizationRole::Owner,
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(token.expose(), state.secure_cookie, state.session_lifetime),
    );
    Ok(response)
}

async fn enforce_setup_rate(state: &OnboardingState) -> Result<(), ApiError> {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_ATTEMPTS: usize = 10;
    let now = Instant::now();
    let mut attempts = state.recent_setup_attempts.lock().await;
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= WINDOW)
    {
        attempts.pop_front();
    }
    if attempts.len() >= MAX_ATTEMPTS {
        return Err(ApiError::unavailable(
            "setup_rate_limited",
            "too many setup attempts",
        ));
    }
    attempts.push_back(now);
    Ok(())
}

async fn insert_setup_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &SetupRequest,
    email: &str,
    password_hash: &str,
    user_id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
    )
    .bind(user_id)
    .bind(email)
    .bind(password_hash)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::database)?;
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,$3)")
        .bind(organization_id)
        .bind(&input.organization_slug)
        .bind(&input.organization_name)
        .execute(&mut **tx)
        .await
        .map_err(ApiError::database)?;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::database)?;
    sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,$4)")
        .bind(project_id)
        .bind(organization_id)
        .bind(&input.project_slug)
        .bind(&input.project_name)
        .execute(&mut **tx)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

async fn principal(
    headers: &HeaderMap,
    state: &OnboardingState,
) -> Result<UserPrincipal, ApiError> {
    state
        .auth
        .authenticate_headers(headers)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::unauthorized("invalid_credential", "authentication required"))
}

async fn installation_metadata(
    State(state): State<OnboardingState>,
    headers: HeaderMap,
) -> Result<Json<AgentInstallationMetadata>, ApiError> {
    principal(&headers, &state).await?;
    let metadata = state.metadata.ok_or_else(|| {
        ApiError::unavailable(
            "installation_metadata_unavailable",
            "agent installation metadata is unavailable",
        )
    })?;
    metadata
        .validate()
        .map_err(|message| ApiError::unavailable("installation_metadata_unavailable", message))?;
    Ok(Json(metadata))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkloadIntent {
    namespace: String,
    kind: String,
    name: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateInstallation {
    cluster_name: String,
    workload: WorkloadIntent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateInstallation {
    cluster_name: String,
    workload: WorkloadIntent,
}

fn validate_installation(input: &CreateInstallation) -> Result<(), ApiError> {
    let dns = |value: &str, max| {
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
    };
    if !valid_name(&input.cluster_name)
        || !dns(&input.workload.namespace, 63)
        || input.workload.kind != "Deployment"
    {
        return Err(ApiError::validation(
            "cluster or workload identity is invalid",
        ));
    }
    match (&input.workload.name, &input.workload.labels) {
        (Some(name), None) if dns(name, 253) => Ok(()),
        (None, Some(labels))
            if !labels.is_empty()
                && labels.len() <= 16
                && labels
                    .iter()
                    .all(|(k, v)| dns(k, 63) && !v.is_empty() && v.len() <= 63) =>
        {
            Ok(())
        }
        _ => Err(ApiError::validation(
            "provide exactly one valid Deployment name or label map",
        )),
    }
}

#[derive(Debug, FromRow, Serialize)]
struct Installation {
    id: Uuid,
    application_id: Uuid,
    credential_id: Uuid,
    cluster_name: String,
    workload_namespace: String,
    workload_kind: String,
    workload_name: Option<String>,
    workload_labels: Option<serde_json::Value>,
    chart_version: String,
    configuration_schema_version: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct InstallationPage {
    items: Vec<Installation>,
}

#[derive(Serialize)]
struct IssuedInstallation {
    installation: Installation,
    credential: IssuedCredential,
    command: CommandModel,
}

#[derive(Serialize)]
struct IssuedCredential {
    id: Uuid,
    token: String,
    token_hint: String,
    shown_once: bool,
}

#[derive(Serialize)]
struct CommandModel {
    chart_reference: String,
    chart_version: String,
    namespace: String,
    secret_name: String,
    secret_key: String,
    grpc_endpoint: String,
    tls_mode: String,
    ca_secret_name: Option<String>,
    ca_secret_key: Option<String>,
}

async fn owned_application(
    state: &OnboardingState,
    principal: UserPrincipal,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApiError> {
    let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)").bind(principal.organization_id).bind(project_id).bind(application_id).fetch_one(&state.pool).await.map_err(ApiError::database)?;
    if found {
        Ok(())
    } else {
        Err(ApiError::not_found())
    }
}

async fn create_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<CreateInstallation>,
) -> Result<Response, ApiError> {
    let user = principal(&headers, &state).await?;
    if !user.role.is_owner() {
        return Err(ApiError::not_found());
    }
    owned_application(&state, user, project_id, application_id).await?;
    validate_installation(&input)?;
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .ok_or_else(|| ApiError::validation("a bounded Idempotency-Key header is required"))?;
    let metadata = state.metadata.clone().ok_or_else(|| {
        ApiError::unavailable(
            "installation_metadata_unavailable",
            "agent installation metadata is unavailable",
        )
    })?;
    metadata
        .validate()
        .map_err(|m| ApiError::unavailable("installation_metadata_unavailable", m))?;
    let hash: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&input).map_err(|_| ApiError::internal())?).into();
    if let Some(existing) = find_idempotent(&state.pool, user.organization_id, key).await? {
        if existing.1.as_slice() == hash {
            return Ok((StatusCode::OK, Json(existing_response(&existing.0))).into_response());
        }
        return Err(ApiError::conflict(
            "idempotency_key_reused",
            "idempotency key was used for another request",
        ));
    }
    issue_installation(
        &state,
        InstallationIssue {
            organization_id: user.organization_id,
            project_id,
            application_id,
            key,
            hash,
            input,
            metadata,
        },
    )
    .await
}

async fn find_idempotent(
    pool: &PgPool,
    organization_id: Uuid,
    key: &str,
) -> Result<Option<(Installation, Vec<u8>)>, ApiError> {
    sqlx::query_as::<_, InstallationWithHash>("SELECT id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at,request_hash FROM application_installations WHERE organization_id=$1 AND idempotency_key=$2").bind(organization_id).bind(key).fetch_optional(pool).await.map_err(ApiError::database).map(|v| v.map(|r| { let hash=r.request_hash.clone(); (r.installation(),hash) }))
}

#[derive(FromRow)]
struct InstallationWithHash {
    id: Uuid,
    application_id: Uuid,
    credential_id: Uuid,
    cluster_name: String,
    workload_namespace: String,
    workload_kind: String,
    workload_name: Option<String>,
    workload_labels: Option<serde_json::Value>,
    chart_version: String,
    configuration_schema_version: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    request_hash: Vec<u8>,
}
impl InstallationWithHash {
    fn installation(self) -> Installation {
        Installation {
            id: self.id,
            application_id: self.application_id,
            credential_id: self.credential_id,
            cluster_name: self.cluster_name,
            workload_namespace: self.workload_namespace,
            workload_kind: self.workload_kind,
            workload_name: self.workload_name,
            workload_labels: self.workload_labels,
            chart_version: self.chart_version,
            configuration_schema_version: self.configuration_schema_version,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

fn existing_response(installation: &Installation) -> serde_json::Value {
    serde_json::json!({"installation": installation, "credential": null, "command": null})
}

struct InstallationIssue<'a> {
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    key: &'a str,
    hash: [u8; 32],
    input: CreateInstallation,
    metadata: AgentInstallationMetadata,
}

async fn issue_installation(
    state: &OnboardingState,
    issue: InstallationIssue<'_>,
) -> Result<Response, ApiError> {
    let InstallationIssue {
        organization_id,
        project_id,
        application_id,
        key,
        hash,
        input,
        metadata,
    } = issue;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    let issued = application_credentials::issue(
        &mut tx,
        organization_id,
        project_id,
        application_id,
        &format!("installation-{}", &id.to_string()[..8]),
    )
    .await
    .map_err(ApiError::database)?;
    let installation = sqlx::query_as::<_, Installation>("INSERT INTO application_installations(id,organization_id,project_id,application_id,credential_id,idempotency_key,request_hash,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at")
        .bind(id).bind(organization_id).bind(project_id).bind(application_id).bind(issued.summary.id).bind(key).bind(hash.as_slice()).bind(&input.cluster_name).bind(&input.workload.namespace).bind(&input.workload.kind).bind(&input.workload.name).bind(input.workload.labels.as_ref().map(|v| serde_json::to_value(v).expect("labels serialize"))).bind(&metadata.chart_version).bind(metadata.configuration_schema_version).fetch_one(&mut *tx).await.map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;
    let body = IssuedInstallation {
        command: command_model(&metadata),
        credential: IssuedCredential {
            id: issued.summary.id,
            token: issued.token().to_owned(),
            token_hint: issued.summary.token_hint,
            shown_once: true,
        },
        installation,
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

fn command_model(metadata: &AgentInstallationMetadata) -> CommandModel {
    CommandModel {
        chart_reference: metadata.chart_reference.clone(),
        chart_version: metadata.chart_version.clone(),
        namespace: metadata.namespace.clone(),
        secret_name: metadata.credential_secret_name.clone(),
        secret_key: metadata.credential_secret_key.clone(),
        grpc_endpoint: metadata.grpc_endpoint.clone(),
        tls_mode: metadata.tls_mode.clone(),
        ca_secret_name: metadata.ca_secret_name.clone(),
        ca_secret_key: metadata.ca_secret_key.clone(),
    }
}

const INSTALL_SELECT: &str = "SELECT id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at FROM application_installations";

async fn list_installations(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<InstallationPage>, ApiError> {
    let user = principal(&headers, &state).await?;
    owned_application(&state, user, project_id, application_id).await?;
    let query = format!(
        "{INSTALL_SELECT} WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 ORDER BY created_at,id"
    );
    let items = sqlx::query_as(&query)
        .bind(user.organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(InstallationPage { items }))
}

async fn get_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Installation>, ApiError> {
    let user = principal(&headers, &state).await?;
    let query = format!(
        "{INSTALL_SELECT} WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4"
    );
    sqlx::query_as(&query)
        .bind(user.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(installation_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::database)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn update_installation(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateInstallation>,
) -> Result<Json<Installation>, ApiError> {
    let user = principal(&headers, &state).await?;
    if !user.role.is_owner() {
        return Err(ApiError::not_found());
    }
    let validated = CreateInstallation {
        cluster_name: input.cluster_name,
        workload: input.workload,
    };
    validate_installation(&validated)?;
    sqlx::query_as::<_, Installation>("UPDATE application_installations SET cluster_name=$5,workload_namespace=$6,workload_kind=$7,workload_name=$8,workload_labels=$9,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 RETURNING id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at")
        .bind(user.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(installation_id)
        .bind(&validated.cluster_name)
        .bind(&validated.workload.namespace)
        .bind(&validated.workload.kind)
        .bind(&validated.workload.name)
        .bind(
            validated
                .workload
                .labels
                .as_ref()
                .map(|labels| serde_json::to_value(labels).expect("bounded labels serialize")),
        )
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::database)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn replace_credential(
    State(state): State<OnboardingState>,
    Path((project_id, application_id, installation_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<IssuedCredential>, ApiError> {
    let user = principal(&headers, &state).await?;
    if !user.role.is_owner() {
        return Err(ApiError::not_found());
    }
    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    let old: Option<Uuid>=sqlx::query_scalar("SELECT credential_id FROM application_installations WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 FOR UPDATE").bind(user.organization_id).bind(project_id).bind(application_id).bind(installation_id).fetch_optional(&mut *tx).await.map_err(ApiError::database)?;
    let old = old.ok_or_else(ApiError::not_found)?;
    sqlx::query("UPDATE application_ingestion_credentials SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1").bind(old).execute(&mut *tx).await.map_err(ApiError::database)?;
    let issued = application_credentials::issue(
        &mut tx,
        user.organization_id,
        project_id,
        application_id,
        &format!("replacement-{}", &Uuid::new_v4().to_string()[..8]),
    )
    .await
    .map_err(ApiError::database)?;
    sqlx::query(
        "UPDATE application_installations SET credential_id=$1,updated_at=now() WHERE id=$2",
    )
    .bind(issued.summary.id)
    .bind(installation_id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;
    Ok(Json(IssuedCredential {
        id: issued.summary.id,
        token: issued.token().to_owned(),
        token_hint: issued.summary.token_hint,
        shown_once: true,
    }))
}

#[derive(Serialize)]
struct Readiness {
    state: &'static str,
    reason: Option<String>,
    credential_last_used_at: Option<DateTime<Utc>>,
    first_event_at: Option<DateTime<Utc>>,
    last_event_at: Option<DateTime<Utc>>,
    reporting_nodes: i64,
    stale_after_seconds: i64,
}

type CredentialEvidence = Option<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)>;
type StatusEvidence = Option<(String, Option<String>, DateTime<Utc>, i64)>;

async fn connection_readiness(
    State(state): State<OnboardingState>,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Readiness>, ApiError> {
    let user = principal(&headers, &state).await?;
    owned_application(&state, user, project_id, application_id).await?;
    let events:(Option<DateTime<Utc>>,Option<DateTime<Utc>>)=sqlx::query_as("SELECT min(received_at),max(received_at) FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3").bind(user.organization_id).bind(project_id).bind(application_id).fetch_one(&state.pool).await.map_err(ApiError::database)?;
    let cred: CredentialEvidence=sqlx::query_as("SELECT c.last_used_at,c.revoked_at FROM application_installations i JOIN application_ingestion_credentials c ON c.id=i.credential_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 ORDER BY i.created_at DESC LIMIT 1").bind(user.organization_id).bind(project_id).bind(application_id).fetch_optional(&state.pool).await.map_err(ApiError::database)?;
    let status: StatusEvidence=sqlx::query_as("SELECT s.state,s.reason,max(s.observed_at),count(*) FROM application_installation_status s JOIN application_installations i ON i.id=s.installation_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 GROUP BY s.state,s.reason ORDER BY max(s.observed_at) DESC LIMIT 1").bind(user.organization_id).bind(project_id).bind(application_id).fetch_optional(&state.pool).await.map_err(ApiError::database)?;
    Ok(Json(derive_readiness(events, cred, status)))
}

fn derive_readiness(
    events: (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
    cred: CredentialEvidence,
    status: StatusEvidence,
) -> Readiness {
    let now = Utc::now();
    let fresh =
        |at: DateTime<Utc>| now.signed_duration_since(at).num_seconds() <= STATUS_FRESH_SECONDS;
    let credential_last_used_at = cred.and_then(|v| v.0);
    let revoked = cred.is_some_and(|v| v.1.is_some());
    let (state, reason, nodes) = if revoked {
        ("credential_revoked", None, 0)
    } else if events.1.is_some_and(fresh) {
        ("receiving_events", None, 0)
    } else if let Some((s, r, at, n)) = status {
        if fresh(at) {
            (
                match s.as_str() {
                    "workload_not_matched" => "workload_not_matched",
                    "permission_denied" => "permission_denied",
                    "kernel_unsupported" => "kernel_unsupported",
                    "waiting_for_event" => "waiting_for_event",
                    _ => "agent_authenticated",
                },
                r,
                n,
            )
        } else {
            ("stale", None, n)
        }
    } else if credential_last_used_at.is_some_and(fresh) {
        ("agent_authenticated", None, 0)
    } else if credential_last_used_at.is_some() || events.1.is_some() {
        ("stale", None, 0)
    } else {
        ("waiting_for_agent", None, 0)
    };
    Readiness {
        state,
        reason,
        credential_last_used_at,
        first_event_at: events.0,
        last_event_at: events.1,
        reporting_nodes: nodes,
        stale_after_seconds: STATUS_FRESH_SECONDS,
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}
impl ApiError {
    fn unauthorized(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            message,
        }
    }
    fn validation(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "validation_failed",
            message,
        }
    }
    fn conflict(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message,
        }
    }
    fn unavailable(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message,
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "resource not found",
        }
    }
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "internal server error",
        }
    }
    fn database(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error,"onboarding database error");
        Self::internal()
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error":self.code,"message":self.message})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_is_bounded() {
        let mut metadata = AgentInstallationMetadata {
            chart_reference: "oci://registry/chart".into(),
            chart_version: "1.0.0".into(),
            recommended_agent_version: "1.0.0".into(),
            minimum_agent_version: "1.0.0".into(),
            configuration_schema_version: 1,
            grpc_endpoint: "grpc.example:443".into(),
            tls_mode: "system".into(),
            ca_secret_name: None,
            ca_secret_key: None,
            namespace: "okoscope-system".into(),
            credential_secret_name: "okoscope-agent-credentials".into(),
            credential_secret_key: "application-token".into(),
            supported_workload_kinds: vec!["Deployment".into()],
        };
        assert!(metadata.validate().is_ok());
        metadata.tls_mode = "custom_ca".into();
        assert!(metadata.validate().is_err());
        metadata.ca_secret_name = Some("okoscope-ca".into());
        metadata.ca_secret_key = Some("ca.crt".into());
        assert!(metadata.validate().is_ok());
        metadata.grpc_endpoint.clear();
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn custom_ca_is_propagated_to_installation_command() {
        let metadata = AgentInstallationMetadata {
            chart_reference: "oci://registry/chart".into(),
            chart_version: "1.0.0".into(),
            recommended_agent_version: "1.0.0".into(),
            minimum_agent_version: "1.0.0".into(),
            configuration_schema_version: 1,
            grpc_endpoint: "grpc.example:443".into(),
            tls_mode: "custom_ca".into(),
            ca_secret_name: Some("private-ca".into()),
            ca_secret_key: Some("ca.crt".into()),
            namespace: "okoscope-system".into(),
            credential_secret_name: "credentials".into(),
            credential_secret_key: "token".into(),
            supported_workload_kinds: vec!["Deployment".into()],
        };
        let command = serde_json::to_value(command_model(&metadata)).unwrap();
        assert_eq!(command["ca_secret_name"], "private-ca");
        assert_eq!(command["ca_secret_key"], "ca.crt");
    }

    #[test]
    fn readiness_precedence_and_staleness_are_stable() {
        let now = Utc::now();
        let recent = now - chrono::Duration::seconds(10);
        let old = now - chrono::Duration::seconds(STATUS_FRESH_SECONDS + 10);
        let diagnostic = Some((
            "permission_denied".into(),
            Some("kubernetes_watch_forbidden".into()),
            recent,
            2,
        ));
        let receiving = derive_readiness((Some(recent), Some(recent)), None, diagnostic.clone());
        assert_eq!(receiving.state, "receiving_events");
        let revoked = derive_readiness(
            (Some(recent), Some(recent)),
            Some((Some(recent), Some(recent))),
            diagnostic.clone(),
        );
        assert_eq!(revoked.state, "credential_revoked");
        let denied = derive_readiness((None, None), Some((Some(recent), None)), diagnostic);
        assert_eq!(denied.state, "permission_denied");
        assert_eq!(denied.reporting_nodes, 2);
        let stale = derive_readiness((Some(old), Some(old)), Some((Some(old), None)), None);
        assert_eq!(stale.state, "stale");
        let older_agent = derive_readiness((None, None), Some((Some(recent), None)), None);
        assert_eq!(older_agent.state, "agent_authenticated");
    }
}
