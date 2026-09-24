//! Provisioning: organizations, projects and applications created by API, and
//! the credentials of an application. Creations accept an idempotency key.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::application_credentials::{
    ApplicationCredentialSummary, IssuedApplicationCredential, issue, list as list_credentials,
    revoke,
};
use crate::auth::{IdentityPrincipal, UserPrincipal};
use crate::repository::provisioning::ProvisioningKeyRepository;
use crate::repository::{
    ApplicationRepository, OrganizationRepository, OrganizationStatus, ProjectRepository,
    UserRepository,
};
use crate::transactional_mail::{Locale, MailConfig, MailError, TemplateData, enqueue};

/// Why a provisioning use case failed.
#[derive(Debug, Error)]
pub enum ProvisioningServiceError {
    /// The session is not a super administrator's and has no active
    /// organization.
    #[error("invalid or missing bearer credential")]
    InvalidCredential,
    /// A platform use case was called by a tenant.
    #[error("super administrator role is required")]
    SuperAdminRequired,
    /// A member of the organization who is not its owner.
    #[error("owner role is required")]
    OwnerRequired,
    /// One field of the request is invalid.
    #[error("{field}: {detail}")]
    Invalid {
        field: &'static str,
        detail: &'static str,
    },
    /// The resource does not exist, or the principal may not see it.
    #[error("{0:?} not found")]
    NotFound(ProvisioningTarget),
    /// The resource already exists, or the idempotency key was used for
    /// something else.
    #[error("{0:?}")]
    Conflict(ProvisioningConflict),
    /// The application mail could not be built.
    #[error("application mail payload rejected")]
    MailPayloadRejected,
    #[error("database error: {0}")]
    Database(sqlx::Error),
}

/// What a [`ProvisioningServiceError::NotFound`] could not find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningTarget {
    Organization,
    Project,
    Application,
    Credential,
}

/// What a [`ProvisioningServiceError::Conflict`] clashes with. Each store
/// failure that is a unique violation becomes the conflict of the step that
/// hit it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningConflict {
    OrganizationSlug,
    ProjectSlug,
    ApplicationSlug,
    CredentialName,
    /// Reported for a unique violation while authenticating.
    Credential,
    IdempotencyKeyReused,
    /// The idempotency key names a creation that already completed and whose
    /// result cannot be shown again.
    OperationAlreadyCompleted,
}

type Result<T, E = ProvisioningServiceError> = std::result::Result<T, E>;

/// A store failure: a unique violation is the given conflict, anything else a
/// database error.
pub fn store_error(error: sqlx::Error, conflict: ProvisioningConflict) -> ProvisioningServiceError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        ProvisioningServiceError::Conflict(conflict)
    } else {
        ProvisioningServiceError::Database(error)
    }
}

fn stored(conflict: ProvisioningConflict) -> impl Fn(sqlx::Error) -> ProvisioningServiceError {
    move |error| store_error(error, conflict)
}

/// An organization, project or application to create.
#[derive(Clone, Debug)]
pub struct NamedResource {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct OrganizationResponse {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProjectResponse {
    id: Uuid,
    organization_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ApplicationResponse {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct IssuedCredentialResponse {
    id: Uuid,
    name: String,
    token: String,
    token_hint: String,
    created_at: DateTime<Utc>,
    shown_once: bool,
}

#[derive(Debug, Serialize)]
pub struct CreatedApplicationResponse {
    application: ApplicationResponse,
    credential: IssuedCredentialResponse,
}

#[derive(Debug, Serialize)]
pub struct CredentialPage {
    items: Vec<ApplicationCredentialSummary>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationPage {
    items: Vec<OrganizationResponse>,
}

#[derive(Debug, Serialize)]
pub struct ProjectPage {
    items: Vec<ProjectResponse>,
}

#[derive(Debug, Serialize)]
pub struct ApplicationPage {
    items: Vec<ApplicationResponse>,
}

/// A creation's result: new, or the one an earlier request with the same
/// idempotency key created.
#[derive(Debug)]
pub enum Created<T> {
    New(T),
    Replayed(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caller {
    PlatformSuperAdmin,
    Tenant(UserPrincipal),
}

enum Idempotency {
    Disabled,
    Fresh(Uuid),
    Replay(Uuid),
}

#[derive(Clone, Debug)]
pub struct ProvisioningService {
    pool: PgPool,
    mail: MailConfig,
}

impl ProvisioningService {
    pub fn new(pool: PgPool, mail: MailConfig) -> Self {
        Self { pool, mail }
    }

    /// Every organization.
    pub async fn list_organizations(
        &self,
        principal: IdentityPrincipal,
    ) -> Result<OrganizationPage> {
        require_platform_admin(principal)?;
        let items = OrganizationRepository::summaries(&self.pool)
            .await
            .map_err(stored(ProvisioningConflict::OrganizationSlug))?;
        Ok(OrganizationPage { items })
    }

    /// The projects of an organization.
    pub async fn list_projects(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
    ) -> Result<ProjectPage> {
        require_platform_admin(principal)?;
        let exists: bool = OrganizationRepository::exists(&self.pool, organization_id)
            .await
            .map_err(stored(ProvisioningConflict::ProjectSlug))?;
        if !exists {
            return Err(ProvisioningServiceError::NotFound(
                ProvisioningTarget::Organization,
            ));
        }
        let items = ProjectRepository::summaries(&self.pool, organization_id)
            .await
            .map_err(stored(ProvisioningConflict::ProjectSlug))?;
        Ok(ProjectPage { items })
    }

    /// The applications of a project.
    pub async fn list_applications(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ApplicationPage> {
        require_platform_admin(principal)?;
        let exists: bool = ProjectRepository::exists(&self.pool, project_id)
            .await
            .map_err(stored(ProvisioningConflict::ApplicationSlug))?;
        if !exists {
            return Err(ProvisioningServiceError::NotFound(
                ProvisioningTarget::Project,
            ));
        }
        let items = ApplicationRepository::summaries(&self.pool, project_id)
            .await
            .map_err(stored(ProvisioningConflict::ApplicationSlug))?;
        Ok(ApplicationPage { items })
    }

    /// One application.
    pub async fn get_application(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationResponse> {
        require_platform_admin(principal)?;
        ApplicationRepository::summary(&self.pool, project_id, application_id)
            .await
            .map_err(stored(ProvisioningConflict::ApplicationSlug))?
            .ok_or(ProvisioningServiceError::NotFound(
                ProvisioningTarget::Application,
            ))
    }

    /// Creates an organization. A retry under the same idempotency key
    /// returns the organization it created.
    pub async fn create_organization(
        &self,
        principal: IdentityPrincipal,
        input: NamedResource,
        idempotency_key: Option<&[u8]>,
    ) -> Result<Created<OrganizationResponse>> {
        require_platform_admin(principal)?;
        validate_slug(&input.slug)?;
        validate_name(&input.name)?;
        let conflict = ProvisioningConflict::OrganizationSlug;
        let mut tx = self.pool.begin().await.map_err(stored(conflict))?;
        let idempotency = reserve_idempotency(
            &mut tx,
            idempotency_key,
            "create_organization",
            &[&input.slug, &input.name],
        )
        .await?;
        if let Idempotency::Replay(resource_id) = idempotency {
            let organization = OrganizationRepository::summary(&mut *tx, resource_id)
                .await
                .map_err(stored(conflict))?;
            return Ok(Created::Replayed(organization));
        }
        let stored_row = OrganizationRepository::insert(
            &mut *tx,
            Uuid::new_v4(),
            &input.slug,
            &input.name,
            OrganizationStatus::Active,
        )
        .await
        .map_err(stored(conflict))?;
        let organization = OrganizationResponse {
            id: stored_row.id,
            slug: stored_row.slug,
            name: stored_row.name,
            created_at: stored_row.created_at,
        };
        complete_idempotency(&mut tx, &idempotency, organization.id).await?;
        tx.commit().await.map_err(stored(conflict))?;
        Ok(Created::New(organization))
    }

    /// Creates a project in an organization the principal owns. A retry
    /// under the same idempotency key returns the project it created.
    pub async fn create_project(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        input: NamedResource,
        idempotency_key: Option<&[u8]>,
    ) -> Result<Created<ProjectResponse>> {
        let caller = caller(principal)?;
        authorize_organization(caller, organization_id, ProvisioningTarget::Organization)?;
        validate_slug(&input.slug)?;
        validate_name(&input.name)?;
        let conflict = ProvisioningConflict::ProjectSlug;
        let mut tx = self.pool.begin().await.map_err(stored(conflict))?;
        let organization_id_text = organization_id.to_string();
        let idempotency = reserve_idempotency(
            &mut tx,
            idempotency_key,
            "create_project",
            &[&organization_id_text, &input.slug, &input.name],
        )
        .await?;
        if let Idempotency::Replay(resource_id) = idempotency {
            let project = ProjectRepository::summary(&mut *tx, resource_id, organization_id)
                .await
                .map_err(stored(conflict))?;
            return Ok(Created::Replayed(project));
        }
        let exists: bool = OrganizationRepository::exists(&mut *tx, organization_id)
            .await
            .map_err(stored(conflict))?;
        if !exists {
            return Err(ProvisioningServiceError::NotFound(
                ProvisioningTarget::Organization,
            ));
        }
        // The existence check above makes `None` a race with a concurrent
        // deletion, which is reported the same way that check reports it.
        let stored_row = ProjectRepository::insert(
            &mut *tx,
            Uuid::new_v4(),
            organization_id,
            &input.slug,
            &input.name,
        )
        .await
        .map_err(stored(conflict))?
        .ok_or(ProvisioningServiceError::NotFound(
            ProvisioningTarget::Organization,
        ))?;
        let project = ProjectResponse {
            id: stored_row.id,
            organization_id: stored_row.organization_id,
            slug: stored_row.slug,
            name: stored_row.name,
            created_at: stored_row.created_at,
        };
        complete_idempotency(&mut tx, &idempotency, project.id).await?;
        tx.commit().await.map_err(stored(conflict))?;
        Ok(Created::New(project))
    }

    /// Creates an application with its default credential, shown once, and
    /// tells the organization's owners by mail. A retry under the same
    /// idempotency key is refused, because the credential cannot be shown
    /// again.
    pub async fn create_application(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        input: NamedResource,
        idempotency_key: Option<&[u8]>,
    ) -> Result<CreatedApplicationResponse> {
        let caller = caller(principal)?;
        validate_slug(&input.slug)?;
        validate_name(&input.name)?;
        let conflict = ProvisioningConflict::ApplicationSlug;
        let mut tx = self.pool.begin().await.map_err(stored(conflict))?;
        let (organization_id, project_name): (Uuid, String) =
            ProjectRepository::organization_and_name(&mut *tx, project_id)
                .await
                .map_err(stored(conflict))?
                .ok_or(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Project,
                ))?;
        authorize_organization(caller, organization_id, ProvisioningTarget::Project)?;
        let project_id_text = project_id.to_string();
        let idempotency = reserve_idempotency(
            &mut tx,
            idempotency_key,
            "create_application",
            &[&project_id_text, &input.slug, &input.name],
        )
        .await?;
        if matches!(idempotency, Idempotency::Replay(_)) {
            return Err(ProvisioningServiceError::Conflict(
                ProvisioningConflict::OperationAlreadyCompleted,
            ));
        }
        // The project was resolved above; `None` is a race with its deletion and
        // is reported the way that lookup reports a missing project.
        let stored_row = ApplicationRepository::insert(
            &mut *tx,
            Uuid::new_v4(),
            project_id,
            &input.slug,
            &input.name,
        )
        .await
        .map_err(stored(conflict))?
        .ok_or(ProvisioningServiceError::NotFound(
            ProvisioningTarget::Project,
        ))?;
        let application = ApplicationResponse {
            id: stored_row.id,
            organization_id: stored_row.organization_id,
            project_id: stored_row.project_id,
            slug: stored_row.slug,
            name: stored_row.name,
            created_at: stored_row.created_at,
        };
        let credential = issue(
            &mut tx,
            organization_id,
            project_id,
            application.id,
            "default",
        )
        .await
        .map_err(stored(ProvisioningConflict::CredentialName))?;
        let response = CreatedApplicationResponse {
            application,
            credential: issued_response(&credential),
        };
        enqueue_application_mail(
            &mut tx,
            &self.mail,
            organization_id,
            &project_name,
            &response.application,
        )
        .await?;
        complete_idempotency(&mut tx, &idempotency, response.application.id).await?;
        tx.commit().await.map_err(stored(conflict))?;
        Ok(response)
    }

    /// The credentials of an application, without their tokens.
    pub async fn list_credentials(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<CredentialPage> {
        let caller = caller(principal)?;
        let organization_id = self.owned_application(project_id, application_id).await?;
        authorize_organization(caller, organization_id, ProvisioningTarget::Application)?;
        let items = list_credentials(&self.pool, organization_id, project_id, application_id)
            .await
            .map_err(stored(ProvisioningConflict::CredentialName))?;
        Ok(CredentialPage { items })
    }

    /// Issues another credential for an application, shown once. A retry
    /// under the same idempotency key is refused, because the credential
    /// cannot be shown again.
    pub async fn issue_credential(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        name: &str,
        idempotency_key: Option<&[u8]>,
    ) -> Result<IssuedCredentialResponse> {
        let caller = caller(principal)?;
        validate_credential_name(name)?;
        let organization_id = self.owned_application(project_id, application_id).await?;
        authorize_organization(caller, organization_id, ProvisioningTarget::Application)?;
        let conflict = ProvisioningConflict::CredentialName;
        let mut tx = self.pool.begin().await.map_err(stored(conflict))?;
        let project_id_text = project_id.to_string();
        let application_id_text = application_id.to_string();
        let idempotency = reserve_idempotency(
            &mut tx,
            idempotency_key,
            "issue_application_credential",
            &[&project_id_text, &application_id_text, name],
        )
        .await?;
        if matches!(idempotency, Idempotency::Replay(_)) {
            return Err(ProvisioningServiceError::Conflict(
                ProvisioningConflict::OperationAlreadyCompleted,
            ));
        }
        let credential = issue(&mut tx, organization_id, project_id, application_id, name)
            .await
            .map_err(stored(conflict))?;
        let response = issued_response(&credential);
        complete_idempotency(&mut tx, &idempotency, response.id).await?;
        tx.commit().await.map_err(stored(conflict))?;
        Ok(response)
    }

    /// Revokes one credential of an application.
    pub async fn revoke_credential(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        credential_id: Uuid,
    ) -> Result<()> {
        let caller = caller(principal)?;
        let organization_id = self.owned_application(project_id, application_id).await?;
        authorize_organization(caller, organization_id, ProvisioningTarget::Application)?;
        revoke(
            &self.pool,
            organization_id,
            project_id,
            application_id,
            credential_id,
        )
        .await
        .map_err(stored(ProvisioningConflict::CredentialName))?
        .ok_or(ProvisioningServiceError::NotFound(
            ProvisioningTarget::Credential,
        ))?;
        Ok(())
    }

    async fn owned_application(&self, project_id: Uuid, application_id: Uuid) -> Result<Uuid> {
        ApplicationRepository::organization_of(&self.pool, project_id, application_id)
            .await
            .map_err(stored(ProvisioningConflict::ApplicationSlug))?
            .ok_or(ProvisioningServiceError::NotFound(
                ProvisioningTarget::Application,
            ))
    }
}

/// Super administrators act on the platform; everyone else needs an active
/// organization.
fn caller(principal: IdentityPrincipal) -> Result<Caller> {
    if principal.is_super_admin {
        Ok(Caller::PlatformSuperAdmin)
    } else {
        principal
            .tenant()
            .map(Caller::Tenant)
            .ok_or(ProvisioningServiceError::InvalidCredential)
    }
}

fn require_platform_admin(principal: IdentityPrincipal) -> Result<()> {
    match caller(principal)? {
        Caller::PlatformSuperAdmin => Ok(()),
        Caller::Tenant(_) => Err(ProvisioningServiceError::SuperAdminRequired),
    }
}

/// Admits super administrators and the organization's owners. Members of
/// another organization do not see it at all.
fn authorize_organization(
    caller: Caller,
    organization_id: Uuid,
    missing: ProvisioningTarget,
) -> Result<()> {
    match caller {
        Caller::PlatformSuperAdmin => Ok(()),
        Caller::Tenant(tenant)
            if tenant.organization_id == organization_id && tenant.role.is_owner() =>
        {
            Ok(())
        }
        Caller::Tenant(tenant) if tenant.organization_id == organization_id => {
            Err(ProvisioningServiceError::OwnerRequired)
        }
        Caller::Tenant(_) => Err(ProvisioningServiceError::NotFound(missing)),
    }
}

fn validate_slug(value: &str) -> Result<()> {
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
        Err(ProvisioningServiceError::Invalid {
            field: "slug",
            detail: "slug must contain 1-63 lowercase letters, digits, or single hyphens",
        })
    }
}

fn validate_name(value: &str) -> Result<()> {
    if value.trim() == value && (1..=120).contains(&value.chars().count()) {
        Ok(())
    } else {
        Err(ProvisioningServiceError::Invalid {
            field: "name",
            detail: "name must contain 1-120 characters without surrounding whitespace",
        })
    }
}

fn validate_credential_name(value: &str) -> Result<()> {
    let valid = (1..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(ProvisioningServiceError::Invalid {
            field: "name",
            detail: "credential name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        })
    }
}

/// Reserves the idempotency key for this operation and request, or finds the
/// earlier reservation. Without a key there is nothing to reserve. The key
/// must be a canonical UUID; reusing it for a different request is refused.
async fn reserve_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    idempotency_key: Option<&[u8]>,
    operation: &'static str,
    fingerprint_parts: &[&str],
) -> Result<Idempotency> {
    let Some(raw_key) = idempotency_key else {
        return Ok(Idempotency::Disabled);
    };
    let key = std::str::from_utf8(raw_key).ok().and_then(|value| {
        Uuid::parse_str(value)
            .ok()
            .filter(|parsed| parsed.to_string() == value)
    });
    let Some(key) = key else {
        return Err(ProvisioningServiceError::Invalid {
            field: "idempotency_key",
            detail: "Idempotency-Key must be a canonical UUID",
        });
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
    let reused = stored(ProvisioningConflict::IdempotencyKeyReused);
    let inserted = ProvisioningKeyRepository::reserve(
        &mut **tx,
        reservation_id,
        operation,
        key_hash.as_slice(),
        fingerprint.as_slice(),
    )
    .await
    .map_err(&reused)?;
    if inserted.is_some() {
        return Ok(Idempotency::Fresh(reservation_id));
    }
    let existing: (Vec<u8>, Option<Uuid>) =
        ProvisioningKeyRepository::reservation(&mut **tx, operation, key_hash.as_slice())
            .await
            .map_err(&reused)?;
    if existing.0.as_slice() != fingerprint.as_slice() {
        return Err(ProvisioningServiceError::Conflict(
            ProvisioningConflict::IdempotencyKeyReused,
        ));
    }
    existing
        .1
        .map(Idempotency::Replay)
        .ok_or(ProvisioningServiceError::Conflict(
            ProvisioningConflict::IdempotencyKeyReused,
        ))
}

async fn complete_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    state: &Idempotency,
    resource_id: Uuid,
) -> Result<()> {
    if let Idempotency::Fresh(reservation_id) = state {
        ProvisioningKeyRepository::complete(&mut **tx, resource_id, *reservation_id)
            .await
            .map_err(stored(ProvisioningConflict::IdempotencyKeyReused))?;
    }
    Ok(())
}

async fn enqueue_application_mail(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    organization_id: Uuid,
    project_name: &str,
    application: &ApplicationResponse,
) -> Result<()> {
    if !mail.enabled {
        return Ok(());
    }
    let rows = UserRepository::active_organization_owners(&mut **tx, organization_id)
        .await
        .map_err(stored(ProvisioningConflict::ApplicationSlug))?;
    if rows.len() > crate::transactional_mail::MAX_RECIPIENTS {
        return Err(too_many_owners());
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
    .map_err(|error| match error {
        MailError::TooManyRecipients => too_many_owners(),
        MailError::Database(error) => store_error(error, ProvisioningConflict::ApplicationSlug),
        MailError::InvalidPayload => ProvisioningServiceError::MailPayloadRejected,
    })
}

fn too_many_owners() -> ProvisioningServiceError {
    ProvisioningServiceError::Invalid {
        field: "owners",
        detail: "verified owner recipient limit exceeded",
    }
}

fn issued_response(credential: &IssuedApplicationCredential) -> IssuedCredentialResponse {
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

    #[test]
    fn validation_fields_are_stable() {
        assert!(matches!(
            validate_slug("Invalid--slug"),
            Err(ProvisioningServiceError::Invalid { field: "slug", .. })
        ));
        assert!(matches!(
            validate_credential_name("rotation 1"),
            Err(ProvisioningServiceError::Invalid { field: "name", .. })
        ));
    }

    #[test]
    fn credential_names_use_a_bounded_ascii_operator_safe_format() {
        for valid in ["default", "rotation-2026-08", "blue_green.v2"] {
            validate_credential_name(valid).unwrap();
        }
        for invalid in ["", " leading", "two words", "юникод", "_leading"] {
            assert!(validate_credential_name(invalid).is_err());
        }
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::auth::OrganizationRole;
        use crate::repository::test_support::tenant;

        fn tenant_principal(organization_id: Uuid, role: OrganizationRole) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                active_organization_id: Some(organization_id),
                organization_role: Some(role),
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn platform() -> IdentityPrincipal {
            IdentityPrincipal {
                active_organization_id: None,
                organization_role: None,
                is_super_admin: true,
                ..tenant_principal(Uuid::nil(), OrganizationRole::Member)
            }
        }

        fn named(slug: &str) -> NamedResource {
            NamedResource {
                slug: slug.into(),
                name: "Resource".into(),
            }
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn platform_routes_classify_the_caller_first(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = ProvisioningService::new(pool.clone(), MailConfig::default());
            let unattached = IdentityPrincipal {
                active_organization_id: None,
                organization_role: None,
                ..tenant_principal(Uuid::nil(), OrganizationRole::Owner)
            };
            assert!(matches!(
                service.list_organizations(unattached).await,
                Err(ProvisioningServiceError::InvalidCredential)
            ));
            let owner = tenant_principal(tenant.organization_id, OrganizationRole::Owner);
            assert!(matches!(
                service.list_organizations(owner).await,
                Err(ProvisioningServiceError::SuperAdminRequired)
            ));
            let organizations = service.list_organizations(platform()).await.unwrap();
            assert_eq!(organizations.items.len(), 1);
            assert!(matches!(
                service.list_projects(platform(), Uuid::new_v4()).await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Organization
                ))
            ));
            let projects = service
                .list_projects(platform(), tenant.organization_id)
                .await
                .unwrap();
            assert_eq!(projects.items.len(), 1);
            let applications = service
                .list_applications(platform(), tenant.project_id)
                .await
                .unwrap();
            assert_eq!(applications.items.len(), 1);
            let application = service
                .get_application(platform(), tenant.project_id, tenant.application_id)
                .await
                .unwrap();
            assert_eq!(application.id, tenant.application_id);
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn idempotency_keys_replay_or_refuse_repeated_creations(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = ProvisioningService::new(pool.clone(), MailConfig::default());
            let key = Uuid::new_v4().to_string();
            let key = Some(key.as_bytes());

            assert!(matches!(
                service
                    .create_organization(platform(), named("acme"), Some(b"not-a-uuid"))
                    .await,
                Err(ProvisioningServiceError::Invalid {
                    field: "idempotency_key",
                    ..
                })
            ));
            let Created::New(first) = service
                .create_organization(platform(), named("acme"), key)
                .await
                .unwrap()
            else {
                panic!("the first request creates the organization");
            };
            let Created::Replayed(again) = service
                .create_organization(platform(), named("acme"), key)
                .await
                .unwrap()
            else {
                panic!("the same request under the same key replays");
            };
            assert_eq!(again.id, first.id);
            assert!(matches!(
                service
                    .create_organization(platform(), named("other"), key)
                    .await,
                Err(ProvisioningServiceError::Conflict(
                    ProvisioningConflict::IdempotencyKeyReused
                ))
            ));
            assert!(matches!(
                service
                    .create_organization(platform(), named("acme"), None)
                    .await,
                Err(ProvisioningServiceError::Conflict(
                    ProvisioningConflict::OrganizationSlug
                ))
            ));

            // An application's credential cannot be shown again, so a retry
            // is refused rather than replayed.
            let owner = tenant_principal(tenant.organization_id, OrganizationRole::Owner);
            let app_key = Uuid::new_v4().to_string();
            let created = service
                .create_application(
                    owner,
                    tenant.project_id,
                    named("worker"),
                    Some(app_key.as_bytes()),
                )
                .await
                .unwrap();
            assert!(created.credential.shown_once);
            assert!(matches!(
                service
                    .create_application(
                        owner,
                        tenant.project_id,
                        named("worker"),
                        Some(app_key.as_bytes()),
                    )
                    .await,
                Err(ProvisioningServiceError::Conflict(
                    ProvisioningConflict::OperationAlreadyCompleted
                ))
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn tenants_provision_only_as_owners_of_their_organization(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = ProvisioningService::new(pool.clone(), MailConfig::default());
            let organization = tenant.organization_id;
            let owner = tenant_principal(organization, OrganizationRole::Owner);
            let member = tenant_principal(organization, OrganizationRole::Member);
            let stranger = tenant_principal(Uuid::new_v4(), OrganizationRole::Owner);

            assert!(matches!(
                service
                    .create_project(member, organization, named("-"), None)
                    .await,
                Err(ProvisioningServiceError::OwnerRequired)
            ));
            assert!(matches!(
                service
                    .create_project(stranger, organization, named("-"), None)
                    .await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Organization
                ))
            ));
            assert!(matches!(
                service
                    .create_project(owner, organization, named("-"), None)
                    .await,
                Err(ProvisioningServiceError::Invalid { field: "slug", .. })
            ));
            let Created::New(project) = service
                .create_project(owner, organization, named("billing"), None)
                .await
                .unwrap()
            else {
                panic!("a project without a key is new");
            };
            assert_eq!(project.organization_id, organization);

            // Application fields are validated before the project is looked up.
            assert!(matches!(
                service
                    .create_application(owner, Uuid::new_v4(), named("-"), None)
                    .await,
                Err(ProvisioningServiceError::Invalid { field: "slug", .. })
            ));
            assert!(matches!(
                service
                    .create_application(owner, Uuid::new_v4(), named("api"), None)
                    .await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Project
                ))
            ));
            assert!(matches!(
                service
                    .create_application(stranger, tenant.project_id, named("api"), None)
                    .await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Project
                ))
            ));

            // Credentials: the name is checked before the application.
            let (project_id, application_id) = (tenant.project_id, tenant.application_id);
            assert!(matches!(
                service
                    .issue_credential(owner, project_id, Uuid::new_v4(), "two words", None)
                    .await,
                Err(ProvisioningServiceError::Invalid { field: "name", .. })
            ));
            assert!(matches!(
                service
                    .issue_credential(owner, project_id, Uuid::new_v4(), "rotation", None)
                    .await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Application
                ))
            ));
            let issued = service
                .issue_credential(owner, project_id, application_id, "rotation", None)
                .await
                .unwrap();
            assert!(matches!(
                service
                    .issue_credential(owner, project_id, application_id, "rotation", None)
                    .await,
                Err(ProvisioningServiceError::Conflict(
                    ProvisioningConflict::CredentialName
                ))
            ));
            let listed = service
                .list_credentials(member, project_id, application_id)
                .await;
            assert!(matches!(
                listed,
                Err(ProvisioningServiceError::OwnerRequired)
            ));
            let listed = service
                .list_credentials(owner, project_id, application_id)
                .await
                .unwrap();
            assert!(listed.items.iter().any(|item| item.id == issued.id));
            service
                .revoke_credential(owner, project_id, application_id, issued.id)
                .await
                .unwrap();
            assert!(matches!(
                service
                    .revoke_credential(owner, project_id, application_id, Uuid::new_v4())
                    .await,
                Err(ProvisioningServiceError::NotFound(
                    ProvisioningTarget::Credential
                ))
            ));
        }
    }
}
