//! Access administration: the platform's users, organizations, projects and
//! applications as a super administrator sees them, the members of an
//! organization or a project, the access audit, and the session changes that
//! pick an organization or confirm a privileged action.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
use crate::access_control::{
    EffectiveAccessSource, ProjectRole, can_manage_organization_role, can_manage_project_role,
    resolve_project_access,
};
use crate::application_credentials::issue as issue_application_credential;
use crate::auth::{IdentityPrincipal, OrganizationRole, SessionToken};
use crate::repository::access_audit::AccessAuditRepository;
use crate::repository::users::UserRepository;
use crate::repository::{
    ApplicationRepository, MembershipRepository, OrganizationRepository, OrganizationStatus,
    ProjectRepository, SessionRepository,
};
use crate::service::identity::{insert_session_with_context, valid_name, valid_slug};
use crate::service::invitations::{
    InvitationServiceError, InvitationView, current_organization_owner_invitation,
    issue_organization_invitation,
};
use crate::transactional_mail::Locale;
use crate::web_api::{OrganizationMode, WebApiConfig};

const DEFAULT_PAGE_LIMIT: i64 = 50;
const MAX_PAGE_LIMIT: i64 = 100;

/// Why an access use case failed.
#[derive(Debug, Error)]
pub enum AccessServiceError {
    /// A platform use case was called by someone who is not a super
    /// administrator.
    #[error("super administrator role is required")]
    SuperAdminRequired,
    /// A privileged platform use case needs a recent password confirmation.
    #[error("recent password confirmation is required")]
    PrivilegeConfirmationRequired,
    /// The named resource does not exist, or the principal may not see it.
    #[error("{0:?} not found")]
    NotFound(AccessTarget),
    /// The principal sees the resource but lacks the authority named.
    #[error("{0:?} denied")]
    Denied(Denial),
    /// Nobody may raise their own role.
    #[error("self promotion is forbidden")]
    SelfPromotion,
    /// The password given to confirm a privileged action is wrong.
    #[error("current password is incorrect")]
    CurrentPasswordInvalid,
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(&'static str),
    /// The user cannot be made a super administrator.
    #[error("user is not eligible")]
    UserNotEligible,
    /// The mutation conflicts with the current authority.
    #[error("{0:?}")]
    Conflict(AccessConflict),
    /// A stored member has a role this server does not know.
    #[error("member role is unreadable")]
    UnreadableMember,
    /// Inviting a new organization's first owner failed.
    #[error(transparent)]
    Invitation(InvitationServiceError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// What a [`AccessServiceError::NotFound`] could not find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTarget {
    Organization,
    Project,
    User,
}

/// The authority a [`AccessServiceError::Denied`] principal lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Owners and admins administer an organization.
    OrganizationAdministration,
    /// Only owners read the organization audit.
    OwnerRequired,
    /// The principal may not move the member between these roles.
    RoleTransition,
    /// The principal may not remove a member in this role.
    MembershipRemoval,
    /// Project admins (and those who inherit it) manage project members.
    ProjectAdministration,
    /// The principal may not grant this project role.
    ProjectRoleGrant,
    /// The principal may not move a project member into this role.
    ProjectRoleTransition,
    /// The principal may not remove project members.
    ProjectMembershipRemoval,
}

/// What a [`AccessServiceError::Conflict`] mutation conflicts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessConflict {
    /// Single-organization mode already has its organization.
    OrganizationLimitReached,
    /// Only an organization that never got an owner can be deleted.
    OrganizationNotDeletable,
    /// The platform must keep at least one super administrator.
    LastSuperAdminRequired,
    /// The user is already a member of the project.
    MembershipExists,
    /// The organization must keep at least one owner.
    LastOrganizationOwnerRequired,
}

type Result<T, E = AccessServiceError> = std::result::Result<T, E>;

/// What the sign-in page may offer.
#[derive(Debug, Serialize)]
pub struct AuthenticationPolicy {
    public_signup_enabled: bool,
    invitation_registration_enabled: bool,
    organization_mode: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SessionSelection {
    active_organization_id: Uuid,
    role: OrganizationRole,
}

#[derive(Debug, Serialize)]
pub struct PrivilegeState {
    privileged_until: DateTime<Utc>,
}

/// A use case that replaced the caller's session: its result and the token of
/// the new session.
#[derive(Debug)]
pub struct SessionChange<T> {
    pub result: T,
    pub session: SessionToken,
}

/// Columns: `id`, `email`, `display_name`, `email_verified`, `enabled`,
/// `is_super_admin`, `created_at`.
#[derive(Debug, Serialize, FromRow)]
pub struct UserSummary {
    id: Uuid,
    email: String,
    display_name: String,
    email_verified: bool,
    enabled: bool,
    is_super_admin: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserPage {
    items: Vec<UserSummary>,
    next_cursor: Option<Uuid>,
}

/// Columns: `id`, `slug`, `name`, `status`, `created_at`, `updated_at`.
#[derive(Debug, Serialize, FromRow)]
pub struct PlatformOrganization {
    id: Uuid,
    slug: String,
    name: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[sqlx(skip)]
    current_owner_invitation: Option<InvitationView>,
}

#[derive(Debug, Serialize)]
pub struct PlatformOrganizationPage {
    items: Vec<PlatformOrganization>,
    next_cursor: Option<Uuid>,
}

/// Who owns an organization a super administrator creates.
#[derive(Clone, Debug)]
pub enum Ownership {
    /// The owner is invited by mail; the organization waits for them.
    InvitedOwner { email: String, locale: Locale },
    /// The super administrator owns it.
    SelfOwner,
}

/// An organization a super administrator creates.
#[derive(Clone, Debug)]
pub struct NewPlatformOrganization {
    pub slug: String,
    pub name: String,
    pub ownership: Ownership,
}

#[derive(Debug, Serialize)]
pub struct ProvisionedOrganization {
    organization: PlatformOrganization,
    invitation: Option<InvitationView>,
}

/// A project or an application to create.
#[derive(Clone, Debug)]
pub struct NamedResource {
    pub slug: String,
    pub name: String,
}

/// Columns: `id`, `slug`, `name`, `created_at`, `archived_at`,
/// `application_count`, `runtime_group_count`.
#[derive(Debug, Serialize, FromRow)]
pub struct PlatformProject {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    application_count: i64,
    runtime_group_count: i64,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<EffectiveAccessSource>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct PlatformProjectPage {
    items: Vec<PlatformProject>,
    next_cursor: Option<Uuid>,
}

/// Columns: `id`, `project_id`, `slug`, `name`, `created_at`,
/// `release_count`, `runtime_group_count`, `latest_observed_at`.
#[derive(Debug, Serialize, FromRow)]
pub struct PlatformApplication {
    id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    release_count: i64,
    runtime_group_count: i64,
    latest_observed_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<EffectiveAccessSource>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ProvisionedApplication {
    id: Uuid,
    organization_id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PlatformApplicationPage {
    items: Vec<PlatformApplication>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct IssuedCredential {
    id: Uuid,
    name: String,
    token: String,
    token_hint: String,
    created_at: DateTime<Utc>,
    shown_once: bool,
}

#[derive(Debug, Serialize)]
pub struct CreatedPlatformApplication {
    application: ProvisionedApplication,
    credential: IssuedCredential,
}

#[derive(Debug, Serialize)]
pub struct OrganizationMember {
    user_id: Uuid,
    email: String,
    display_name: String,
    role: OrganizationRole,
    enabled: bool,
    email_verified: bool,
    created_at: DateTime<Utc>,
    can_change_role: serde_json::Value,
    can_remove: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct OrganizationMemberPage {
    items: Vec<OrganizationMember>,
    next_cursor: Option<Uuid>,
}

type OrganizationMemberRow = (Uuid, String, String, String, bool, bool, DateTime<Utc>);

#[derive(Debug, Serialize)]
pub struct ProjectMember {
    user_id: Uuid,
    email: String,
    display_name: String,
    role: ProjectRole,
    access_source: EffectiveAccessSource,
    created_at: DateTime<Utc>,
    can_change_role: serde_json::Value,
    can_remove: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ProjectMemberPage {
    items: Vec<ProjectMember>,
    next_cursor: Option<Uuid>,
}

/// Columns: `id`, `actor_kind`, `actor_user_id`, `action`, `organization_id`,
/// `project_id`, `target_user_id`, `invitation_id`, `previous_role`,
/// `new_role`, `outcome`, `request_id`, `created_at`.
#[derive(Debug, Serialize, FromRow)]
pub struct AuditRecord {
    id: Uuid,
    actor_kind: String,
    actor_user_id: Option<Uuid>,
    action: String,
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    invitation_id: Option<Uuid>,
    previous_role: Option<String>,
    new_role: Option<String>,
    outcome: String,
    request_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    items: Vec<AuditRecord>,
    next_cursor: Option<Uuid>,
}

/// A page request: where to continue and how many items to return. The limit
/// defaults to 50 and is clamped to 1..=100.
#[derive(Clone, Copy, Debug, Default)]
pub struct PageRequest {
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

impl PageRequest {
    fn limit(self) -> i64 {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT)
    }
}

/// The caller of a project member use case.
struct ProjectActor {
    principal: IdentityPrincipal,
    organization_id: Uuid,
    role: ProjectRole,
}

#[derive(Clone, Debug)]
pub struct AccessService {
    pool: PgPool,
    config: WebApiConfig,
}

impl AccessService {
    pub fn new(pool: PgPool, config: &WebApiConfig) -> Self {
        Self {
            pool,
            config: config.clone(),
        }
    }

    /// The sign-in options this deployment offers.
    pub fn authentication_policy(&self) -> AuthenticationPolicy {
        let organization_mode = match self.config.organization_mode {
            OrganizationMode::Single => "single",
            OrganizationMode::Multiple => "multiple",
        };
        AuthenticationPolicy {
            public_signup_enabled: self.config.public_signup_enabled,
            invitation_registration_enabled: true,
            organization_mode,
        }
    }

    /// Makes one of the principal's active organizations the active one: the
    /// current session is revoked and a new one opened in that organization.
    pub async fn select_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
    ) -> Result<SessionChange<SessionSelection>> {
        let role = MembershipRepository::organization_role_when_active(
            &self.pool,
            principal.user_id,
            organization_id,
        )
        .await?;
        let role: OrganizationRole = role
            .and_then(|value| value.parse().ok())
            .ok_or(AccessServiceError::NotFound(AccessTarget::Organization))?;
        let mut tx = self.pool.begin().await?;
        SessionRepository::revoke(&mut *tx, principal.session_id).await?;
        let (_, session) = insert_session_with_context(
            &mut tx,
            principal.user_id,
            Some(organization_id),
            principal.privileged_until,
            self.config.session_lifetime,
        )
        .await?;
        tx.commit().await?;
        Ok(SessionChange {
            result: SessionSelection {
                active_organization_id: organization_id,
                role,
            },
            session,
        })
    }

    /// Confirms a super administrator's password: the current session is
    /// replaced by one that may perform privileged actions for 15 minutes.
    pub async fn confirm_privilege(
        &self,
        principal: IdentityPrincipal,
        current_password: &str,
        request_id: &str,
    ) -> Result<SessionChange<PrivilegeState>> {
        require_platform(principal, false)?;
        let password_hash: String =
            UserRepository::password_hash(&self.pool, principal.user_id).await?;
        if !crate::auth::verify_password(current_password, &password_hash) {
            return Err(AccessServiceError::CurrentPasswordInvalid);
        }
        let until = Utc::now() + Duration::minutes(15);
        let mut tx = self.pool.begin().await?;
        SessionRepository::revoke(&mut *tx, principal.session_id).await?;
        let (_, session) = insert_session_with_context(
            &mut tx,
            principal.user_id,
            principal.active_organization_id,
            Some(until),
            self.config.session_lifetime,
        )
        .await?;
        audit(
            &mut tx,
            principal.user_id,
            "privilege.confirmed",
            AuditSubject {
                target_user_id: Some(principal.user_id),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(SessionChange {
            result: PrivilegeState {
                privileged_until: until,
            },
            session,
        })
    }

    /// Every user on the platform.
    pub async fn list_platform_users(
        &self,
        principal: IdentityPrincipal,
        page: PageRequest,
    ) -> Result<UserPage> {
        require_platform(principal, false)?;
        let limit = page.limit();
        let mut items: Vec<UserSummary> =
            UserRepository::platform_page(&self.pool, page.cursor, limit + 1).await?;
        let next_cursor = trim_page(&mut items, limit, |item| item.id);
        Ok(UserPage { items, next_cursor })
    }

    /// Every organization on the platform.
    pub async fn list_platform_organizations(
        &self,
        principal: IdentityPrincipal,
        page: PageRequest,
    ) -> Result<PlatformOrganizationPage> {
        require_platform(principal, false)?;
        let limit = page.limit();
        let mut items: Vec<PlatformOrganization> =
            OrganizationRepository::platform_page(&self.pool, page.cursor, limit + 1).await?;
        let next_cursor = trim_page(&mut items, limit, |item| item.id);
        Ok(PlatformOrganizationPage { items, next_cursor })
    }

    /// One organization with the pending invitation of its first owner.
    pub async fn get_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
    ) -> Result<PlatformOrganization> {
        require_platform(principal, false)?;
        let mut organization: PlatformOrganization =
            OrganizationRepository::platform_get(&self.pool, organization_id)
                .await?
                .ok_or(AccessServiceError::NotFound(AccessTarget::Organization))?;
        organization.current_owner_invitation =
            current_organization_owner_invitation(&self.pool, organization_id).await?;
        Ok(organization)
    }

    /// Creates an organization owned by the super administrator, or waiting
    /// for an invited owner. In single-organization mode only the first
    /// succeeds.
    pub async fn create_platform_organization(
        &self,
        principal: IdentityPrincipal,
        input: NewPlatformOrganization,
        request_id: &str,
    ) -> Result<ProvisionedOrganization> {
        let actor = require_platform(principal, true)?;
        if !valid_slug(&input.slug) || !valid_name(&input.name) {
            return Err(AccessServiceError::Invalid("organization is invalid"));
        }
        let mut tx = self.pool.begin().await?;
        ensure_organization_capacity(&mut tx, self.config.organization_mode).await?;
        let organization_id = Uuid::new_v4();
        let status = if matches!(input.ownership, Ownership::SelfOwner) {
            OrganizationStatus::Active
        } else {
            OrganizationStatus::PendingOwner
        };
        let stored = OrganizationRepository::insert(
            &mut *tx,
            organization_id,
            &input.slug,
            &input.name,
            status,
        )
        .await?;
        let organization = PlatformOrganization {
            id: stored.id,
            slug: stored.slug,
            name: stored.name,
            status: stored.status,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
            current_owner_invitation: None,
        };
        let invitation = match input.ownership {
            Ownership::SelfOwner => {
                MembershipRepository::insert_organization_role(
                    &mut *tx,
                    organization_id,
                    actor.user_id,
                    "owner",
                )
                .await?;
                None
            }
            Ownership::InvitedOwner { email, locale } => Some(
                issue_organization_invitation(
                    &mut tx,
                    &self.config,
                    actor.user_id,
                    organization_id,
                    &email,
                    OrganizationRole::Owner,
                    locale,
                    request_id,
                )
                .await
                .map_err(AccessServiceError::Invitation)?,
            ),
        };
        audit(
            &mut tx,
            actor.user_id,
            "organization.created",
            AuditSubject {
                organization_id: Some(organization_id),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(ProvisionedOrganization {
            organization,
            invitation,
        })
    }

    /// Deletes an organization that never got an owner.
    pub async fn delete_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let actor = require_platform(principal, true)?;
        let mut tx = self.pool.begin().await?;
        let deleted = OrganizationRepository::discard_unclaimed(&mut *tx, organization_id).await?;
        if !deleted {
            return Err(AccessServiceError::Conflict(
                AccessConflict::OrganizationNotDeletable,
            ));
        }
        audit(
            &mut tx,
            actor.user_id,
            "organization.deleted",
            AuditSubject::default(),
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The projects of an organization, with the platform's full authority
    /// over each.
    pub async fn list_platform_projects(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        page: PageRequest,
    ) -> Result<PlatformProjectPage> {
        require_platform(principal, false)?;
        let limit = page.limit();
        let mut items: Vec<PlatformProject> =
            ProjectRepository::platform_page(&self.pool, organization_id, page.cursor, limit + 1)
                .await?;
        for item in &mut items {
            item.effective_project_role = Some(ProjectRole::Admin);
            item.effective_access_source = Some(EffectiveAccessSource::Platform);
            item.capabilities = platform_capabilities();
        }
        let next_cursor = trim_page(&mut items, limit, |item| item.id);
        Ok(PlatformProjectPage { items, next_cursor })
    }

    /// Creates a project in an organization.
    pub async fn create_platform_project(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        input: NamedResource,
        request_id: &str,
    ) -> Result<PlatformProject> {
        let actor = require_platform(principal, false)?;
        validate_named_resource(&input)?;
        let mut tx = self.pool.begin().await?;
        let stored = ProjectRepository::insert(
            &mut *tx,
            Uuid::new_v4(),
            organization_id,
            &input.slug,
            &input.name,
        )
        .await?
        .ok_or(AccessServiceError::NotFound(AccessTarget::Organization))?;
        // A project that was just created has no applications and no runtime
        // groups yet, so the counts are known without a query.
        let project = PlatformProject {
            id: stored.id,
            slug: stored.slug,
            name: stored.name,
            created_at: stored.created_at,
            archived_at: stored.archived_at,
            application_count: 0,
            runtime_group_count: 0,
            effective_project_role: Some(ProjectRole::Admin),
            effective_access_source: Some(EffectiveAccessSource::Platform),
            capabilities: platform_capabilities(),
        };
        audit(
            &mut tx,
            actor.user_id,
            "project.created",
            AuditSubject {
                organization_id: Some(organization_id),
                project_id: Some(project.id),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(project)
    }

    /// The applications of a project, with the platform's full authority over
    /// each.
    pub async fn list_platform_applications(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        page: PageRequest,
    ) -> Result<PlatformApplicationPage> {
        require_platform(principal, false)?;
        let limit = page.limit();
        let mut items: Vec<PlatformApplication> =
            ApplicationRepository::platform_page(&self.pool, project_id, page.cursor, limit + 1)
                .await?;
        for item in &mut items {
            item.effective_project_role = Some(ProjectRole::Admin);
            item.effective_access_source = Some(EffectiveAccessSource::Platform);
            item.capabilities = platform_capabilities();
        }
        let next_cursor = trim_page(&mut items, limit, |item| item.id);
        Ok(PlatformApplicationPage { items, next_cursor })
    }

    /// Creates an application with its first credential, which is shown once.
    pub async fn create_platform_application(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        input: NamedResource,
        request_id: &str,
    ) -> Result<CreatedPlatformApplication> {
        let actor = require_platform(principal, false)?;
        validate_named_resource(&input)?;
        let mut tx = self.pool.begin().await?;
        let stored = ApplicationRepository::insert(
            &mut *tx,
            Uuid::new_v4(),
            project_id,
            &input.slug,
            &input.name,
        )
        .await?
        .ok_or(AccessServiceError::NotFound(AccessTarget::Project))?;
        let application = ProvisionedApplication {
            id: stored.id,
            organization_id: stored.organization_id,
            project_id: stored.project_id,
            slug: stored.slug,
            name: stored.name,
            created_at: stored.created_at,
        };
        let issued = issue_application_credential(
            &mut tx,
            application.organization_id,
            project_id,
            application.id,
            "default",
        )
        .await?;
        let token = issued.token().to_owned();
        let credential = IssuedCredential {
            id: issued.summary.id,
            name: issued.summary.name,
            token,
            token_hint: issued.summary.token_hint,
            created_at: issued.summary.created_at,
            shown_once: true,
        };
        audit(
            &mut tx,
            actor.user_id,
            "credential.issued",
            AuditSubject {
                organization_id: Some(application.organization_id),
                project_id: Some(project_id),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(CreatedPlatformApplication {
            application,
            credential,
        })
    }

    /// Enables or disables a user. Every session of the user ends either way.
    pub async fn set_user_status(
        &self,
        principal: IdentityPrincipal,
        user_id: Uuid,
        disabled: bool,
        request_id: &str,
    ) -> Result<UserSummary> {
        let actor = require_platform(principal, true)?;
        let mut tx = self.pool.begin().await?;
        MembershipRepository::lock_authority(&mut *tx).await?;
        let item: UserSummary = UserRepository::set_disabled(&mut *tx, user_id, disabled)
            .await?
            .ok_or(AccessServiceError::NotFound(AccessTarget::User))?;
        SessionRepository::revoke_all_for_user(&mut *tx, user_id, None).await?;
        audit(
            &mut tx,
            actor.user_id,
            if disabled {
                "user.disabled"
            } else {
                "user.enabled"
            },
            AuditSubject {
                target_user_id: Some(user_id),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(item)
    }

    /// Makes another eligible user a super administrator.
    pub async fn grant_super_admin(
        &self,
        principal: IdentityPrincipal,
        user_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let actor = require_platform(principal, true)?;
        if actor.user_id == user_id {
            return Err(AccessServiceError::SelfPromotion);
        }
        let mut tx = self.pool.begin().await?;
        MembershipRepository::lock_authority(&mut *tx).await?;
        let eligible: bool = UserRepository::eligible_for_super_admin(&mut *tx, user_id).await?;
        if !eligible {
            return Err(AccessServiceError::UserNotEligible);
        }
        UserRepository::grant_super_admin(&mut *tx, user_id, actor.user_id).await?;
        audit(
            &mut tx,
            actor.user_id,
            "platform_role.granted",
            AuditSubject {
                target_user_id: Some(user_id),
                new_role: Some("super_admin"),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Takes the super administrator role away and ends the user's sessions.
    /// The last super administrator keeps it.
    pub async fn revoke_super_admin(
        &self,
        principal: IdentityPrincipal,
        user_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let actor = require_platform(principal, true)?;
        let mut tx = self.pool.begin().await?;
        MembershipRepository::lock_authority(&mut *tx).await?;
        let result = UserRepository::revoke_super_admin(&mut *tx, user_id).await;
        map_authority_result(result, AccessConflict::LastSuperAdminRequired)?;
        SessionRepository::revoke_all_for_user(&mut *tx, user_id, None).await?;
        audit(
            &mut tx,
            actor.user_id,
            "platform_role.revoked",
            AuditSubject {
                target_user_id: Some(user_id),
                previous_role: Some("super_admin"),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The members of an organization, each with whether the principal may
    /// change or remove them. The last owner can never be removed.
    pub async fn list_organization_members(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        page: PageRequest,
    ) -> Result<OrganizationMemberPage> {
        let actor = organization_admin(principal, organization_id)?;
        let limit = page.limit();
        let rows: Vec<OrganizationMemberRow> = MembershipRepository::organization_member_page(
            &self.pool,
            organization_id,
            page.cursor,
            limit + 1,
        )
        .await?;
        let mut items = rows
            .into_iter()
            .filter_map(organization_member)
            .collect::<Vec<_>>();
        let owner_count =
            MembershipRepository::organization_owner_count(&self.pool, organization_id).await?;
        for item in &mut items {
            let allowed = actor.is_super_admin
                || can_manage_organization_role(
                    actor.organization_role.unwrap_or(OrganizationRole::Member),
                    item.role,
                    None,
                );
            item.can_change_role = serde_json::json!(allowed);
            item.can_remove = serde_json::json!(
                allowed && !(item.role == OrganizationRole::Owner && owner_count == 1)
            );
        }
        let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
        Ok(OrganizationMemberPage { items, next_cursor })
    }

    /// Moves an organization member to another role.
    pub async fn update_organization_member(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        user_id: Uuid,
        role: OrganizationRole,
        request_id: &str,
    ) -> Result<OrganizationMember> {
        let actor = organization_admin(principal, organization_id)?;
        let current = self.organization_member(organization_id, user_id).await?;
        if !actor.is_super_admin
            && !can_manage_organization_role(
                actor.organization_role.unwrap_or(OrganizationRole::Member),
                current.role,
                Some(role),
            )
        {
            return Err(AccessServiceError::Denied(Denial::RoleTransition));
        }
        if actor.user_id == user_id && role_promotes(current.role, role) {
            return Err(AccessServiceError::SelfPromotion);
        }
        let mut tx = self.pool.begin().await?;
        MembershipRepository::lock_authority(&mut *tx).await?;
        let result = MembershipRepository::set_organization_role(
            &mut *tx,
            organization_id,
            user_id,
            role_name(role),
        )
        .await;
        map_authority_result(result, AccessConflict::LastOrganizationOwnerRequired)?;
        audit(
            &mut tx,
            actor.user_id,
            "organization_member.role_changed",
            AuditSubject {
                organization_id: Some(organization_id),
                target_user_id: Some(user_id),
                previous_role: Some(role_name(current.role)),
                new_role: Some(role_name(role)),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        self.organization_member(organization_id, user_id).await
    }

    /// Removes a member from an organization and ends their sessions in it.
    pub async fn remove_organization_member(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        user_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let actor = organization_admin(principal, organization_id)?;
        let current = self.organization_member(organization_id, user_id).await?;
        if !actor.is_super_admin
            && !can_manage_organization_role(
                actor.organization_role.unwrap_or(OrganizationRole::Member),
                current.role,
                None,
            )
        {
            return Err(AccessServiceError::Denied(Denial::MembershipRemoval));
        }
        let mut tx = self.pool.begin().await?;
        MembershipRepository::lock_authority(&mut *tx).await?;
        let result =
            MembershipRepository::remove_organization_role(&mut *tx, organization_id, user_id)
                .await;
        map_authority_result(result, AccessConflict::LastOrganizationOwnerRequired)?;
        SessionRepository::revoke_for_user_in_organization(&mut *tx, user_id, organization_id)
            .await?;
        audit(
            &mut tx,
            actor.user_id,
            "organization_member.removed",
            AuditSubject {
                organization_id: Some(organization_id),
                target_user_id: Some(user_id),
                previous_role: Some(role_name(current.role)),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The direct members of a project, each with whether the principal may
    /// change or remove them.
    pub async fn list_project_members(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        page: PageRequest,
    ) -> Result<ProjectMemberPage> {
        let actor = self.project_actor(principal, project_id).await?;
        let limit = page.limit();
        let rows: Vec<(Uuid, String, String, String, DateTime<Utc>)> =
            MembershipRepository::project_member_page(
                &self.pool,
                project_id,
                page.cursor,
                limit + 1,
            )
            .await?;
        let mut items = rows
            .into_iter()
            .filter_map(project_member)
            .collect::<Vec<_>>();
        for item in &mut items {
            let allowed = can_manage_project_role(
                actor.principal.is_super_admin,
                actor.principal.organization_role,
                Some(actor.role),
                Some(item.role),
            );
            item.can_change_role = serde_json::json!(allowed);
            item.can_remove = serde_json::json!(allowed);
        }
        let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
        Ok(ProjectMemberPage { items, next_cursor })
    }

    /// The organization members who could be added to a project.
    pub async fn list_eligible_project_members(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        page: PageRequest,
    ) -> Result<OrganizationMemberPage> {
        let actor = self.project_actor(principal, project_id).await?;
        let limit = page.limit();
        let rows: Vec<OrganizationMemberRow> = MembershipRepository::eligible_project_member_page(
            &self.pool,
            actor.organization_id,
            project_id,
            page.cursor,
            limit + 1,
        )
        .await?;
        let mut items = rows.into_iter().filter_map(organization_member).collect();
        let next_cursor = trim_page(&mut items, limit, |item| item.user_id);
        Ok(OrganizationMemberPage { items, next_cursor })
    }

    /// Adds a user to a project in a role the principal may grant.
    pub async fn add_project_member(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        user_id: Uuid,
        role: ProjectRole,
        request_id: &str,
    ) -> Result<ProjectMember> {
        let actor = self.project_actor(principal, project_id).await?;
        if !can_manage_project_role(
            actor.principal.is_super_admin,
            actor.principal.organization_role,
            Some(actor.role),
            Some(role),
        ) {
            return Err(AccessServiceError::Denied(Denial::ProjectRoleGrant));
        }
        let mut tx = self.pool.begin().await?;
        MembershipRepository::insert_project_role(
            &mut *tx,
            actor.organization_id,
            project_id,
            user_id,
            project_role_name(role),
        )
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                AccessServiceError::Conflict(AccessConflict::MembershipExists)
            } else {
                AccessServiceError::Database(error)
            }
        })?;
        audit(
            &mut tx,
            actor.principal.user_id,
            "project_member.added",
            AuditSubject {
                organization_id: Some(actor.organization_id),
                project_id: Some(project_id),
                target_user_id: Some(user_id),
                new_role: Some(project_role_name(role)),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        self.project_member(project_id, user_id).await
    }

    /// Moves a project member into a role the principal may grant.
    pub async fn update_project_member(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        user_id: Uuid,
        role: ProjectRole,
        request_id: &str,
    ) -> Result<ProjectMember> {
        let actor = self.project_actor(principal, project_id).await?;
        if !can_manage_project_role(
            actor.principal.is_super_admin,
            actor.principal.organization_role,
            Some(actor.role),
            Some(role),
        ) {
            return Err(AccessServiceError::Denied(Denial::ProjectRoleTransition));
        }
        let current = self.project_member(project_id, user_id).await?;
        let mut tx = self.pool.begin().await?;
        MembershipRepository::set_project_role(
            &mut *tx,
            project_id,
            user_id,
            project_role_name(role),
        )
        .await?;
        audit(
            &mut tx,
            actor.principal.user_id,
            "project_member.role_changed",
            AuditSubject {
                organization_id: Some(actor.organization_id),
                project_id: Some(project_id),
                target_user_id: Some(user_id),
                previous_role: Some(project_role_name(current.role)),
                new_role: Some(project_role_name(role)),
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        self.project_member(project_id, user_id).await
    }

    /// Removes a direct member from a project.
    pub async fn remove_project_member(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        user_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let actor = self.project_actor(principal, project_id).await?;
        let current = self.project_member(project_id, user_id).await?;
        if !can_manage_project_role(
            actor.principal.is_super_admin,
            actor.principal.organization_role,
            Some(actor.role),
            None,
        ) {
            return Err(AccessServiceError::Denied(Denial::ProjectMembershipRemoval));
        }
        let mut tx = self.pool.begin().await?;
        MembershipRepository::remove_project_role(&mut *tx, project_id, user_id).await?;
        audit(
            &mut tx,
            actor.principal.user_id,
            "project_member.removed",
            AuditSubject {
                organization_id: Some(actor.organization_id),
                project_id: Some(project_id),
                target_user_id: Some(user_id),
                previous_role: Some(project_role_name(current.role)),
                ..AuditSubject::default()
            },
            request_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The access audit of one organization, for its owners.
    pub async fn list_audit(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        page: PageRequest,
    ) -> Result<AuditPage> {
        let actor = organization_admin(principal, organization_id)?;
        if !actor.is_super_admin && actor.organization_role != Some(OrganizationRole::Owner) {
            return Err(AccessServiceError::Denied(Denial::OwnerRequired));
        }
        self.query_audit(Some(organization_id), page).await
    }

    /// The access audit of the whole platform.
    pub async fn list_platform_audit(
        &self,
        principal: IdentityPrincipal,
        page: PageRequest,
    ) -> Result<AuditPage> {
        require_platform(principal, false)?;
        self.query_audit(None, page).await
    }

    async fn query_audit(
        &self,
        organization_id: Option<Uuid>,
        page: PageRequest,
    ) -> Result<AuditPage> {
        let limit = page.limit();
        let mut items: Vec<AuditRecord> =
            AccessAuditRepository::page(&self.pool, organization_id, page.cursor, limit + 1)
                .await?;
        let next_cursor = trim_page(&mut items, limit, |item| item.id);
        Ok(AuditPage { items, next_cursor })
    }

    /// Resolves the project's organization and the principal's access to the
    /// project, which must include managing its members.
    async fn project_actor(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectActor> {
        let organization_id: Uuid = ProjectRepository::organization_of(&self.pool, project_id)
            .await?
            .ok_or(AccessServiceError::NotFound(AccessTarget::Project))?;
        let access = resolve_project_access(&self.pool, principal, organization_id, project_id)
            .await?
            .ok_or(AccessServiceError::NotFound(AccessTarget::Project))?;
        if !access.can_manage_members() {
            return Err(AccessServiceError::Denied(Denial::ProjectAdministration));
        }
        Ok(ProjectActor {
            principal,
            organization_id,
            role: access.role,
        })
    }

    async fn organization_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMember> {
        let row = MembershipRepository::organization_member(&self.pool, organization_id, user_id)
            .await?
            .ok_or(AccessServiceError::NotFound(AccessTarget::User))?;
        organization_member(row).ok_or(AccessServiceError::UnreadableMember)
    }

    async fn project_member(&self, project_id: Uuid, user_id: Uuid) -> Result<ProjectMember> {
        let row = MembershipRepository::project_member(&self.pool, project_id, user_id)
            .await?
            .ok_or(AccessServiceError::NotFound(AccessTarget::User))?;
        project_member(row).ok_or(AccessServiceError::UnreadableMember)
    }
}

/// Admits super administrators only; `privileged` also requires a recent
/// password confirmation.
fn require_platform(principal: IdentityPrincipal, privileged: bool) -> Result<IdentityPrincipal> {
    if !principal.is_super_admin {
        return Err(AccessServiceError::SuperAdminRequired);
    }
    if privileged && !principal.has_recent_privilege() {
        return Err(AccessServiceError::PrivilegeConfirmationRequired);
    }
    Ok(principal)
}

/// Admits super administrators, and owners and admins of the organization
/// that is active in their session. Anyone else in another organization does
/// not see this one at all.
fn organization_admin(
    principal: IdentityPrincipal,
    organization_id: Uuid,
) -> Result<IdentityPrincipal> {
    if principal.is_super_admin {
        return Ok(principal);
    }
    if principal.active_organization_id != Some(organization_id) {
        return Err(AccessServiceError::NotFound(AccessTarget::Organization));
    }
    if !principal
        .organization_role
        .is_some_and(OrganizationRole::inherits_project_access)
    {
        return Err(AccessServiceError::Denied(
            Denial::OrganizationAdministration,
        ));
    }
    Ok(principal)
}

fn validate_named_resource(input: &NamedResource) -> Result<()> {
    if valid_slug(&input.slug) && valid_name(&input.name) {
        Ok(())
    } else {
        Err(AccessServiceError::Invalid("resource is invalid"))
    }
}

/// Refuses to create a second organization in single-organization mode.
///
/// Must run inside the transaction that creates the organization. The check
/// used to run on the pool before that transaction began, so two concurrent
/// requests could both find no organization and both insert one; nothing in
/// the schema limits the table to a single row. Holding the authority lock
/// across the check and the insert means a second request waits for the first
/// to commit and then sees its organization.
async fn ensure_organization_capacity(
    tx: &mut Transaction<'_, Postgres>,
    mode: OrganizationMode,
) -> Result<()> {
    if mode != OrganizationMode::Single {
        return Ok(());
    }
    MembershipRepository::lock_authority(&mut **tx).await?;
    let exists = OrganizationRepository::any_exists(&mut **tx).await?;
    if exists {
        return Err(AccessServiceError::Conflict(
            AccessConflict::OrganizationLimitReached,
        ));
    }
    Ok(())
}

fn platform_capabilities() -> serde_json::Value {
    serde_json::json!({
        "manage_platform": true,
        "manage_organization": true,
        "create_project": true,
        "manage_project_members": true,
        "create_application": true,
        "manage_credentials": true,
        "organization_roles_grantable": ["owner", "admin", "member"],
        "project_roles_grantable": ["admin", "member"],
    })
}

fn organization_member(row: OrganizationMemberRow) -> Option<OrganizationMember> {
    Some(OrganizationMember {
        user_id: row.0,
        email: row.1,
        display_name: row.2,
        role: row.3.parse().ok()?,
        enabled: row.4,
        email_verified: row.5,
        created_at: row.6,
        can_change_role: serde_json::json!(false),
        can_remove: serde_json::json!(false),
    })
}

fn project_member(row: (Uuid, String, String, String, DateTime<Utc>)) -> Option<ProjectMember> {
    Some(ProjectMember {
        user_id: row.0,
        email: row.1,
        display_name: row.2,
        role: row.3.parse().ok()?,
        access_source: EffectiveAccessSource::Project,
        created_at: row.4,
        can_change_role: serde_json::json!(false),
        can_remove: serde_json::json!(false),
    })
}

/// Drops the probe row fetched beyond the limit and returns the cursor of the
/// next page, if there is one.
fn trim_page<T>(
    items: &mut Vec<T>,
    limit: i64,
    id: impl FnOnce(&T) -> Uuid + Copy,
) -> Option<Uuid> {
    if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.pop();
        items.last().map(id)
    } else {
        None
    }
}

fn role_name(role: OrganizationRole) -> &'static str {
    match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    }
}

fn project_role_name(role: ProjectRole) -> &'static str {
    match role {
        ProjectRole::Admin => "admin",
        ProjectRole::Member => "member",
    }
}

fn role_promotes(current: OrganizationRole, next: OrganizationRole) -> bool {
    matches!(
        (current, next),
        (
            OrganizationRole::Member,
            OrganizationRole::Admin | OrganizationRole::Owner
        ) | (OrganizationRole::Admin, OrganizationRole::Owner)
    )
}

/// The database guards the last owner and the last super administrator with a
/// check constraint; its violation becomes the given conflict.
fn map_authority_result<T>(result: Result<T, sqlx::Error>, conflict: AccessConflict) -> Result<()> {
    result.map(|_| ()).map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|item| item.code().as_deref() == Some("23514"))
        {
            AccessServiceError::Conflict(conflict)
        } else {
            AccessServiceError::Database(error)
        }
    })
}

/// What an audited access mutation touched, besides its actor and action.
#[derive(Clone, Copy, Default)]
struct AuditSubject<'a> {
    organization_id: Option<Uuid>,
    project_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
    previous_role: Option<&'a str>,
    new_role: Option<&'a str>,
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor_user_id: Uuid,
    action: &str,
    subject: AuditSubject<'_>,
    request_id: &str,
) -> Result<()> {
    write_access_audit(
        tx,
        AccessAuditEvent {
            actor: AccessAuditActor::User(actor_user_id),
            action,
            organization_id: subject.organization_id,
            project_id: subject.project_id,
            target_user_id: subject.target_user_id,
            invitation_id: None,
            previous_role: subject.previous_role,
            new_role: subject.new_role,
            request_id: Some(request_id),
        },
    )
    .await?;
    if matches!(
        action,
        "platform_role.granted"
            | "platform_role.revoked"
            | "user.disabled"
            | "user.enabled"
            | "organization.created"
            | "organization.deleted"
            | "project.created"
            | "credential.issued"
            | "credential.revoked"
    ) {
        crate::metrics::record_platform_mutation();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::test_support::{Tenant, tenant, user};

    /// Two creations racing in single-organization mode must leave exactly one
    /// organization. The first has passed the capacity check and inserted but
    /// not committed when the second arrives, which is the window the check
    /// used to leave open: under read committed the second could not see the
    /// first's row, found the table empty, and inserted its own.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn single_mode_admits_one_organization_under_concurrency(pool: PgPool) {
        let mut first = pool.begin().await.unwrap();
        ensure_organization_capacity(&mut first, OrganizationMode::Single)
            .await
            .unwrap();
        OrganizationRepository::insert(
            &mut *first,
            Uuid::new_v4(),
            "first",
            "First",
            OrganizationStatus::Active,
        )
        .await
        .unwrap();

        let second_pool = pool.clone();
        let second = tokio::spawn(async move {
            let mut tx = second_pool.begin().await.unwrap();
            let admitted = ensure_organization_capacity(&mut tx, OrganizationMode::Single)
                .await
                .is_ok();
            if admitted {
                OrganizationRepository::insert(
                    &mut *tx,
                    Uuid::new_v4(),
                    "second",
                    "Second",
                    OrganizationStatus::Active,
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
            }
            admitted
        });
        // Let the second request reach its check while the first is open.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        first.commit().await.unwrap();

        assert!(
            !second.await.unwrap(),
            "the second creation must be refused once the first commits"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "single mode must never hold two organizations");
    }

    /// Multiple-organization mode has no limit and takes no lock.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn multiple_mode_is_not_limited(pool: PgPool) {
        for slug in ["one", "two"] {
            let mut tx = pool.begin().await.unwrap();
            ensure_organization_capacity(&mut tx, OrganizationMode::Multiple)
                .await
                .unwrap();
            OrganizationRepository::insert(
                &mut *tx,
                Uuid::new_v4(),
                slug,
                slug,
                OrganizationStatus::Active,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::*;

        fn principal(
            user_id: Uuid,
            organization_id: Option<Uuid>,
            role: Option<OrganizationRole>,
        ) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id,
                session_id: Uuid::new_v4(),
                active_organization_id: organization_id,
                organization_role: role,
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn super_admin(user_id: Uuid, privileged: bool) -> IdentityPrincipal {
            IdentityPrincipal {
                is_super_admin: true,
                privileged_until: privileged.then(|| Utc::now() + Duration::minutes(5)),
                ..principal(user_id, None, None)
            }
        }

        /// A user who is a member of the tenant's organization in `role`.
        async fn member(
            pool: &PgPool,
            tenant: &Tenant,
            role: OrganizationRole,
        ) -> IdentityPrincipal {
            let user_id = user(pool).await;
            MembershipRepository::insert_organization_role(
                pool,
                tenant.organization_id,
                user_id,
                role_name(role),
            )
            .await
            .unwrap();
            principal(user_id, Some(tenant.organization_id), Some(role))
        }

        fn organization(slug: &str) -> NewPlatformOrganization {
            NewPlatformOrganization {
                slug: slug.into(),
                name: "Northstar".into(),
                ownership: Ownership::SelfOwner,
            }
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn platform_authority_precedes_validation_and_capacity(pool: PgPool) {
            let service = AccessService::new(pool.clone(), &WebApiConfig::default());
            let actor = user(&pool).await;

            let created = service
                .create_platform_organization(principal(actor, None, None), organization("-"), "r")
                .await;
            assert!(matches!(
                created,
                Err(AccessServiceError::SuperAdminRequired)
            ));
            let created = service
                .create_platform_organization(super_admin(actor, false), organization("-"), "r")
                .await;
            assert!(matches!(
                created,
                Err(AccessServiceError::PrivilegeConfirmationRequired)
            ));
            let created = service
                .create_platform_organization(super_admin(actor, true), organization("-"), "r")
                .await;
            assert!(matches!(
                created,
                Err(AccessServiceError::Invalid("organization is invalid"))
            ));

            let provisioned = service
                .create_platform_organization(
                    super_admin(actor, true),
                    organization("northstar"),
                    "r",
                )
                .await
                .unwrap();
            assert_eq!(provisioned.organization.status, "active");
            assert!(provisioned.invitation.is_none());
            let role = MembershipRepository::organization_role_when_active(
                &pool,
                actor,
                provisioned.organization.id,
            )
            .await
            .unwrap();
            assert_eq!(role.as_deref(), Some("owner"));
            // The default deployment holds a single organization.
            let second = service
                .create_platform_organization(super_admin(actor, true), organization("other"), "r")
                .await;
            assert!(matches!(
                second,
                Err(AccessServiceError::Conflict(
                    AccessConflict::OrganizationLimitReached
                ))
            ));
            // An owned organization cannot be deleted.
            let deleted = service
                .delete_platform_organization(
                    super_admin(actor, true),
                    provisioned.organization.id,
                    "r",
                )
                .await;
            assert!(matches!(
                deleted,
                Err(AccessServiceError::Conflict(
                    AccessConflict::OrganizationNotDeletable
                ))
            ));
            let fetched = service
                .get_platform_organization(super_admin(actor, false), provisioned.organization.id)
                .await
                .unwrap();
            assert_eq!(fetched.slug, "northstar");
            let missing = service
                .get_platform_organization(super_admin(actor, false), Uuid::new_v4())
                .await;
            assert!(matches!(
                missing,
                Err(AccessServiceError::NotFound(AccessTarget::Organization))
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn platform_resources_are_created_with_full_authority(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = AccessService::new(pool.clone(), &WebApiConfig::default());
            let actor = super_admin(user(&pool).await, false);

            let invalid = service
                .create_platform_project(
                    actor,
                    tenant.organization_id,
                    NamedResource {
                        slug: "Bad Slug".into(),
                        name: "Payments".into(),
                    },
                    "r",
                )
                .await;
            assert!(matches!(
                invalid,
                Err(AccessServiceError::Invalid("resource is invalid"))
            ));
            let project = service
                .create_platform_project(
                    actor,
                    tenant.organization_id,
                    NamedResource {
                        slug: "payments".into(),
                        name: "Payments".into(),
                    },
                    "r",
                )
                .await
                .unwrap();
            assert_eq!(project.effective_project_role, Some(ProjectRole::Admin));
            assert_eq!(project.application_count, 0);
            let orphan = service
                .create_platform_application(
                    actor,
                    Uuid::new_v4(),
                    NamedResource {
                        slug: "api".into(),
                        name: "API".into(),
                    },
                    "r",
                )
                .await;
            assert!(matches!(
                orphan,
                Err(AccessServiceError::NotFound(AccessTarget::Project))
            ));
            let created = service
                .create_platform_application(
                    actor,
                    project.id,
                    NamedResource {
                        slug: "api".into(),
                        name: "API".into(),
                    },
                    "r",
                )
                .await
                .unwrap();
            assert_eq!(created.application.organization_id, tenant.organization_id);
            assert!(created.credential.shown_once);
            assert!(!created.credential.token.is_empty());

            let applications = service
                .list_platform_applications(actor, project.id, PageRequest::default())
                .await
                .unwrap();
            assert_eq!(applications.items.len(), 1);
            assert_eq!(
                applications.items[0].effective_access_source,
                Some(EffectiveAccessSource::Platform)
            );
            // Each creation left an audit record.
            let audit = service
                .list_platform_audit(actor, PageRequest::default())
                .await
                .unwrap();
            let actions = audit
                .items
                .iter()
                .map(|item| item.action.as_str())
                .collect::<Vec<_>>();
            assert!(actions.contains(&"project.created"));
            assert!(actions.contains(&"credential.issued"));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn organization_members_follow_the_role_rules(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = AccessService::new(pool.clone(), &WebApiConfig::default());
            let organization = tenant.organization_id;
            let owner = member(&pool, &tenant, OrganizationRole::Owner).await;
            let admin = member(&pool, &tenant, OrganizationRole::Admin).await;
            let plain = member(&pool, &tenant, OrganizationRole::Member).await;
            let page = PageRequest::default();

            let elsewhere = principal(admin.user_id, Some(Uuid::new_v4()), admin.organization_role);
            assert!(matches!(
                service
                    .list_organization_members(elsewhere, organization, page)
                    .await,
                Err(AccessServiceError::NotFound(AccessTarget::Organization))
            ));
            assert!(matches!(
                service
                    .list_organization_members(plain, organization, page)
                    .await,
                Err(AccessServiceError::Denied(
                    Denial::OrganizationAdministration
                ))
            ));
            let members = service
                .list_organization_members(admin, organization, page)
                .await
                .unwrap();
            assert_eq!(members.items.len(), 3);
            for item in &members.items {
                let manageable = item.role != OrganizationRole::Owner;
                assert_eq!(item.can_change_role, serde_json::json!(manageable));
            }
            let sole_owner = members
                .items
                .iter()
                .find(|item| item.user_id == owner.user_id)
                .unwrap();
            assert_eq!(sole_owner.can_remove, serde_json::json!(false));

            // An admin may not touch an owner, nor promote anyone to owner.
            assert!(matches!(
                service
                    .update_organization_member(
                        admin,
                        organization,
                        plain.user_id,
                        OrganizationRole::Owner,
                        "r",
                    )
                    .await,
                Err(AccessServiceError::Denied(Denial::RoleTransition))
            ));
            assert!(matches!(
                service
                    .remove_organization_member(admin, organization, owner.user_id, "r")
                    .await,
                Err(AccessServiceError::Denied(Denial::MembershipRemoval))
            ));
            assert!(matches!(
                service
                    .update_organization_member(
                        admin,
                        organization,
                        Uuid::new_v4(),
                        OrganizationRole::Member,
                        "r",
                    )
                    .await,
                Err(AccessServiceError::NotFound(AccessTarget::User))
            ));
            // A super administrator passes the role rules but not the self
            // promotion rule.
            let platform = IdentityPrincipal {
                is_super_admin: true,
                ..plain
            };
            assert!(matches!(
                service
                    .update_organization_member(
                        platform,
                        organization,
                        plain.user_id,
                        OrganizationRole::Admin,
                        "r",
                    )
                    .await,
                Err(AccessServiceError::SelfPromotion)
            ));
            // The last owner stays.
            assert!(matches!(
                service
                    .update_organization_member(
                        owner,
                        organization,
                        owner.user_id,
                        OrganizationRole::Admin,
                        "r",
                    )
                    .await,
                Err(AccessServiceError::Conflict(
                    AccessConflict::LastOrganizationOwnerRequired
                ))
            ));

            let promoted = service
                .update_organization_member(
                    admin,
                    organization,
                    plain.user_id,
                    OrganizationRole::Admin,
                    "r",
                )
                .await
                .unwrap();
            assert_eq!(promoted.role, OrganizationRole::Admin);
            service
                .remove_organization_member(owner, organization, plain.user_id, "r")
                .await
                .unwrap();

            // Only owners read the organization audit.
            assert!(matches!(
                service.list_audit(admin, organization, page).await,
                Err(AccessServiceError::Denied(Denial::OwnerRequired))
            ));
            let audit = service.list_audit(owner, organization, page).await.unwrap();
            let actions = audit
                .items
                .iter()
                .map(|item| item.action.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                actions,
                [
                    "organization_member.removed",
                    "organization_member.role_changed"
                ]
            );
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn project_members_are_managed_by_project_admins(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = AccessService::new(pool.clone(), &WebApiConfig::default());
            let project = tenant.project_id;
            let admin = member(&pool, &tenant, OrganizationRole::Admin).await;
            let candidate = member(&pool, &tenant, OrganizationRole::Member).await;
            let page = PageRequest::default();

            assert!(matches!(
                service
                    .list_project_members(admin, Uuid::new_v4(), page)
                    .await,
                Err(AccessServiceError::NotFound(AccessTarget::Project))
            ));
            let eligible = service
                .list_eligible_project_members(admin, project, page)
                .await
                .unwrap();
            assert!(
                eligible
                    .items
                    .iter()
                    .any(|item| item.user_id == candidate.user_id)
            );

            let added = service
                .add_project_member(admin, project, candidate.user_id, ProjectRole::Member, "r")
                .await
                .unwrap();
            assert_eq!(added.role, ProjectRole::Member);
            assert!(matches!(
                service
                    .add_project_member(admin, project, candidate.user_id, ProjectRole::Admin, "r")
                    .await,
                Err(AccessServiceError::Conflict(
                    AccessConflict::MembershipExists
                ))
            ));
            // A project member does not administer the project.
            assert!(matches!(
                service.list_project_members(candidate, project, page).await,
                Err(AccessServiceError::Denied(Denial::ProjectAdministration))
            ));
            let updated = service
                .update_project_member(admin, project, candidate.user_id, ProjectRole::Admin, "r")
                .await
                .unwrap();
            assert_eq!(updated.role, ProjectRole::Admin);
            let members = service
                .list_project_members(admin, project, page)
                .await
                .unwrap();
            assert_eq!(members.items.len(), 1);
            assert_eq!(members.items[0].can_remove, serde_json::json!(true));

            service
                .remove_project_member(admin, project, candidate.user_id, "r")
                .await
                .unwrap();
            // The member is looked up before the removal rule applies.
            assert!(matches!(
                service
                    .remove_project_member(admin, project, candidate.user_id, "r")
                    .await,
                Err(AccessServiceError::NotFound(AccessTarget::User))
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn sessions_switch_organization_and_confirm_privilege(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = AccessService::new(pool.clone(), &WebApiConfig::default());
            let admin = member(&pool, &tenant, OrganizationRole::Admin).await;

            assert!(matches!(
                service.select_organization(admin, Uuid::new_v4()).await,
                Err(AccessServiceError::NotFound(AccessTarget::Organization))
            ));
            let selected = service
                .select_organization(admin, tenant.organization_id)
                .await
                .unwrap();
            assert_eq!(selected.result.role, OrganizationRole::Admin);
            assert_eq!(
                selected.result.active_organization_id,
                tenant.organization_id
            );

            assert!(matches!(
                service.confirm_privilege(admin, "anything", "r").await,
                Err(AccessServiceError::SuperAdminRequired)
            ));
            // The fixture's password hash matches no password.
            assert!(matches!(
                service
                    .confirm_privilege(super_admin(admin.user_id, false), "anything", "r")
                    .await,
                Err(AccessServiceError::CurrentPasswordInvalid)
            ));
            assert!(matches!(
                service
                    .grant_super_admin(super_admin(admin.user_id, true), admin.user_id, "r")
                    .await,
                Err(AccessServiceError::SelfPromotion)
            ));
            let operator = super_admin(user(&pool).await, true);
            assert!(matches!(
                service
                    .set_user_status(operator, Uuid::new_v4(), true, "r")
                    .await,
                Err(AccessServiceError::NotFound(AccessTarget::User))
            ));
            let disabled = service
                .set_user_status(operator, admin.user_id, true, "r")
                .await
                .unwrap();
            assert!(!disabled.enabled);
            // Disabling ends the user's sessions.
            let sessions: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL",
            )
            .bind(admin.user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(sessions, 0);
        }
    }
}
