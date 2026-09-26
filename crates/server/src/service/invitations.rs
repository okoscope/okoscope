//! Invitations to an organization or a project: issuing, listing, resending
//! and revoking them, and accepting one as a new or an existing user.

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
use crate::access_control::{ProjectRole, can_manage_project_role};
use crate::auth::{
    IdentityPrincipal, OrganizationRole, SessionToken, hash_password, normalize_email,
    validate_password,
};
use crate::repository::invitations::InvitationRepository;
use crate::repository::{
    MembershipRepository, OrganizationRepository, ProjectRepository, UserRepository,
};
use crate::service::identity::{insert_session_with_context, valid_name};
use crate::service::project_access::{ProjectScope, project_scope};
use crate::transactional_mail::{Locale, MailConfig, MailError, TemplateData, enqueue_invitation};
use crate::web_api::{InvitationConfig, WebApiConfig};

const TOKEN_PREFIX: &str = "oko_invitation_v1_";
const TOKEN_BYTES: usize = 32;
const DEFAULT_PAGE_LIMIT: i64 = 50;
const MAX_PAGE_LIMIT: i64 = 100;

/// Why an invitation use case failed.
#[derive(Debug, Error)]
pub enum InvitationServiceError {
    /// A platform route was called by someone who is not a super
    /// administrator.
    #[error("super administrator role is required")]
    SuperAdminRequired,
    /// The named resource does not exist, or the principal may not see it.
    #[error("{0:?} not found")]
    NotFound(InvitationTarget),
    /// The principal sees the resource but may not do this to it.
    #[error("insufficient permission")]
    Forbidden,
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(&'static str),
    /// The page limit is outside 1..=100.
    #[error("limit must be between 1 and 100")]
    InvalidLimit,
    /// The invitation clashes with the current state.
    #[error("{0:?}")]
    Conflict(InvitationConflict),
    /// The inviter has issued or resent too many invitations in the last hour.
    #[error("invitation rate limit exceeded")]
    RateLimited,
    /// Mail delivery is not configured, so no invitation can reach anyone.
    #[error("invitation mail is unavailable")]
    MailUnavailable,
    /// Queueing the invitation mail failed.
    #[error("invitation mail intent failed")]
    MailIntent(MailError),
    /// The token names no live invitation.
    #[error("invitation is unavailable")]
    Unusable,
    /// The new user's password could not be hashed.
    #[error("invitation password hashing failed")]
    PasswordHashing,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// What a [`InvitationServiceError::NotFound`] could not find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationTarget {
    Organization,
    Project,
    /// The organization or project an invitation is being issued for.
    Scope,
    Invitation,
}

/// What a [`InvitationServiceError::Conflict`] clashes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationConflict {
    /// The recipient is already a member of the scope.
    MembershipExists,
    /// A live invitation for the same recipient and scope exists.
    InvitationExists,
    /// The invitation was already accepted, revoked or replaced.
    NotPending,
    /// The recipient already has an account and must sign in to accept.
    RequiresSignIn,
    /// The signed-in account is not the verified recipient.
    AccountMismatch,
    /// Creating the recipient's account collided with an existing identity.
    IdentityConflict,
}

type Result<T, E = InvitationServiceError> = std::result::Result<T, E>;

struct InvitationToken {
    plaintext: Zeroizing<String>,
    digest: [u8; 32],
}

impl InvitationToken {
    fn generate() -> Self {
        let mut bytes = [0_u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let plaintext = Zeroizing::new(format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
        let digest = Sha256::digest(plaintext.as_bytes()).into();
        Self { plaintext, digest }
    }
}

impl fmt::Debug for InvitationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationToken")
            .finish_non_exhaustive()
    }
}

fn invitation_digest(token: &str) -> Option<[u8; 32]> {
    let encoded = token.strip_prefix(TOKEN_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if bytes.len() != TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationScope {
    Organization,
    Project,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
    Replaced,
}

/// An invitation to create: who receives it, in which role, and the language
/// of its mail.
#[derive(Clone, Debug)]
pub struct NewInvitation {
    pub email: String,
    pub role: String,
    pub locale: Locale,
}

/// A new user accepting an invitation: the token from the mail plus the
/// account to create.
#[derive(Clone, Debug)]
pub struct NewUserAcceptance {
    pub token: String,
    pub password: String,
    pub display_name: String,
    pub locale: Locale,
}

/// Columns: `id`, `organization_id`, `organization_name`, `project_id`,
/// `project_name`, `recipient_email`, `role`, `inviter_display_name`,
/// `locale`, `created_at`, `expires_at`, `accepted_at`, `accepted_by_user_id`,
/// `revoked_at`, `replaced_at`.
#[derive(Debug, FromRow)]
struct InvitationRow {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    recipient_email: String,
    role: String,
    inviter_display_name: String,
    locale: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    accepted_by_user_id: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
    replaced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct InvitationView {
    id: Uuid,
    scope: InvitationScope,
    organization_id: Uuid,
    organization_name: String,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    recipient_email: String,
    role: String,
    inviter_display_name: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    status: InvitationStatus,
}

#[derive(Debug, Serialize)]
pub struct InvitationPage {
    items: Vec<InvitationView>,
    next_cursor: Option<Uuid>,
}

impl From<InvitationRow> for InvitationView {
    fn from(row: InvitationRow) -> Self {
        let status = status(&row);
        Self {
            id: row.id,
            scope: scope(&row),
            organization_id: row.organization_id,
            organization_name: row.organization_name,
            project_id: row.project_id,
            project_name: row.project_name,
            recipient_email: row.recipient_email,
            role: row.role,
            inviter_display_name: row.inviter_display_name,
            created_at: row.created_at,
            expires_at: row.expires_at,
            status,
        }
    }
}

fn scope(row: &InvitationRow) -> InvitationScope {
    if row.project_id.is_some() {
        InvitationScope::Project
    } else {
        InvitationScope::Organization
    }
}

fn status(row: &InvitationRow) -> InvitationStatus {
    if row.accepted_at.is_some() {
        InvitationStatus::Accepted
    } else if row.revoked_at.is_some() {
        InvitationStatus::Revoked
    } else if row.replaced_at.is_some() {
        InvitationStatus::Replaced
    } else if row.expires_at <= Utc::now() {
        InvitationStatus::Expired
    } else {
        InvitationStatus::Pending
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationAccountState {
    NewUser,
    ExistingUser,
}

/// What the invitation page shows before the recipient accepts.
#[derive(Debug, Serialize)]
pub struct InvitationInspection {
    scope: InvitationScope,
    organization_name: String,
    project_name: Option<String>,
    role: String,
    inviter_display_name: String,
    expires_at: DateTime<Utc>,
    account_state: InvitationAccountState,
}

#[derive(Debug, Serialize)]
pub struct InvitationAcceptance {
    status: &'static str,
    scope: InvitationScope,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    role: String,
    user_id: Uuid,
}

fn accepted(row: &InvitationRow, user_id: Uuid) -> InvitationAcceptance {
    InvitationAcceptance {
        status: "accepted",
        scope: scope(row),
        organization_id: row.organization_id,
        project_id: row.project_id,
        role: row.role.clone(),
        user_id,
    }
}

/// A new user's acceptance: what they joined, and the session opened for
/// them.
#[derive(Debug)]
pub struct AcceptedNewUser {
    pub acceptance: InvitationAcceptance,
    pub session: SessionToken,
}

struct ProjectActor {
    principal: IdentityPrincipal,
    organization_id: Uuid,
    project_role: ProjectRole,
}

#[derive(Clone, Copy)]
struct IssueScope {
    organization_id: Uuid,
    project_id: Option<Uuid>,
}

struct IssueRequest {
    scope: IssueScope,
    recipient_email: String,
    role: String,
    locale: Locale,
    inviter_user_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct InvitationService {
    pool: PgPool,
    invitations: InvitationConfig,
    mail: MailConfig,
    session_lifetime: std::time::Duration,
}

impl InvitationService {
    pub fn new(pool: PgPool, config: &WebApiConfig) -> Self {
        Self {
            pool,
            invitations: config.invitations,
            mail: config.mail.clone(),
            session_lifetime: config.session_lifetime,
        }
    }

    /// Refuses when mail delivery is not configured. Issuing and resending
    /// report this before anything else, even before authentication, so the
    /// transport calls it first on those routes.
    pub fn require_mail(&self) -> Result<()> {
        if self.mail.enabled {
            Ok(())
        } else {
            Err(InvitationServiceError::MailUnavailable)
        }
    }

    /// Every invitation on the platform, newest first.
    pub async fn list_platform(
        &self,
        principal: IdentityPrincipal,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitationPage> {
        require_super_admin(principal)?;
        let limit = page_limit(limit)?;
        let rows = InvitationRepository::page(&self.pool, cursor, limit + 1).await?;
        Ok(page(rows, limit))
    }

    /// [`Self::list_organization`] on the platform route.
    pub async fn list_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitationPage> {
        require_super_admin(principal)?;
        self.list_organization(principal, organization_id, cursor, limit)
            .await
    }

    /// [`Self::list_project`] on the platform route.
    pub async fn list_platform_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitationPage> {
        require_super_admin(principal)?;
        self.list_project(principal, project_id, cursor, limit)
            .await
    }

    /// The invitations of an organization, for its owners and admins.
    pub async fn list_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitationPage> {
        organization_actor(principal, organization_id)?;
        let limit = page_limit(limit)?;
        let rows =
            InvitationRepository::organization_page(&self.pool, organization_id, cursor, limit + 1)
                .await?;
        Ok(page(rows, limit))
    }

    /// The invitations of a project, for those who manage its members.
    pub async fn list_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitationPage> {
        self.project_actor(principal, project_id).await?;
        let limit = page_limit(limit)?;
        let rows =
            InvitationRepository::project_page(&self.pool, project_id, cursor, limit + 1).await?;
        Ok(page(rows, limit))
    }

    /// Invites someone into an organization. Only an owner or a super
    /// administrator may invite an owner.
    pub async fn create_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        input: NewInvitation,
        request_id: &str,
    ) -> Result<InvitationView> {
        self.require_mail()?;
        let inviter = organization_actor(principal, organization_id)?;
        let role = OrganizationRole::from_str(&input.role)
            .map_err(|()| invalid("role must be owner, admin, or member"))?;
        if role == OrganizationRole::Owner
            && !inviter.is_super_admin
            && inviter.organization_role != Some(OrganizationRole::Owner)
        {
            return Err(InvitationServiceError::Forbidden);
        }
        self.issue(
            IssueRequest {
                scope: IssueScope {
                    organization_id,
                    project_id: None,
                },
                recipient_email: normalize_email(&input.email)
                    .map_err(|_| invalid("email is invalid"))?,
                role: input.role,
                locale: input.locale,
                inviter_user_id: inviter.user_id,
            },
            request_id,
        )
        .await
    }

    /// Invites someone into a project, in a role the inviter may grant.
    pub async fn create_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        input: NewInvitation,
        request_id: &str,
    ) -> Result<InvitationView> {
        self.require_mail()?;
        let actor = self.project_actor(principal, project_id).await?;
        let role = ProjectRole::from_str(&input.role)
            .map_err(|()| invalid("role must be admin or member"))?;
        if !can_manage_project_role(
            actor.principal.is_super_admin,
            actor.principal.organization_role,
            Some(actor.project_role),
            Some(role),
        ) {
            return Err(InvitationServiceError::Forbidden);
        }
        self.issue(
            IssueRequest {
                scope: IssueScope {
                    organization_id: actor.organization_id,
                    project_id: Some(project_id),
                },
                recipient_email: normalize_email(&input.email)
                    .map_err(|_| invalid("email is invalid"))?,
                role: input.role,
                locale: input.locale,
                inviter_user_id: actor.principal.user_id,
            },
            request_id,
        )
        .await
    }

    /// [`Self::create_organization`] on the platform route.
    pub async fn create_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        input: NewInvitation,
        request_id: &str,
    ) -> Result<InvitationView> {
        require_super_admin(principal)?;
        self.create_organization(principal, organization_id, input, request_id)
            .await
    }

    /// [`Self::create_project`] on the platform route.
    pub async fn create_platform_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        input: NewInvitation,
        request_id: &str,
    ) -> Result<InvitationView> {
        require_super_admin(principal)?;
        self.create_project(principal, project_id, input, request_id)
            .await
    }

    /// Replaces a pending organization invitation with a fresh one and mails
    /// it again.
    pub async fn resend_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<InvitationView> {
        self.require_mail()?;
        let (principal, row) = self
            .authorize_organization_invitation(principal, organization_id, invitation_id)
            .await?;
        self.resend(principal, row, request_id).await
    }

    /// Replaces a pending project invitation with a fresh one and mails it
    /// again.
    pub async fn resend_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<InvitationView> {
        self.require_mail()?;
        let (actor, row) = self
            .authorize_project_invitation(principal, project_id, invitation_id)
            .await?;
        self.resend(actor.principal, row, request_id).await
    }

    /// [`Self::resend_organization`] on the platform route.
    pub async fn resend_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<InvitationView> {
        require_super_admin(principal)?;
        self.resend_organization(principal, organization_id, invitation_id, request_id)
            .await
    }

    /// [`Self::resend_project`] on the platform route.
    pub async fn resend_platform_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<InvitationView> {
        require_super_admin(principal)?;
        self.resend_project(principal, project_id, invitation_id, request_id)
            .await
    }

    /// Revokes an organization invitation. Revoking one that is already
    /// revoked succeeds without a second audit record.
    pub async fn revoke_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let (principal, row) = self
            .authorize_organization_invitation(principal, organization_id, invitation_id)
            .await?;
        self.revoke(principal.user_id, row, request_id).await
    }

    /// Revokes a project invitation, like [`Self::revoke_organization`].
    pub async fn revoke_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        let (actor, row) = self
            .authorize_project_invitation(principal, project_id, invitation_id)
            .await?;
        self.revoke(actor.principal.user_id, row, request_id).await
    }

    /// [`Self::revoke_organization`] on the platform route.
    pub async fn revoke_platform_organization(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        require_super_admin(principal)?;
        self.revoke_organization(principal, organization_id, invitation_id, request_id)
            .await
    }

    /// [`Self::revoke_project`] on the platform route.
    pub async fn revoke_platform_project(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        invitation_id: Uuid,
        request_id: &str,
    ) -> Result<()> {
        require_super_admin(principal)?;
        self.revoke_project(principal, project_id, invitation_id, request_id)
            .await
    }

    /// Describes a live invitation to whoever holds its token, and whether its
    /// recipient already has an account.
    pub async fn inspect(&self, token: &str) -> Result<InvitationInspection> {
        let digest = invitation_digest(token).ok_or(InvitationServiceError::Unusable)?;
        let row: InvitationRow = InvitationRepository::by_token_digest(&self.pool, digest.to_vec())
            .await?
            .filter(is_live)
            .ok_or(InvitationServiceError::Unusable)?;
        let user_exists: bool =
            UserRepository::exists_by_email(&self.pool, &row.recipient_email).await?;
        Ok(InvitationInspection {
            scope: scope(&row),
            organization_name: row.organization_name,
            project_name: row.project_name,
            role: row.role,
            inviter_display_name: row.inviter_display_name,
            expires_at: row.expires_at,
            account_state: if user_exists {
                InvitationAccountState::ExistingUser
            } else {
                InvitationAccountState::NewUser
            },
        })
    }

    /// Creates the recipient's account, grants the invited role, consumes the
    /// invitation and opens a session in its organization, all at once.
    pub async fn accept_new_user(
        &self,
        input: NewUserAcceptance,
        request_id: &str,
    ) -> Result<AcceptedNewUser> {
        validate_password(&input.password).map_err(|_| invalid("password is invalid"))?;
        if !valid_name(&input.display_name) {
            return Err(invalid("display name is invalid"));
        }
        let digest = invitation_digest(&input.token).ok_or(InvitationServiceError::Unusable)?;
        let password_hash = hash_password(&input.password)
            .map_err(|_error| InvitationServiceError::PasswordHashing)?;
        let mut tx = self.pool.begin().await?;
        let row = load_invitation_by_digest(&mut tx, digest)
            .await?
            .filter(is_live)
            .ok_or(InvitationServiceError::Unusable)?;
        let user_exists: bool =
            UserRepository::exists_by_email(&mut *tx, &row.recipient_email).await?;
        if user_exists {
            return Err(InvitationServiceError::Conflict(
                InvitationConflict::RequiresSignIn,
            ));
        }
        let user_id = Uuid::new_v4();
        UserRepository::insert_verified(
            &mut *tx,
            user_id,
            &row.recipient_email,
            &password_hash,
            input.locale.as_str(),
            &input.display_name,
        )
        .await
        .map_err(|error| map_unique(error, InvitationConflict::IdentityConflict))?;
        grant_and_consume(&mut tx, &row, user_id, request_id).await?;
        let (_, session) = insert_session_with_context(
            &mut tx,
            user_id,
            Some(row.organization_id),
            None,
            self.session_lifetime,
        )
        .await?;
        tx.commit().await?;
        Ok(AcceptedNewUser {
            acceptance: accepted(&row, user_id),
            session,
        })
    }

    /// Accepts an invitation for the signed-in user, who must be its verified
    /// recipient. Accepting one the same user already accepted succeeds again.
    pub async fn accept_existing_user(
        &self,
        principal: IdentityPrincipal,
        token: &str,
        request_id: &str,
    ) -> Result<InvitationAcceptance> {
        let digest = invitation_digest(token).ok_or(InvitationServiceError::Unusable)?;
        let mut tx = self.pool.begin().await?;
        let row = load_invitation_by_digest(&mut tx, digest)
            .await?
            .ok_or(InvitationServiceError::Unusable)?;
        if row.accepted_by_user_id == Some(principal.user_id) {
            tx.commit().await?;
            return Ok(accepted(&row, principal.user_id));
        }
        if !is_live(&row) {
            return Err(InvitationServiceError::Unusable);
        }
        let identity: Option<(String, Option<DateTime<Utc>>)> =
            UserRepository::active_email_for_update(&mut *tx, principal.user_id).await?;
        let matches = identity
            .is_some_and(|(email, verified)| verified.is_some() && email == row.recipient_email);
        if !matches {
            return Err(InvitationServiceError::Conflict(
                InvitationConflict::AccountMismatch,
            ));
        }
        grant_and_consume(&mut tx, &row, principal.user_id, request_id).await?;
        tx.commit().await?;
        Ok(accepted(&row, principal.user_id))
    }

    async fn project_actor(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectActor> {
        let ProjectScope {
            organization_id,
            access,
        } = project_scope(&self.pool, principal, project_id)
            .await?
            .ok_or(InvitationServiceError::NotFound(InvitationTarget::Project))?;
        if !access.can_manage_members() {
            return Err(InvitationServiceError::Forbidden);
        }
        Ok(ProjectActor {
            principal,
            organization_id,
            project_role: access.role,
        })
    }

    async fn issue(&self, request: IssueRequest, request_id: &str) -> Result<InvitationView> {
        let mut tx = self.pool.begin().await?;
        let invitation =
            issue_in_transaction(&mut tx, &self.invitations, &self.mail, request, request_id)
                .await?;
        tx.commit().await?;
        Ok(invitation)
    }

    async fn authorize_organization_invitation(
        &self,
        principal: IdentityPrincipal,
        organization_id: Uuid,
        invitation_id: Uuid,
    ) -> Result<(IdentityPrincipal, InvitationRow)> {
        let principal = organization_actor(principal, organization_id)?;
        let row = InvitationRepository::get::<_, InvitationRow>(&self.pool, invitation_id)
            .await?
            .filter(|row| row.organization_id == organization_id && row.project_id.is_none())
            .ok_or(InvitationServiceError::NotFound(
                InvitationTarget::Invitation,
            ))?;
        if row.role == "owner"
            && !principal.is_super_admin
            && principal.organization_role != Some(OrganizationRole::Owner)
        {
            return Err(InvitationServiceError::Forbidden);
        }
        Ok((principal, row))
    }

    async fn authorize_project_invitation(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        invitation_id: Uuid,
    ) -> Result<(ProjectActor, InvitationRow)> {
        let actor = self.project_actor(principal, project_id).await?;
        let row = InvitationRepository::get::<_, InvitationRow>(&self.pool, invitation_id)
            .await?
            .filter(|row| row.project_id == Some(project_id))
            .ok_or(InvitationServiceError::NotFound(
                InvitationTarget::Invitation,
            ))?;
        let role = ProjectRole::from_str(&row.role)
            .map_err(|()| InvitationServiceError::Database(sqlx::Error::RowNotFound))?;
        if !can_manage_project_role(
            actor.principal.is_super_admin,
            actor.principal.organization_role,
            Some(actor.project_role),
            Some(role),
        ) {
            return Err(InvitationServiceError::Forbidden);
        }
        Ok((actor, row))
    }

    async fn resend(
        &self,
        principal: IdentityPrincipal,
        row: InvitationRow,
        request_id: &str,
    ) -> Result<InvitationView> {
        let mut tx = self.pool.begin().await?;
        let locked = InvitationRepository::get_for_update::<_, InvitationRow>(&mut *tx, row.id)
            .await?
            .ok_or(InvitationServiceError::NotFound(
                InvitationTarget::Invitation,
            ))?;
        if locked.accepted_at.is_some()
            || locked.revoked_at.is_some()
            || locked.replaced_at.is_some()
        {
            return Err(InvitationServiceError::Conflict(
                InvitationConflict::NotPending,
            ));
        }
        self.enforce_resend_rate(&mut tx, principal.user_id).await?;
        let replacement_id = Uuid::new_v4();
        InvitationRepository::revoke(&mut *tx, locked.id).await?;
        let request = IssueRequest {
            scope: IssueScope {
                organization_id: locked.organization_id,
                project_id: locked.project_id,
            },
            recipient_email: locked.recipient_email,
            role: locked.role,
            locale: locked.locale.parse().unwrap_or(Locale::En),
            inviter_user_id: principal.user_id,
        };
        let token = InvitationToken::generate();
        let expires_at = Utc::now()
            + Duration::from_std(self.invitations.lifetime)
                .map_err(|_| invalid("invitation lifetime is invalid"))?;
        insert_invitation(&mut tx, replacement_id, &request, &token, expires_at).await?;
        InvitationRepository::mark_replaced(&mut *tx, locked.id, replacement_id).await?;
        enqueue_issue_mail(
            &mut tx,
            &self.mail,
            &request,
            replacement_id,
            &token,
            expires_at,
        )
        .await?;
        audit(
            &mut tx,
            principal.user_id,
            "invitation.resent",
            request.scope,
            replacement_id,
            Some(&request.role),
            request_id,
        )
        .await?;
        let replacement = InvitationRepository::get::<_, InvitationRow>(&mut *tx, replacement_id)
            .await?
            .ok_or(InvitationServiceError::Database(sqlx::Error::RowNotFound))?;
        tx.commit().await?;
        Ok(replacement.into())
    }

    async fn enforce_resend_rate(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        actor_user_id: Uuid,
    ) -> Result<()> {
        let count: i64 = InvitationRepository::resent_last_hour(&mut **tx, actor_user_id).await?;
        if count >= i64::from(self.invitations.resend_limit_per_hour) {
            return Err(InvitationServiceError::RateLimited);
        }
        Ok(())
    }

    async fn revoke(
        &self,
        actor_user_id: Uuid,
        row: InvitationRow,
        request_id: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let locked = InvitationRepository::get_for_update::<_, InvitationRow>(&mut *tx, row.id)
            .await?
            .ok_or(InvitationServiceError::NotFound(
                InvitationTarget::Invitation,
            ))?;
        if locked.accepted_at.is_some() || locked.replaced_at.is_some() {
            return Err(InvitationServiceError::Conflict(
                InvitationConflict::NotPending,
            ));
        }
        if locked.revoked_at.is_none() {
            InvitationRepository::revoke(&mut *tx, locked.id).await?;
            audit(
                &mut tx,
                actor_user_id,
                "invitation.revoked",
                IssueScope {
                    organization_id: locked.organization_id,
                    project_id: locked.project_id,
                },
                locked.id,
                None,
                request_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Invites the first owner of an organization a super administrator is
/// creating, inside the transaction that creates it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_organization_invitation(
    tx: &mut Transaction<'_, Postgres>,
    config: &WebApiConfig,
    actor_user_id: Uuid,
    organization_id: Uuid,
    email: &str,
    role: OrganizationRole,
    locale: Locale,
    request_id: &str,
) -> Result<InvitationView> {
    if !config.mail.enabled {
        return Err(InvitationServiceError::MailUnavailable);
    }
    let email = normalize_email(email).map_err(|_| invalid("email is invalid"))?;
    let role = match role {
        OrganizationRole::Owner => "owner",
        OrganizationRole::Admin => "admin",
        OrganizationRole::Member => "member",
    };
    issue_in_transaction(
        tx,
        &config.invitations,
        &config.mail,
        IssueRequest {
            scope: IssueScope {
                organization_id,
                project_id: None,
            },
            recipient_email: email,
            role: role.to_owned(),
            locale,
            inviter_user_id: actor_user_id,
        },
        request_id,
    )
    .await
}

/// The pending invitation of an organization's first owner, if any.
pub(crate) async fn current_organization_owner_invitation(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<InvitationView>, sqlx::Error> {
    let row: Option<InvitationRow> =
        InvitationRepository::pending_owner_invitation(pool, organization_id).await?;
    Ok(row.map(InvitationView::from))
}

fn require_super_admin(principal: IdentityPrincipal) -> Result<()> {
    if principal.is_super_admin {
        Ok(())
    } else {
        Err(InvitationServiceError::SuperAdminRequired)
    }
}

fn organization_actor(
    principal: IdentityPrincipal,
    organization_id: Uuid,
) -> Result<IdentityPrincipal> {
    if principal.is_super_admin {
        return Ok(principal);
    }
    if principal.active_organization_id != Some(organization_id) {
        return Err(InvitationServiceError::NotFound(
            InvitationTarget::Organization,
        ));
    }
    if matches!(
        principal.organization_role,
        Some(OrganizationRole::Owner | OrganizationRole::Admin)
    ) {
        Ok(principal)
    } else {
        Err(InvitationServiceError::Forbidden)
    }
}

fn invalid(message: &'static str) -> InvitationServiceError {
    InvitationServiceError::Invalid(message)
}

fn page_limit(limit: Option<i64>) -> Result<i64> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if (1..=MAX_PAGE_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(InvitationServiceError::InvalidLimit)
    }
}

async fn load_invitation_by_digest(
    tx: &mut Transaction<'_, Postgres>,
    digest: [u8; 32],
) -> Result<Option<InvitationRow>, sqlx::Error> {
    InvitationRepository::by_token_digest_for_update(&mut **tx, digest.to_vec()).await
}

fn is_live(row: &InvitationRow) -> bool {
    row.accepted_at.is_none()
        && row.revoked_at.is_none()
        && row.replaced_at.is_none()
        && row.expires_at > Utc::now()
}

fn page(mut rows: Vec<InvitationRow>, limit: i64) -> InvitationPage {
    let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        rows.pop();
    }
    let next_cursor = has_more.then(|| rows.last().map(|row| row.id)).flatten();
    InvitationPage {
        items: rows.into_iter().map(InvitationView::from).collect(),
        next_cursor,
    }
}

async fn issue_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    invitation_config: &InvitationConfig,
    mail_config: &MailConfig,
    request: IssueRequest,
    request_id: &str,
) -> Result<InvitationView> {
    validate_issue_target(tx, &request).await?;
    enforce_create_rate(tx, invitation_config, request.inviter_user_id).await?;
    let id = Uuid::new_v4();
    let expired_equivalent = reserve_expired_equivalent(tx, &request).await?;
    let token = InvitationToken::generate();
    let lifetime = Duration::from_std(invitation_config.lifetime)
        .map_err(|_| invalid("invitation lifetime is invalid"))?;
    let expires_at = Utc::now() + lifetime;
    insert_invitation(tx, id, &request, &token, expires_at).await?;
    if let Some(expired_id) = expired_equivalent {
        InvitationRepository::mark_replaced(&mut **tx, expired_id, id).await?;
    }
    enqueue_issue_mail(tx, mail_config, &request, id, &token, expires_at).await?;
    audit(
        tx,
        request.inviter_user_id,
        "invitation.created",
        request.scope,
        id,
        Some(&request.role),
        request_id,
    )
    .await?;
    let invitation = InvitationRepository::get::<_, InvitationRow>(&mut **tx, id)
        .await?
        .ok_or(InvitationServiceError::Database(sqlx::Error::RowNotFound))?;
    Ok(invitation.into())
}

async fn validate_issue_target(
    tx: &mut Transaction<'_, Postgres>,
    request: &IssueRequest,
) -> Result<()> {
    let target_exists: bool = if let Some(project_id) = request.scope.project_id {
        ProjectRepository::exists_in(&mut **tx, request.scope.organization_id, project_id).await
    } else {
        OrganizationRepository::exists(&mut **tx, request.scope.organization_id).await
    }?;
    if !target_exists {
        return Err(InvitationServiceError::NotFound(InvitationTarget::Scope));
    }
    let membership_exists: bool = if let Some(project_id) = request.scope.project_id {
        InvitationRepository::recipient_is_project_member(
            &mut **tx,
            &request.recipient_email,
            project_id,
        )
        .await
    } else {
        InvitationRepository::recipient_is_organization_member(
            &mut **tx,
            &request.recipient_email,
            request.scope.organization_id,
        )
        .await
    }?;
    if membership_exists {
        return Err(InvitationServiceError::Conflict(
            InvitationConflict::MembershipExists,
        ));
    }
    Ok(())
}

async fn enforce_create_rate(
    tx: &mut Transaction<'_, Postgres>,
    config: &InvitationConfig,
    inviter_user_id: Uuid,
) -> Result<()> {
    let count: i64 = InvitationRepository::created_last_hour(&mut **tx, inviter_user_id).await?;
    if count >= i64::from(config.create_limit_per_hour) {
        Err(InvitationServiceError::RateLimited)
    } else {
        Ok(())
    }
}

/// Finds the unresolved invitation for the same recipient and scope. A live
/// one is a conflict; an expired one is revoked now and replaced by the new
/// invitation once that exists.
async fn reserve_expired_equivalent(
    tx: &mut Transaction<'_, Postgres>,
    request: &IssueRequest,
) -> Result<Option<Uuid>> {
    let existing: Option<(Uuid, DateTime<Utc>)> =
        InvitationRepository::unresolved_equivalent_for_update(
            &mut **tx,
            request.scope.organization_id,
            request.scope.project_id,
            &request.recipient_email,
        )
        .await?;
    if let Some((id, expires_at)) = existing {
        if expires_at > Utc::now() {
            return Err(InvitationServiceError::Conflict(
                InvitationConflict::InvitationExists,
            ));
        }
        InvitationRepository::revoke(&mut **tx, id).await?;
        return Ok(Some(id));
    }
    Ok(None)
}

async fn insert_invitation(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    request: &IssueRequest,
    token: &InvitationToken,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    InvitationRepository::insert(
        &mut **tx,
        id,
        request.scope.organization_id,
        request.scope.project_id,
        &request.recipient_email,
        &request.role,
        request.inviter_user_id,
        request.locale.as_str(),
        token.digest.to_vec(),
        expires_at,
    )
    .await
    .map_err(|error| map_unique(error, InvitationConflict::InvitationExists))?;
    Ok(())
}

async fn enqueue_issue_mail(
    tx: &mut Transaction<'_, Postgres>,
    mail: &MailConfig,
    request: &IssueRequest,
    invitation_id: Uuid,
    token: &InvitationToken,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    let context: (String, Option<String>, String) = InvitationRepository::mail_context(
        &mut **tx,
        request.scope.organization_id,
        request.scope.project_id,
        request.inviter_user_id,
    )
    .await?;
    let action_url = format!(
        "{}/invite#token={}",
        mail.public_web_url.as_str().trim_end_matches('/'),
        token.plaintext.as_str()
    );
    let expires_minutes = (expires_at - Utc::now()).num_minutes().max(1);
    let data = if let Some(project_name) = context.1 {
        TemplateData::ProjectInvitation {
            action_url,
            organization_name: context.0,
            project_name,
            inviter_display_name: context.2,
            role: request.role.clone(),
            expires_minutes,
        }
    } else {
        TemplateData::OrganizationInvitation {
            action_url,
            organization_name: context.0,
            inviter_display_name: context.2,
            role: request.role.clone(),
            expires_minutes,
        }
    };
    enqueue_invitation(
        tx,
        mail,
        &format!("invitation:{invitation_id}"),
        (request.recipient_email.clone(), request.locale),
        &data,
        invitation_id,
        expires_at,
    )
    .await
    .map_err(InvitationServiceError::MailIntent)
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor_user_id: Uuid,
    action: &str,
    scope: IssueScope,
    invitation_id: Uuid,
    new_role: Option<&str>,
    request_id: &str,
) -> Result<()> {
    write_access_audit(
        tx,
        AccessAuditEvent {
            actor: AccessAuditActor::User(actor_user_id),
            action,
            organization_id: Some(scope.organization_id),
            project_id: scope.project_id,
            target_user_id: None,
            invitation_id: Some(invitation_id),
            previous_role: None,
            new_role,
            request_id: Some(request_id),
        },
    )
    .await?;
    crate::metrics::record_invitation_lifecycle(true);
    Ok(())
}

async fn grant_and_consume(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &InvitationRow,
    user_id: Uuid,
    request_id: &str,
) -> Result<()> {
    let consumed = InvitationRepository::consume(&mut **tx, invitation.id, user_id).await?;
    if consumed.rows_affected() != 1 {
        return Err(InvitationServiceError::Unusable);
    }
    if let Some(project_id) = invitation.project_id {
        MembershipRepository::grant_organization_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            user_id,
            "member",
        )
        .await?;
        MembershipRepository::grant_project_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            project_id,
            user_id,
            &invitation.role,
        )
        .await?;
    } else {
        MembershipRepository::grant_organization_role_if_absent(
            &mut **tx,
            invitation.organization_id,
            user_id,
            &invitation.role,
        )
        .await?;
    }
    if invitation.project_id.is_none() && invitation.role == "owner" {
        OrganizationRepository::activate_when_owned(&mut **tx, invitation.organization_id).await?;
    }
    audit(
        tx,
        user_id,
        "invitation.accepted",
        IssueScope {
            organization_id: invitation.organization_id,
            project_id: invitation.project_id,
        },
        invitation.id,
        Some(&invitation.role),
        request_id,
    )
    .await
}

/// A unique violation becomes the given conflict; anything else stays a
/// database error.
fn map_unique(error: sqlx::Error, conflict: InvitationConflict) -> InvitationServiceError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
    {
        InvitationServiceError::Conflict(conflict)
    } else {
        InvitationServiceError::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_tokens_are_canonical_high_entropy_and_redacted() {
        let token = InvitationToken::generate();
        assert_eq!(
            invitation_digest(token.plaintext.as_str()),
            Some(token.digest)
        );
        assert!(token.plaintext.starts_with(TOKEN_PREFIX));
        assert!(!format!("{token:?}").contains(token.plaintext.as_str()));
        assert!(invitation_digest("invalid").is_none());
        assert!(invitation_digest("oko_invitation_v1_short").is_none());
    }

    #[test]
    fn status_precedence_is_closed_and_safe() {
        let now = Utc::now();
        let mut row = sample_row(now + Duration::days(7));
        assert_eq!(status(&row), InvitationStatus::Pending);
        row.expires_at = now - Duration::seconds(1);
        assert_eq!(status(&row), InvitationStatus::Expired);
        row.replaced_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Replaced);
        row.replaced_at = None;
        row.revoked_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Revoked);
        row.revoked_at = None;
        row.accepted_at = Some(now);
        assert_eq!(status(&row), InvitationStatus::Accepted);
    }

    fn sample_row(expires_at: DateTime<Utc>) -> InvitationRow {
        InvitationRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            organization_name: "Northstar".into(),
            project_id: None,
            project_name: None,
            recipient_email: "user@example.com".into(),
            role: "member".into(),
            inviter_display_name: "Alice".into(),
            locale: "en".into(),
            created_at: Utc::now(),
            expires_at,
            accepted_at: None,
            accepted_by_user_id: None,
            revoked_at: None,
            replaced_at: None,
        }
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::repository::test_support::{Tenant, tenant, user};
        use crate::web_api::OrganizationMode;

        fn config(mail: bool) -> WebApiConfig {
            WebApiConfig::default()
                .with_access_policy(
                    OrganizationMode::Multiple,
                    InvitationConfig {
                        lifetime: std::time::Duration::from_secs(7 * 86_400),
                        create_limit_per_hour: 20,
                        resend_limit_per_hour: 5,
                    },
                )
                .with_mail(MailConfig {
                    enabled: mail,
                    public_web_url: url::Url::parse("https://ui.example.com").unwrap(),
                    encryption_key: [11; 32],
                    ..MailConfig::default()
                })
        }

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

        /// A user who is a member of the tenant's organization in `role`.
        async fn member(
            pool: &PgPool,
            tenant: &Tenant,
            role: OrganizationRole,
        ) -> IdentityPrincipal {
            let user_id = user(pool).await;
            let name = match role {
                OrganizationRole::Owner => "owner",
                OrganizationRole::Admin => "admin",
                OrganizationRole::Member => "member",
            };
            MembershipRepository::insert_organization_role(
                pool,
                tenant.organization_id,
                user_id,
                name,
            )
            .await
            .unwrap();
            principal(user_id, Some(tenant.organization_id), Some(role))
        }

        fn invitation(email: &str, role: &str) -> NewInvitation {
            NewInvitation {
                email: email.into(),
                role: role.into(),
                locale: Locale::En,
            }
        }

        /// Stores a pending organization invitation and returns its id and
        /// the plaintext token the recipient would get by mail.
        async fn pending(
            pool: &PgPool,
            tenant: &Tenant,
            inviter: Uuid,
            email: &str,
        ) -> (Uuid, String) {
            let id = Uuid::new_v4();
            let token = InvitationToken::generate();
            InvitationRepository::insert(
                pool,
                id,
                tenant.organization_id,
                None,
                email,
                "member",
                inviter,
                "en",
                token.digest.to_vec(),
                Utc::now() + Duration::days(1),
            )
            .await
            .unwrap();
            (id, token.plaintext.to_string())
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn unavailable_mail_is_reported_before_authority(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = InvitationService::new(pool.clone(), &config(false));
            let stranger = principal(Uuid::new_v4(), Some(Uuid::new_v4()), None);

            assert!(matches!(
                service.require_mail(),
                Err(InvitationServiceError::MailUnavailable)
            ));
            let created = service
                .create_organization(
                    stranger,
                    tenant.organization_id,
                    invitation("x@example.test", "member"),
                    "request",
                )
                .await;
            assert!(matches!(
                created,
                Err(InvitationServiceError::MailUnavailable)
            ));
            let resent = service
                .resend_project(stranger, tenant.project_id, Uuid::new_v4(), "request")
                .await;
            assert!(matches!(
                resent,
                Err(InvitationServiceError::MailUnavailable)
            ));
            // The platform routes check the role first.
            let platform = service
                .create_platform_organization(
                    stranger,
                    tenant.organization_id,
                    invitation("x@example.test", "member"),
                    "request",
                )
                .await;
            assert!(matches!(
                platform,
                Err(InvitationServiceError::SuperAdminRequired)
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn organization_listing_checks_scope_then_role_then_limit(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = InvitationService::new(pool.clone(), &config(true));
            let organization = tenant.organization_id;

            let elsewhere = principal(Uuid::new_v4(), Some(Uuid::new_v4()), None);
            let listed = service
                .list_organization(elsewhere, organization, None, Some(0))
                .await;
            assert!(matches!(
                listed,
                Err(InvitationServiceError::NotFound(
                    InvitationTarget::Organization
                ))
            ));
            let plain = member(&pool, &tenant, OrganizationRole::Member).await;
            let listed = service
                .list_organization(plain, organization, None, Some(0))
                .await;
            assert!(matches!(listed, Err(InvitationServiceError::Forbidden)));
            let admin = member(&pool, &tenant, OrganizationRole::Admin).await;
            let listed = service
                .list_organization(admin, organization, None, Some(0))
                .await;
            assert!(matches!(listed, Err(InvitationServiceError::InvalidLimit)));
            let listed = service
                .list_platform_organization(admin, organization, None, None)
                .await;
            assert!(matches!(
                listed,
                Err(InvitationServiceError::SuperAdminRequired)
            ));
            let page = service
                .list_organization(admin, organization, None, None)
                .await
                .unwrap();
            assert!(page.items.is_empty());
            assert!(page.next_cursor.is_none());

            let missing = service
                .list_project(admin, Uuid::new_v4(), None, None)
                .await;
            assert!(matches!(
                missing,
                Err(InvitationServiceError::NotFound(InvitationTarget::Project))
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn issuing_resending_and_revoking_follow_the_invitation_lifecycle(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = InvitationService::new(pool.clone(), &config(true));
            let organization = tenant.organization_id;
            let owner = member(&pool, &tenant, OrganizationRole::Owner).await;
            let admin = member(&pool, &tenant, OrganizationRole::Admin).await;

            // The role is parsed before the owner rule is applied, and the
            // email only after both.
            let created = service
                .create_organization(admin, organization, invitation("bad", "boss"), "r")
                .await;
            assert!(matches!(
                created,
                Err(InvitationServiceError::Invalid(
                    "role must be owner, admin, or member"
                ))
            ));
            let created = service
                .create_organization(admin, organization, invitation("bad", "owner"), "r")
                .await;
            assert!(matches!(created, Err(InvitationServiceError::Forbidden)));
            let created = service
                .create_organization(owner, organization, invitation("bad", "owner"), "r")
                .await;
            assert!(matches!(
                created,
                Err(InvitationServiceError::Invalid("email is invalid"))
            ));

            let first = service
                .create_organization(
                    admin,
                    organization,
                    invitation(" New@Example.test ", "member"),
                    "r",
                )
                .await
                .unwrap();
            assert_eq!(first.recipient_email, "new@example.test");
            assert_eq!(first.status, InvitationStatus::Pending);
            assert_eq!(first.scope, InvitationScope::Organization);
            let again = service
                .create_organization(
                    admin,
                    organization,
                    invitation("new@example.test", "member"),
                    "r",
                )
                .await;
            assert!(matches!(
                again,
                Err(InvitationServiceError::Conflict(
                    InvitationConflict::InvitationExists
                ))
            ));
            let existing_member = service
                .create_organization(
                    admin,
                    organization,
                    invitation(&format!("{}@example.test", owner.user_id), "member"),
                    "r",
                )
                .await;
            assert!(matches!(
                existing_member,
                Err(InvitationServiceError::Conflict(
                    InvitationConflict::MembershipExists
                ))
            ));

            let replacement = service
                .resend_organization(admin, organization, first.id, "r")
                .await
                .unwrap();
            assert_ne!(replacement.id, first.id);
            assert_eq!(replacement.status, InvitationStatus::Pending);
            let replaced = service
                .revoke_organization(admin, organization, first.id, "r")
                .await;
            assert!(matches!(
                replaced,
                Err(InvitationServiceError::Conflict(
                    InvitationConflict::NotPending
                ))
            ));
            // Revoking twice is the same as revoking once.
            for _ in 0..2 {
                service
                    .revoke_organization(admin, organization, replacement.id, "r")
                    .await
                    .unwrap();
            }
            let resent = service
                .resend_organization(admin, organization, replacement.id, "r")
                .await;
            assert!(matches!(
                resent,
                Err(InvitationServiceError::Conflict(
                    InvitationConflict::NotPending
                ))
            ));
            let page = service
                .list_organization(owner, organization, None, None)
                .await
                .unwrap();
            let statuses = page
                .items
                .iter()
                .map(|item| (item.id, item.status))
                .collect::<Vec<_>>();
            assert!(statuses.contains(&(first.id, InvitationStatus::Replaced)));
            assert!(statuses.contains(&(replacement.id, InvitationStatus::Revoked)));

            let unknown = service
                .revoke_organization(admin, organization, Uuid::new_v4(), "r")
                .await;
            assert!(matches!(
                unknown,
                Err(InvitationServiceError::NotFound(
                    InvitationTarget::Invitation
                ))
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn accepting_grants_the_role_once(pool: PgPool) {
            let tenant = tenant(&pool, "northstar").await;
            let service = InvitationService::new(pool.clone(), &config(true));
            let owner = member(&pool, &tenant, OrganizationRole::Owner).await;
            let (_, token) = pending(&pool, &tenant, owner.user_id, "new@example.test").await;

            assert!(matches!(
                service.inspect("oko_invitation_v1_short").await,
                Err(InvitationServiceError::Unusable)
            ));
            let inspection = service.inspect(&token).await.unwrap();
            assert!(matches!(
                inspection.account_state,
                InvitationAccountState::NewUser
            ));

            // The password is checked before the token.
            let weak = service
                .accept_new_user(
                    NewUserAcceptance {
                        token: "garbage".into(),
                        password: "short".into(),
                        display_name: "New".into(),
                        locale: Locale::En,
                    },
                    "r",
                )
                .await;
            assert!(matches!(
                weak,
                Err(InvitationServiceError::Invalid("password is invalid"))
            ));
            // An existing user who is not the recipient cannot take it.
            let stranger = principal(user(&pool).await, None, None);
            let taken = service.accept_existing_user(stranger, &token, "r").await;
            assert!(matches!(
                taken,
                Err(InvitationServiceError::Conflict(
                    InvitationConflict::AccountMismatch
                ))
            ));

            let accepted = service
                .accept_new_user(
                    NewUserAcceptance {
                        token: token.clone(),
                        password: "correct horse battery staple".into(),
                        display_name: "New".into(),
                        locale: Locale::En,
                    },
                    "r",
                )
                .await
                .unwrap();
            let user_id = accepted.acceptance.user_id;
            assert_eq!(accepted.acceptance.organization_id, tenant.organization_id);
            assert_eq!(accepted.acceptance.role, "member");
            let role = MembershipRepository::organization_role_when_active(
                &pool,
                user_id,
                tenant.organization_id,
            )
            .await
            .unwrap();
            assert_eq!(role.as_deref(), Some("member"));

            let twice = service
                .accept_new_user(
                    NewUserAcceptance {
                        token: token.clone(),
                        password: "correct horse battery staple".into(),
                        display_name: "New".into(),
                        locale: Locale::En,
                    },
                    "r",
                )
                .await;
            assert!(matches!(twice, Err(InvitationServiceError::Unusable)));
            // The user who accepted it may accept it again.
            let again = service
                .accept_existing_user(principal(user_id, None, None), &token, "r")
                .await
                .unwrap();
            assert_eq!(again.user_id, user_id);
        }
    }
}
