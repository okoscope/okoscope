//! Invitation persistence: pending, replaced, revoked and accepted
//! invitations to an organization or one of its projects, and the checks the
//! issuing flow makes against them.
//!
//! The invitation projection belongs to the invitation endpoints, so the reads
//! returning it are generic over the row type; [`INVITATION_SELECT`] lists its
//! columns.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// The invitation projection the endpoints read: the invitation with its
/// organization and project names and the inviter's display name.
///
/// Selects `id`, `organization_id`, `organization_name`, `project_id`,
/// `project_name`, `recipient_email`, `role`, `inviter_display_name`,
/// `locale`, `created_at`, `expires_at`, `accepted_at`,
/// `accepted_by_user_id`, `revoked_at` and `replaced_at`.
const INVITATION_SELECT: &str = "SELECT i.id,i.organization_id,o.name organization_name,i.project_id,p.name project_name,i.recipient_email,i.role,u.display_name inviter_display_name,i.locale,i.created_at,i.expires_at,i.accepted_at,i.accepted_by_user_id,i.revoked_at,i.replaced_at FROM invitations i JOIN organizations o ON o.id=i.organization_id LEFT JOIN projects p ON p.id=i.project_id JOIN users u ON u.id=i.inviter_user_id";

/// Invitations: issuing, replacing, revoking and accepting them, and the
/// reads behind the invitation endpoints.
#[derive(Clone, Copy, Debug)]
pub struct InvitationRepository;

impl InvitationRepository {
    /// Deletes invitations past their retention.
    pub async fn delete_retained<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM invitations WHERE retain_until<now()")
            .execute(executor)
            .await
    }

    /// The invitation with this id.
    pub async fn get<'e, E, T>(executor: E, invitation_id: Uuid) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!("{INVITATION_SELECT} WHERE i.id=$1");
        sqlx::query_as(&query)
            .bind(invitation_id)
            .fetch_optional(executor)
            .await
    }

    /// Locks the invitation with this id and returns it.
    pub async fn get_for_update<'e, E, T>(
        executor: E,
        invitation_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!("{INVITATION_SELECT} WHERE i.id=$1 FOR UPDATE OF i");
        sqlx::query_as(&query)
            .bind(invitation_id)
            .fetch_optional(executor)
            .await
    }

    /// The invitation whose token hashes to `token_digest`.
    pub async fn by_token_digest<'e, E, T>(
        executor: E,
        token_digest: Vec<u8>,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!("{INVITATION_SELECT} WHERE i.token_digest=$1");
        sqlx::query_as(&query)
            .bind(token_digest)
            .fetch_optional(executor)
            .await
    }

    /// Locks the invitation whose token hashes to `token_digest` and returns
    /// it.
    pub async fn by_token_digest_for_update<'e, E, T>(
        executor: E,
        token_digest: Vec<u8>,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!("{INVITATION_SELECT} WHERE i.token_digest=$1 FOR UPDATE OF i");
        sqlx::query_as(&query)
            .bind(token_digest)
            .fetch_optional(executor)
            .await
    }

    /// A page of all invitations, newest first, after the cursor invitation
    /// when one is given.
    pub async fn page<'e, E, T>(
        executor: E,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INVITATION_SELECT} WHERE ($1::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$1)) ORDER BY i.created_at DESC,i.id DESC LIMIT $2"
        );
        sqlx::query_as(&query)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the organization's own invitations (not its projects'),
    /// newest first, after the cursor invitation when one is given.
    pub async fn organization_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INVITATION_SELECT} WHERE i.organization_id=$1 AND i.project_id IS NULL AND ($2::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$2 AND organization_id=$1 AND project_id IS NULL)) ORDER BY i.created_at DESC,i.id DESC LIMIT $3"
        );
        sqlx::query_as(&query)
            .bind(organization_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the project's invitations, newest first, after the cursor
    /// invitation when one is given.
    pub async fn project_page<'e, E, T>(
        executor: E,
        project_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INVITATION_SELECT} WHERE i.project_id=$1 AND ($2::uuid IS NULL OR (i.created_at,i.id)<(SELECT created_at,id FROM invitations WHERE id=$2 AND project_id=$1)) ORDER BY i.created_at DESC,i.id DESC LIMIT $3"
        );
        sqlx::query_as(&query)
            .bind(project_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// The newest owner invitation to the organization that is neither
    /// accepted, revoked nor replaced. It may have expired.
    pub async fn pending_owner_invitation<'e, E, T>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INVITATION_SELECT} WHERE i.organization_id=$1 AND i.project_id IS NULL AND i.role='owner' AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.replaced_at IS NULL ORDER BY i.created_at DESC,i.id DESC LIMIT 1"
        );
        sqlx::query_as(&query)
            .bind(organization_id)
            .fetch_optional(executor)
            .await
    }

    /// Inserts a pending invitation, retained for a year past its expiry. A
    /// live invitation for the same recipient and scope violates a unique
    /// index, which callers report as a conflict.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Option<Uuid>,
        recipient_email: &str,
        role: &str,
        inviter_user_id: Uuid,
        locale: &str,
        token_digest: Vec<u8>,
        expires_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO invitations(id,organization_id,project_id,recipient_email,role,inviter_user_id,locale,token_digest,expires_at,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9+interval '365 days')")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(recipient_email)
            .bind(role)
            .bind(inviter_user_id)
            .bind(locale)
            .bind(token_digest)
            .bind(expires_at)
            .execute(executor)
            .await
    }

    /// Reports whether a user with this email already belongs to the project.
    pub async fn recipient_is_project_member<'e, E>(
        executor: E,
        recipient_email: &str,
        project_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users u JOIN project_memberships m ON m.user_id=u.id WHERE u.email=$1 AND m.project_id=$2)")
            .bind(recipient_email)
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// Reports whether a user with this email already belongs to the
    /// organization.
    pub async fn recipient_is_organization_member<'e, E>(
        executor: E,
        recipient_email: &str,
        organization_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users u JOIN organization_memberships m ON m.user_id=u.id WHERE u.email=$1 AND m.organization_id=$2)")
            .bind(recipient_email)
            .bind(organization_id)
            .fetch_one(executor)
            .await
    }

    /// How many invitations the user issued in the last hour.
    pub async fn created_last_hour<'e, E>(
        executor: E,
        inviter_user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM invitations WHERE inviter_user_id=$1 AND created_at>now()-interval '1 hour'")
            .bind(inviter_user_id)
            .fetch_one(executor)
            .await
    }

    /// Locks the invitation for this recipient and scope that is neither
    /// accepted, revoked nor replaced, returning its id and expiry. It may
    /// already have expired.
    pub async fn unresolved_equivalent_for_update<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Option<Uuid>,
        recipient_email: &str,
    ) -> Result<Option<(Uuid, DateTime<Utc>)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, DateTime<Utc>)>("SELECT id,expires_at FROM invitations WHERE organization_id=$1 AND project_id IS NOT DISTINCT FROM $2 AND recipient_email=$3 AND accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL FOR UPDATE")
            .bind(organization_id)
            .bind(project_id)
            .bind(recipient_email)
            .fetch_optional(executor)
            .await
    }

    /// Marks an invitation revoked now.
    pub async fn revoke<'e, E>(
        executor: E,
        invitation_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE invitations SET revoked_at=now() WHERE id=$1")
            .bind(invitation_id)
            .execute(executor)
            .await
    }

    /// Turns the revocation of an expired invitation into a replacement by a
    /// new one: clears `revoked_at` and records the replacement.
    pub async fn mark_replaced<'e, E>(
        executor: E,
        expired_id: Uuid,
        replacement_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE invitations SET revoked_at=NULL,replaced_at=now(),replaced_by_invitation_id=$2 WHERE id=$1")
            .bind(expired_id)
            .bind(replacement_id)
            .execute(executor)
            .await
    }

    /// The organization name, project name when scoped to a project, and
    /// inviter display name for the invitation mail.
    pub async fn mail_context<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Option<Uuid>,
        inviter_user_id: Uuid,
    ) -> Result<(String, Option<String>, String), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (String, Option<String>, String)>("SELECT o.name,p.name,u.display_name FROM organizations o LEFT JOIN projects p ON p.id=$2 JOIN users u ON u.id=$3 WHERE o.id=$1")
            .bind(organization_id)
            .bind(project_id)
            .bind(inviter_user_id)
            .fetch_one(executor)
            .await
    }

    /// How many invitations the user resent in the last hour, counted from
    /// the access audit.
    pub async fn resent_last_hour<'e, E>(
        executor: E,
        actor_user_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM access_audit_records WHERE actor_user_id=$1 AND action='invitation.resent' AND created_at>now()-interval '1 hour'")
            .bind(actor_user_id)
            .fetch_one(executor)
            .await
    }

    /// Accepts a live invitation on behalf of the user. Affects no row when
    /// the invitation is no longer live.
    pub async fn consume<'e, E>(
        executor: E,
        invitation_id: Uuid,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE invitations SET accepted_at=now(),accepted_by_user_id=$2 WHERE id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL AND expires_at>now()")
            .bind(invitation_id)
            .bind(user_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::InvitationRepository;
    use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
    use crate::repository::MembershipRepository;
    use crate::repository::test_support::{Tenant, tenant, user};

    #[derive(Debug, FromRow)]
    struct Invitation {
        id: Uuid,
        organization_name: String,
        project_name: Option<String>,
        recipient_email: String,
        role: String,
        inviter_display_name: String,
        accepted_at: Option<DateTime<Utc>>,
        accepted_by_user_id: Option<Uuid>,
        revoked_at: Option<DateTime<Utc>>,
        replaced_at: Option<DateTime<Utc>>,
    }

    async fn issue(
        pool: &PgPool,
        own: &Tenant,
        project_id: Option<Uuid>,
        email: &str,
        role: &str,
        inviter: Uuid,
        digest: u8,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        InvitationRepository::insert(
            pool,
            id,
            own.organization_id,
            project_id,
            email,
            role,
            inviter,
            "en",
            vec![digest; 32],
            Utc::now() + Duration::days(1),
        )
        .await?;
        Ok(id)
    }

    async fn get(pool: &PgPool, id: Uuid) -> Invitation {
        InvitationRepository::get(pool, id).await.unwrap().unwrap()
    }

    async fn email_of(pool: &PgPool, user_id: Uuid) -> String {
        sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Issuing reads its target's names, rejects a second live invitation for
    /// the same scope and recipient, and finds, revokes and replaces the one
    /// that exists.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn issuing_checks_revokes_and_replaces(pool: PgPool) {
        let own = tenant(&pool, "invitations-issue").await;
        let inviter = user(&pool).await;
        let first = issue(&pool, &own, None, "a@example.test", "member", inviter, 1)
            .await
            .unwrap();
        let read = get(&pool, first).await;
        assert_eq!(
            (
                read.id,
                read.organization_name.as_str(),
                read.project_name.as_deref(),
                read.recipient_email.as_str(),
                read.role.as_str(),
                read.inviter_display_name.as_str(),
            ),
            (
                first,
                "invitations-issue",
                None,
                "a@example.test",
                "member",
                "User"
            )
        );
        let duplicate = issue(&pool, &own, None, "a@example.test", "admin", inviter, 2)
            .await
            .unwrap_err();
        assert_eq!(
            duplicate
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505"),
            "one live invitation per scope and recipient"
        );
        assert_eq!(
            InvitationRepository::created_last_hour(&pool, inviter)
                .await
                .unwrap(),
            1
        );

        let live = InvitationRepository::unresolved_equivalent_for_update(
            &pool,
            own.organization_id,
            None,
            "a@example.test",
        )
        .await
        .unwrap();
        assert_eq!(live.map(|(id, _)| id), Some(first));
        assert!(
            InvitationRepository::unresolved_equivalent_for_update(
                &pool,
                own.organization_id,
                Some(own.project_id),
                "a@example.test",
            )
            .await
            .unwrap()
            .is_none(),
            "a project invitation is a different scope"
        );

        InvitationRepository::revoke(&pool, first).await.unwrap();
        assert!(get(&pool, first).await.revoked_at.is_some());
        assert!(
            InvitationRepository::unresolved_equivalent_for_update(
                &pool,
                own.organization_id,
                None,
                "a@example.test",
            )
            .await
            .unwrap()
            .is_none()
        );
        let second = issue(&pool, &own, None, "a@example.test", "member", inviter, 3)
            .await
            .unwrap();
        InvitationRepository::mark_replaced(&pool, first, second)
            .await
            .unwrap();
        let replaced = get(&pool, first).await;
        assert!(replaced.revoked_at.is_none() && replaced.replaced_at.is_some());
        let by: Option<Uuid> =
            sqlx::query_scalar("SELECT replaced_by_invitation_id FROM invitations WHERE id=$1")
                .bind(first)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(by, Some(second));

        let organization =
            InvitationRepository::mail_context(&pool, own.organization_id, None, inviter)
                .await
                .unwrap();
        assert_eq!(
            organization,
            ("invitations-issue".into(), None, "User".into())
        );
        let project = InvitationRepository::mail_context(
            &pool,
            own.organization_id,
            Some(own.project_id),
            inviter,
        )
        .await
        .unwrap();
        assert_eq!(project.1.as_deref(), Some("Project"));
    }

    /// Membership checks match the recipient's address against members of the
    /// organization or of the project.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_recipient_can_already_be_a_member(pool: PgPool) {
        let own = tenant(&pool, "invitations-members").await;
        let member = user(&pool).await;
        let email = email_of(&pool, member).await;
        let in_organization = || {
            InvitationRepository::recipient_is_organization_member(
                &pool,
                &email,
                own.organization_id,
            )
        };
        let in_project =
            || InvitationRepository::recipient_is_project_member(&pool, &email, own.project_id);
        assert!(!in_organization().await.unwrap());
        MembershipRepository::insert_organization_role(
            &pool,
            own.organization_id,
            member,
            "member",
        )
        .await
        .unwrap();
        assert!(in_organization().await.unwrap());
        assert!(!in_project().await.unwrap());
        MembershipRepository::insert_project_role(
            &pool,
            own.organization_id,
            own.project_id,
            member,
            "member",
        )
        .await
        .unwrap();
        assert!(in_project().await.unwrap());
        assert!(
            !InvitationRepository::recipient_is_organization_member(
                &pool,
                "nobody@example.test",
                own.organization_id
            )
            .await
            .unwrap()
        );
    }

    /// An invitation is found by its token digest and consumed once, and only
    /// while it is live.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_token_is_consumed_once_while_live(pool: PgPool) {
        let own = tenant(&pool, "invitations-token").await;
        let inviter = user(&pool).await;
        let invitee = user(&pool).await;
        let id = issue(&pool, &own, None, "b@example.test", "member", inviter, 7)
            .await
            .unwrap();
        let found: Option<Invitation> = InvitationRepository::by_token_digest(&pool, vec![7; 32])
            .await
            .unwrap();
        assert_eq!(found.map(|i| i.id), Some(id));
        let mut tx = pool.begin().await.unwrap();
        let locked: Option<Invitation> =
            InvitationRepository::by_token_digest_for_update(&mut *tx, vec![7; 32])
                .await
                .unwrap();
        assert_eq!(locked.map(|i| i.id), Some(id));
        let by_id: Option<Invitation> = InvitationRepository::get_for_update(&mut *tx, id)
            .await
            .unwrap();
        assert!(by_id.is_some());
        tx.commit().await.unwrap();
        assert!(
            InvitationRepository::by_token_digest::<_, Invitation>(&pool, vec![8; 32])
                .await
                .unwrap()
                .is_none()
        );

        let first = InvitationRepository::consume(&pool, id, invitee)
            .await
            .unwrap();
        let again = InvitationRepository::consume(&pool, id, invitee)
            .await
            .unwrap();
        assert_eq!((first.rows_affected(), again.rows_affected()), (1, 0));
        let accepted = get(&pool, id).await;
        assert!(accepted.accepted_at.is_some());
        assert_eq!(accepted.accepted_by_user_id, Some(invitee));

        let expired = issue(&pool, &own, None, "c@example.test", "member", inviter, 9)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE invitations SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(expired)
        .execute(&pool)
        .await
        .unwrap();
        let late = InvitationRepository::consume(&pool, expired, invitee)
            .await
            .unwrap();
        assert_eq!(
            late.rows_affected(),
            0,
            "an expired invitation is not consumed"
        );
    }

    /// Pages list newest first after a cursor, the organization page leaves
    /// out project invitations, and each page stays within its scope.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn pages_are_scoped_and_newest_first(pool: PgPool) {
        let own = tenant(&pool, "invitations-pages").await;
        let other = tenant(&pool, "invitations-pages-other").await;
        let inviter = user(&pool).await;
        let mut organization = Vec::new();
        for (index, email) in ["1@example.test", "2@example.test", "3@example.test"]
            .into_iter()
            .enumerate()
        {
            let id = issue(
                &pool,
                &own,
                None,
                email,
                "member",
                inviter,
                10 + u8::try_from(index).unwrap(),
            )
            .await
            .unwrap();
            organization.push(id);
        }
        let project = issue(
            &pool,
            &own,
            Some(own.project_id),
            "p@example.test",
            "member",
            inviter,
            20,
        )
        .await
        .unwrap();
        let foreign = issue(&pool, &other, None, "f@example.test", "member", inviter, 21)
            .await
            .unwrap();
        for (minutes, id) in [
            (50, organization[0]),
            (40, organization[1]),
            (30, organization[2]),
            (20, project),
            (10, foreign),
        ] {
            sqlx::query(
                "UPDATE invitations SET created_at=now()-make_interval(mins=>$2) WHERE id=$1",
            )
            .bind(id)
            .bind(minutes)
            .execute(&pool)
            .await
            .unwrap();
        }
        let ids = |rows: Vec<Invitation>| rows.into_iter().map(|i| i.id).collect::<Vec<_>>();

        let all = ids(InvitationRepository::page(&pool, None, 10).await.unwrap());
        assert_eq!(
            all,
            [
                foreign,
                project,
                organization[2],
                organization[1],
                organization[0]
            ]
        );
        let after = ids(InvitationRepository::page(&pool, Some(project), 2)
            .await
            .unwrap());
        assert_eq!(after, [organization[2], organization[1]]);

        let own_page =
            ids(
                InvitationRepository::organization_page(&pool, own.organization_id, None, 10)
                    .await
                    .unwrap(),
            );
        assert_eq!(
            own_page,
            [organization[2], organization[1], organization[0]]
        );
        let own_after = ids(InvitationRepository::organization_page(
            &pool,
            own.organization_id,
            Some(organization[2]),
            10,
        )
        .await
        .unwrap());
        assert_eq!(own_after, [organization[1], organization[0]]);
        let project_page = ids(
            InvitationRepository::project_page(&pool, own.project_id, None, 10)
                .await
                .unwrap(),
        );
        assert_eq!(project_page, [project]);
    }

    /// The pending owner invitation is the newest unresolved owner invitation
    /// to the organization itself.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_pending_owner_invitation_is_the_newest_unresolved(pool: PgPool) {
        let own = tenant(&pool, "invitations-owner").await;
        let inviter = user(&pool).await;
        issue(&pool, &own, None, "m@example.test", "member", inviter, 30)
            .await
            .unwrap();
        let older = issue(&pool, &own, None, "o1@example.test", "owner", inviter, 31)
            .await
            .unwrap();
        sqlx::query("UPDATE invitations SET created_at=now()-interval '1 hour' WHERE id=$1")
            .bind(older)
            .execute(&pool)
            .await
            .unwrap();
        let newer = issue(&pool, &own, None, "o2@example.test", "owner", inviter, 32)
            .await
            .unwrap();
        let pending = || async {
            InvitationRepository::pending_owner_invitation::<_, Invitation>(
                &pool,
                own.organization_id,
            )
            .await
            .unwrap()
            .map(|i| i.id)
        };
        assert_eq!(pending().await, Some(newer));
        InvitationRepository::revoke(&pool, newer).await.unwrap();
        assert_eq!(pending().await, Some(older));
        InvitationRepository::revoke(&pool, older).await.unwrap();
        assert_eq!(pending().await, None);
    }

    /// Resends are counted from the access audit, per actor, for the last
    /// hour.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn resends_are_counted_from_the_audit(pool: PgPool) {
        let actor = user(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        for action in [
            "invitation.resent",
            "invitation.resent",
            "invitation.revoked",
        ] {
            write_access_audit(
                &mut tx,
                AccessAuditEvent {
                    actor: AccessAuditActor::User(actor),
                    action,
                    organization_id: None,
                    project_id: None,
                    target_user_id: None,
                    invitation_id: None,
                    previous_role: None,
                    new_role: None,
                    request_id: None,
                },
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        assert_eq!(
            InvitationRepository::resent_last_hour(&pool, actor)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            InvitationRepository::resent_last_hour(&pool, Uuid::new_v4())
                .await
                .unwrap(),
            0
        );
    }
}
