//! Organization-scoped persistence.
//!
//! # Lifecycle
//!
//! An organization is in one of two states, and moves between them only in the
//! directions below. The transitions used to be written in three modules —
//! creation in [`crate::access_api`], activation in [`crate::invitation_api`],
//! and the count of stragglers in [`crate::metrics`] — so no single place said
//! what the states were or how one became the other.
//!
//! ```text
//!              create(PendingOwner)          create(Active)
//!                     |                            |
//!                     v                            v
//!              +---------------+  activate  +----------+
//!              | pending_owner | ---------> |  active  |
//!              +---------------+            +----------+
//!                     |
//!                     | discard (no members at all)
//!                     v
//!                  deleted
//! ```
//!
//! `pending_owner` is an organization a platform administrator created on
//! someone else's behalf and that nobody has claimed yet. It confers no role:
//! [`crate::repository::MembershipRepository::organization_role_when_active`]
//! ignores it. It becomes `active` once an owner who can act exists, and can be
//! discarded only while it has no members at all — after that, deleting it
//! would take other people's access with it.
//!
//! Retention settings are not here. They live beside the logic that interprets
//! them, in [`crate::runtime_retention::settings`] and
//! [`crate::notification::retention_settings`].

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::repository::users::ACTIVE as ACTIVE_USER;

/// Where an organization is in its lifecycle. See the module documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationStatus {
    /// Created on someone's behalf and not yet claimed by an owner who can act.
    PendingOwner,
    /// In service.
    Active,
}

impl OrganizationStatus {
    /// The value stored in `organizations.status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingOwner => "pending_owner",
            Self::Active => "active",
        }
    }
}

/// An organization row as stored.
///
/// This is a persistence row, not a response. Endpoints project it into their
/// own types so the table and the public contract can change independently.
#[derive(Clone, Debug, FromRow, PartialEq)]
pub struct StoredOrganization {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Queries against the `organizations` table.
#[derive(Clone, Copy, Debug)]
pub struct OrganizationRepository;

impl OrganizationRepository {
    /// Creates an organization in the given state and returns the stored row.
    ///
    /// A duplicate slug fails on the unique index; callers report that as a
    /// slug conflict.
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        slug: &str,
        name: &str,
        status: OrganizationStatus,
    ) -> Result<StoredOrganization, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO organizations(id, slug, name, status)
            VALUES ($1, $2, $3, $4)
            RETURNING id, slug, name, status, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(slug)
        .bind(name)
        .bind(status.as_str())
        .fetch_one(executor)
        .await
    }

    /// Reports whether any organization exists at all.
    ///
    /// Single-organization mode refuses a second one on the strength of this.
    /// On its own it is only a snapshot: a caller enforcing a limit with it
    /// must hold a lock that a concurrent creation also takes, or two requests
    /// can both see `false` and both insert.
    pub async fn any_exists<'e, E>(executor: E) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations)")
            .fetch_one(executor)
            .await
    }

    /// Takes a share lock on the organization, reporting whether it exists.
    ///
    /// This is the first half of the lock order for project-scoped work:
    /// organization `FOR SHARE`, then project `FOR UPDATE`. Every path that
    /// needs both must take them in that order, or two of them can each hold
    /// the lock the other is waiting for. A share lock lets concurrent project
    /// work in the same organization proceed while blocking the organization's
    /// own deletion until it finishes.
    ///
    /// Requires a transaction; pass `&mut *tx`.
    pub async fn lock_shared<'e, E>(executor: E, organization_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Ok(
            sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR SHARE")
                .bind(organization_id)
                .fetch_optional(executor)
                .await?
                .is_some(),
        )
    }

    /// Moves a pending organization to active, provided it now has an owner
    /// who can act. Reports whether the transition happened.
    ///
    /// The owner check is part of the transition rather than something the
    /// caller verifies first, so the state and the reason for it change in one
    /// statement. An organization already active, or pending with only
    /// disabled or unverified owners, is left as it is.
    pub async fn activate_when_owned<'e, E>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Ok(sqlx::query(&format!(
            "UPDATE organizations SET status = 'active', updated_at = now() \
             WHERE id = $1 AND status = 'pending_owner' \
               AND EXISTS(SELECT 1 FROM organization_memberships m \
                          JOIN users u ON u.id = m.user_id \
                          WHERE m.organization_id = $1 AND m.role = 'owner' \
                            AND {ACTIVE_USER})"
        ))
        .bind(organization_id)
        .execute(executor)
        .await?
        .rows_affected()
            > 0)
    }

    /// Deletes a pending organization that nobody has joined. Reports whether
    /// it was deleted.
    ///
    /// Both conditions are checked in the statement itself. An active
    /// organization is never discarded this way, and neither is a pending one
    /// with any member — an invited administrator who accepted before the
    /// owner did would otherwise lose their access without being asked.
    pub async fn discard_unclaimed<'e, E>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Ok(sqlx::query(
            r#"
            DELETE FROM organizations
            WHERE id = $1 AND status = 'pending_owner'
              AND NOT EXISTS(SELECT 1 FROM organization_memberships
                             WHERE organization_id = $1)
            "#,
        )
        .bind(organization_id)
        .execute(executor)
        .await?
        .rows_affected()
            > 0)
    }

    /// Counts organizations still waiting for an owner.
    pub async fn pending_owner_count<'e, E>(executor: E) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT count(*) FROM organizations WHERE status = 'pending_owner'")
            .fetch_one(executor)
            .await
    }

    /// Reports whether the organization exists.
    pub async fn exists<'e, E>(executor: E, organization_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)
            "#,
        )
        .bind(organization_id)
        .fetch_one(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{OrganizationRepository, OrganizationStatus};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn create(pool: &PgPool, status: OrganizationStatus) -> Uuid {
        let id = Uuid::new_v4();
        OrganizationRepository::insert(pool, id, &id.to_string(), "Lifecycle", status)
            .await
            .unwrap();
        id
    }

    async fn status_of(pool: &PgPool, id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT status FROM organizations WHERE id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap()
    }

    async fn add_member(pool: &PgPool, organization: Uuid, role: &str, verified: bool) -> Uuid {
        let user = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,email_verified_at) \
             VALUES($1,$2,$3,CASE WHEN $4 THEN now() END)",
        )
        .bind(user)
        .bind(format!("{user}@example.test"))
        .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef")
        .bind(verified)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
        )
        .bind(organization)
        .bind(user)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
        user
    }

    /// The owner check is part of the transition. A pending organization whose
    /// only owner cannot act yet stays pending, and becomes active in the same
    /// statement that finds a usable owner — never before.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_pending_organization_activates_only_once_an_owner_can_act(pool: PgPool) {
        let organization = create(&pool, OrganizationStatus::PendingOwner).await;
        assert!(
            !OrganizationRepository::activate_when_owned(&pool, organization)
                .await
                .unwrap(),
            "no owner at all"
        );

        let owner = add_member(&pool, organization, "owner", false).await;
        assert!(
            !OrganizationRepository::activate_when_owned(&pool, organization)
                .await
                .unwrap(),
            "an unverified owner cannot claim the organization"
        );
        assert_eq!(
            status_of(&pool, organization).await.as_deref(),
            Some("pending_owner")
        );

        sqlx::query("UPDATE users SET email_verified_at=now() WHERE id=$1")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            OrganizationRepository::activate_when_owned(&pool, organization)
                .await
                .unwrap()
        );
        assert_eq!(
            status_of(&pool, organization).await.as_deref(),
            Some("active")
        );
        assert!(
            !OrganizationRepository::activate_when_owned(&pool, organization)
                .await
                .unwrap(),
            "activating twice reports no transition"
        );
    }

    /// Only a pending organization with no members at all can be discarded. An
    /// invited administrator who joined before the owner did must not lose
    /// access because someone decided to clean up.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn only_an_unjoined_pending_organization_can_be_discarded(pool: PgPool) {
        let active = create(&pool, OrganizationStatus::Active).await;
        assert!(
            !OrganizationRepository::discard_unclaimed(&pool, active)
                .await
                .unwrap(),
            "an active organization is never discarded this way"
        );
        assert!(status_of(&pool, active).await.is_some());

        let joined = create(&pool, OrganizationStatus::PendingOwner).await;
        add_member(&pool, joined, "admin", true).await;
        assert!(
            !OrganizationRepository::discard_unclaimed(&pool, joined)
                .await
                .unwrap(),
            "a pending organization someone joined is kept"
        );
        assert!(status_of(&pool, joined).await.is_some());

        let empty = create(&pool, OrganizationStatus::PendingOwner).await;
        assert!(
            OrganizationRepository::discard_unclaimed(&pool, empty)
                .await
                .unwrap()
        );
        assert!(status_of(&pool, empty).await.is_none());
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn creation_records_the_requested_state_and_counts_stragglers(pool: PgPool) {
        assert!(!OrganizationRepository::any_exists(&pool).await.unwrap());

        let id = Uuid::new_v4();
        let stored = OrganizationRepository::insert(
            &pool,
            id,
            "stragglers",
            "Stragglers",
            OrganizationStatus::PendingOwner,
        )
        .await
        .unwrap();
        assert_eq!((stored.id, stored.status.as_str()), (id, "pending_owner"));
        create(&pool, OrganizationStatus::Active).await;

        assert!(OrganizationRepository::any_exists(&pool).await.unwrap());
        assert_eq!(
            OrganizationRepository::pending_owner_count(&pool)
                .await
                .unwrap(),
            1
        );
        assert!(
            OrganizationRepository::insert(
                &pool,
                Uuid::new_v4(),
                "stragglers",
                "Duplicate",
                OrganizationStatus::Active
            )
            .await
            .is_err(),
            "a duplicate slug is refused"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_share_lock_reports_whether_the_organization_exists(pool: PgPool) {
        let organization = create(&pool, OrganizationStatus::Active).await;
        let mut tx = pool.begin().await.unwrap();
        assert!(
            OrganizationRepository::lock_shared(&mut *tx, organization)
                .await
                .unwrap()
        );
        assert!(
            !OrganizationRepository::lock_shared(&mut *tx, Uuid::new_v4())
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
    }

    #[test]
    fn status_values_match_the_check_constraint() {
        assert_eq!(OrganizationStatus::PendingOwner.as_str(), "pending_owner");
        assert_eq!(OrganizationStatus::Active.as_str(), "active");
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn distinguishes_a_known_organization_from_an_unknown_one(pool: PgPool) {
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            OrganizationRepository::exists(&pool, organization)
                .await
                .unwrap()
        );
        assert!(
            !OrganizationRepository::exists(&pool, Uuid::new_v4())
                .await
                .unwrap()
        );
    }
}
