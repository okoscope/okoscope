//! User account persistence.
//!
//! A user is only allowed to act when two independent conditions hold: the
//! account is not disabled, and its email address has been verified. That pair
//! was restated at nine call sites across six modules, in three shapes — a
//! `WHERE` clause, an `EXISTS` subquery, and a `count(*)` — and a tenth site
//! checked only half of it in SQL and the other half in Rust.
//!
//! Splitting a security predicate across that many copies is how one of them
//! eventually loses a conjunct. The predicate is written once here, as
//! [`ACTIVE`], and the queries that need it as a whole statement are methods.
//!
//! Every statement about users lives here, including the sign-in projections
//! that join memberships and organizations for one endpoint's response. Those
//! are generic over the row type and document the columns they select.
//!
//! Some statements moved here verbatim from their handlers still spell the
//! predicate out inline rather than through [`ACTIVE`];
//! [`UserRepository::eligible_for_super_admin`] is one. They were moved without
//! rewriting so the SQL stays byte-for-byte what it was.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// The condition under which a user account may act, as a SQL fragment.
///
/// Both halves are load-bearing and neither implies the other. `disabled_at`
/// is set when an administrator suspends an account that was once in good
/// standing; `email_verified_at` is null for an account that was never
/// confirmed, including one created by a self-registration whose confirmation
/// link was never followed.
///
/// Expects `users` aliased as `u`. Use it where the check has to sit inside a
/// larger statement — an `EXISTS` guarding an `UPDATE`, say. Where the whole
/// statement is about users, prefer a method on [`UserRepository`], which
/// applies this without the caller having to remember to.
pub const ACTIVE: &str = "u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL";

/// Queries against the `users` table.
#[derive(Clone, Copy, Debug)]
pub struct UserRepository;

impl UserRepository {
    /// Deletes up to 100 self-registered owners who never verified their
    /// email within 7 days and never signed in, together with the
    /// organization only they belong to.
    pub async fn delete_abandoned_signups<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("WITH candidates AS (SELECT u.id user_id,m.organization_id FROM users u JOIN organization_memberships m ON m.user_id=u.id AND m.role='owner' WHERE u.email_verified_at IS NULL AND u.created_at<now()-interval '7 days' AND NOT EXISTS(SELECT 1 FROM user_sessions s WHERE s.user_id=u.id) AND NOT EXISTS(SELECT 1 FROM organization_memberships other WHERE other.organization_id=m.organization_id AND other.user_id<>u.id) AND NOT EXISTS(SELECT 1 FROM organization_memberships external WHERE external.user_id=u.id AND external.organization_id<>m.organization_id) LIMIT 100), deleted_organizations AS (DELETE FROM organizations o USING candidates c WHERE o.id=c.organization_id RETURNING c.user_id) DELETE FROM users u USING deleted_organizations d WHERE u.id=d.user_id")
            .execute(executor)
            .await
    }

    /// Takes the transaction-scoped advisory lock that serialises first-run
    /// setup, so only one request can create the first super admin.
    pub async fn lock_setup<'e, E>(
        executor: E,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SELECT pg_advisory_xact_lock(1869373291)")
            .execute(executor)
            .await
    }

    /// Makes a user without any platform role assignment a super admin.
    pub async fn assign_super_admin<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO platform_role_assignments(user_id,role) VALUES($1,'super_admin')")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// Makes the user a super admin on behalf of platform recovery, with no
    /// granting user.
    pub async fn recover_super_admin<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO platform_role_assignments(user_id,role,revoked_at) VALUES($1,'super_admin',NULL) ON CONFLICT(user_id) DO UPDATE SET role='super_admin',revoked_at=NULL,granted_at=now(),granted_by_user_id=NULL")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// The sign-in projection of the user with this email, whether or not
    /// they may act. The organization columns are set only when the user
    /// belongs to exactly one active organization.
    ///
    /// Selects `user_id`, `email`, `password_hash`, `display_name`,
    /// `organization_id`, `organization_slug`, `organization_name`, `role`,
    /// `is_super_admin`, `disabled_at`, `email_verified_at` and
    /// `preferred_locale`.
    pub async fn sign_in_by_email<'e, E, T>(
        executor: E,
        email: &str,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT u.id user_id,u.email,u.password_hash,u.display_name,m.organization_id,o.slug organization_slug,o.name organization_name,m.role,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=u.id AND p.role='super_admin' AND p.revoked_at IS NULL) is_super_admin,u.disabled_at,u.email_verified_at,u.preferred_locale FROM users u LEFT JOIN organization_memberships m ON m.user_id=u.id AND (SELECT count(*) FROM organization_memberships mx JOIN organizations ox ON ox.id=mx.organization_id WHERE mx.user_id=u.id AND ox.status='active')=1 LEFT JOIN organizations o ON o.id=m.organization_id AND o.status='active' WHERE u.email=$1 LIMIT 1")
            .bind(email)
            .fetch_optional(executor)
            .await
    }

    /// The sign-in projection of [`Self::sign_in_by_email`] for a user by id,
    /// with the organization columns set from their membership of
    /// `organization_id` when it is active.
    pub async fn sign_in_by_id<'e, E, T>(
        executor: E,
        user_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT u.id user_id,u.email,u.password_hash,u.display_name,m.organization_id,o.slug organization_slug,o.name organization_name,m.role,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=u.id AND p.role='super_admin' AND p.revoked_at IS NULL) is_super_admin,u.disabled_at,u.email_verified_at,u.preferred_locale FROM users u LEFT JOIN organization_memberships m ON m.user_id=u.id AND m.organization_id=$2 LEFT JOIN organizations o ON o.id=m.organization_id AND o.status='active' WHERE u.id=$1")
            .bind(user_id)
            .bind(organization_id)
            .fetch_optional(executor)
            .await
    }

    /// Locks the user's row for the rest of the transaction.
    pub async fn lock<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// Marks the user's email verified, keeping an earlier verification time.
    pub async fn mark_email_verified<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE users SET email_verified_at=coalesce(email_verified_at,now()),updated_at=now() WHERE id=$1")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// Replaces the user's password hash.
    pub async fn set_password_hash<'e, E>(
        executor: E,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1")
            .bind(user_id)
            .bind(password_hash)
            .execute(executor)
            .await
    }

    /// The user's email and preferred locale.
    pub async fn email_and_locale<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<(String, String)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (String, String)>(
            "SELECT email,preferred_locale FROM users WHERE id=$1",
        )
        .bind(user_id)
        .fetch_optional(executor)
        .await
    }

    /// Sets the user's preferred locale and, when given, display name.
    pub async fn update_preferences<'e, E>(
        executor: E,
        user_id: Uuid,
        preferred_locale: &str,
        display_name: Option<String>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE users SET preferred_locale=$2,display_name=coalesce($3,display_name),updated_at=now() WHERE id=$1")
            .bind(user_id)
            .bind(preferred_locale)
            .bind(display_name)
            .execute(executor)
            .await
    }

    /// The user's password hash.
    pub async fn password_hash<'e, E>(executor: E, user_id: Uuid) -> Result<String, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(executor)
            .await
    }

    /// A page of all users by id, after the cursor when one is given, for
    /// platform administration.
    ///
    /// Selects `id`, `email`, `display_name`, `email_verified`, `enabled`,
    /// `is_super_admin` and `created_at`.
    pub async fn platform_page<'e, E, T>(
        executor: E,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT u.id,u.email,u.display_name,(u.email_verified_at IS NOT NULL) email_verified,(u.disabled_at IS NULL) enabled,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=u.id AND p.revoked_at IS NULL) is_super_admin,u.created_at FROM users u WHERE ($1::uuid IS NULL OR u.id>$1) ORDER BY u.id LIMIT $2")
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Disables the user, keeping an earlier disable time, or enables them,
    /// and returns them with the columns of [`Self::platform_page`]. `None`
    /// when there is no such user.
    pub async fn set_disabled<'e, E, T>(
        executor: E,
        user_id: Uuid,
        disabled: bool,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE users SET disabled_at=CASE WHEN $2 THEN coalesce(disabled_at,now()) ELSE NULL END,updated_at=now() WHERE id=$1 RETURNING id,email,display_name,(email_verified_at IS NOT NULL) email_verified,(disabled_at IS NULL) enabled,EXISTS(SELECT 1 FROM platform_role_assignments p WHERE p.user_id=users.id AND p.revoked_at IS NULL) is_super_admin,created_at")
            .bind(user_id)
            .bind(disabled)
            .fetch_optional(executor)
            .await
    }

    /// Reports whether the user is enabled and verified, as a super admin
    /// must be.
    pub async fn eligible_for_super_admin<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND disabled_at IS NULL AND email_verified_at IS NOT NULL)")
            .bind(user_id)
            .fetch_one(executor)
            .await
    }

    /// Grants the super admin role, reinstating a revoked assignment.
    pub async fn grant_super_admin<'e, E>(
        executor: E,
        user_id: Uuid,
        granted_by_user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO platform_role_assignments(user_id,role,granted_by_user_id) VALUES($1,'super_admin',$2) ON CONFLICT(user_id) DO UPDATE SET revoked_at=NULL,granted_at=now(),granted_by_user_id=$2")
            .bind(user_id)
            .bind(granted_by_user_id)
            .execute(executor)
            .await
    }

    /// Revokes an active super admin role. A check constraint rejects
    /// revoking the last one (SQLSTATE 23514).
    pub async fn revoke_super_admin<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE platform_role_assignments SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// Locks an active user and returns their email and when it was verified.
    pub async fn active_email_for_update<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (String, Option<DateTime<Utc>>)>("SELECT email,email_verified_at FROM users WHERE id=$1 AND disabled_at IS NULL FOR UPDATE")
            .bind(user_id)
            .fetch_optional(executor)
            .await
    }

    /// Returns the id of the account that may sign in with this address, or
    /// `None` when no account is both present and active.
    ///
    /// `FOR UPDATE` holds the row for the rest of the caller's transaction, so
    /// a concurrent request cannot disable the account between this check and
    /// whatever the caller does on the strength of it. That requires a
    /// transaction; pass `&mut *tx`.
    ///
    /// A disabled account, an unverified one, and an address with no account
    /// at all are all `None` by design: distinguishing them would tell an
    /// unauthenticated caller which addresses are registered.
    pub async fn active_id_by_email_for_update<'e, E>(
        executor: E,
        email: &str,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(&format!(
            "SELECT u.id FROM users u WHERE u.email = $1 AND {ACTIVE} FOR UPDATE"
        ))
        .bind(email)
        .fetch_optional(executor)
        .await
    }

    /// Reports whether an account with this id exists, active or not.
    pub async fn exists<'e, E>(executor: E, user_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(user_id)
            .fetch_one(executor)
            .await
    }

    /// Reports whether any account holds this address, active or not.
    ///
    /// This deliberately ignores [`ACTIVE`]: it answers "is this address
    /// taken", which a disabled or unverified account still makes true. Do not
    /// use it to decide whether someone may act.
    pub async fn exists_by_email<'e, E>(executor: E, email: &str) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(email)
            .fetch_one(executor)
            .await
    }

    /// Creates an account that must confirm its address before it can act.
    ///
    /// This is the self-registration path. The account exists but fails
    /// [`ACTIVE`] until a confirmation completes.
    pub async fn insert_unverified<'e, E>(
        executor: E,
        id: Uuid,
        email: &str,
        password_hash: &str,
        preferred_locale: &str,
        display_name: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Self::insert(
            executor,
            id,
            email,
            password_hash,
            preferred_locale,
            display_name,
            false,
        )
        .await
    }

    /// Creates an account that is already confirmed.
    ///
    /// Two paths reach this: accepting an invitation sent to the address, and
    /// the first-administrator setup. Both prove control of the address by
    /// other means, so requiring a second confirmation would ask the operator
    /// to verify something already established.
    pub async fn insert_verified<'e, E>(
        executor: E,
        id: Uuid,
        email: &str,
        password_hash: &str,
        preferred_locale: &str,
        display_name: &str,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        Self::insert(
            executor,
            id,
            email,
            password_hash,
            preferred_locale,
            display_name,
            true,
        )
        .await
    }

    async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        email: &str,
        password_hash: &str,
        preferred_locale: &str,
        display_name: &str,
        verified: bool,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO users(id, email, password_hash, email_verified_at,
                              preferred_locale, display_name)
            VALUES ($1, $2, $3, CASE WHEN $6 THEN now() END, $4, $5)
            "#,
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .bind(preferred_locale)
        .bind(display_name)
        .bind(verified)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Reports whether the installation has at least one super administrator
    /// who can actually act.
    ///
    /// Onboarding turns on this answer: an installation with no such account
    /// is unclaimed and still accepts first-administrator setup. Counting a
    /// disabled or unverified assignment would leave an installation that
    /// nobody can administer, and no way back in.
    pub async fn active_super_admin_exists<'e, E>(executor: E) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM platform_role_assignments p \
             JOIN users u ON u.id = p.user_id \
             WHERE p.role = 'super_admin' AND p.revoked_at IS NULL AND {ACTIVE})"
        ))
        .fetch_one(executor)
        .await
    }

    /// Counts the super administrators who can act.
    ///
    /// Used to refuse the demotion or disabling that would remove the last
    /// one, so it must agree with [`Self::active_super_admin_exists`] on what
    /// counts — hence the shared predicate rather than two spellings.
    pub async fn active_super_admin_count<'e, E>(executor: E) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(&format!(
            "SELECT count(*) FROM platform_role_assignments p \
             JOIN users u ON u.id = p.user_id \
             WHERE p.role = 'super_admin' AND p.revoked_at IS NULL AND {ACTIVE}"
        ))
        .fetch_one(executor)
        .await
    }

    /// Returns the address and locale of every owner of an organization who
    /// can act, ordered by address.
    ///
    /// This addresses operational mail, so an inactive owner must not appear:
    /// an unverified address has not been shown to belong to anyone, and
    /// mailing a disabled account tells a suspended operator what is happening
    /// in the organization. `DISTINCT` guards against an owner holding the
    /// role through more than one row.
    pub async fn active_organization_owners<'e, E>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<Vec<(String, String)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(&format!(
            "SELECT DISTINCT u.email, u.preferred_locale \
             FROM organization_memberships m \
             JOIN users u ON u.id = m.user_id \
             WHERE m.organization_id = $1 AND m.role = 'owner' AND {ACTIVE} \
             ORDER BY u.email"
        ))
        .bind(organization_id)
        .fetch_all(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ACTIVE, UserRepository};
    use sqlx::PgPool;
    use uuid::Uuid;

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef";

    async fn seed_user(pool: &PgPool, email: &str, verified: bool) -> Uuid {
        let id = Uuid::new_v4();
        if verified {
            UserRepository::insert_verified(pool, id, email, HASH, "en", "Person").await
        } else {
            UserRepository::insert_unverified(pool, id, email, HASH, "en", "Person").await
        }
        .unwrap();
        id
    }

    async fn disable(pool: &PgPool, id: Uuid) {
        sqlx::query("UPDATE users SET disabled_at=now() WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn grant_super_admin(pool: &PgPool, id: Uuid) {
        sqlx::query(
            "INSERT INTO platform_role_assignments(user_id,role,revoked_at) VALUES($1,'super_admin',NULL)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The two halves of [`ACTIVE`] are independent, so each has to be able to
    /// exclude an account on its own. A predicate that lost either conjunct
    /// would still pass a test that only ever disabled a verified account.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn each_half_of_the_active_predicate_excludes_on_its_own(pool: PgPool) {
        let active = seed_user(&pool, "active@example.test", true).await;
        let _unverified = seed_user(&pool, "unverified@example.test", false).await;
        let disabled = seed_user(&pool, "disabled@example.test", true).await;
        disable(&pool, disabled).await;

        for (email, expected) in [
            ("active@example.test", Some(active)),
            ("unverified@example.test", None),
            ("disabled@example.test", None),
            ("absent@example.test", None),
        ] {
            let mut tx = pool.begin().await.unwrap();
            assert_eq!(
                UserRepository::active_id_by_email_for_update(&mut *tx, email)
                    .await
                    .unwrap(),
                expected,
                "lookup of {email}"
            );
            tx.commit().await.unwrap();
        }
    }

    /// An account that cannot act still occupies its address. Treating
    /// "unusable" as "available" would let a second account be created for an
    /// address the first one holds, which the unique index would reject at a
    /// point the caller cannot report well.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn an_address_is_taken_even_by_an_account_that_cannot_act(pool: PgPool) {
        let disabled = seed_user(&pool, "disabled@example.test", true).await;
        disable(&pool, disabled).await;
        seed_user(&pool, "unverified@example.test", false).await;

        for email in ["disabled@example.test", "unverified@example.test"] {
            assert!(
                UserRepository::exists_by_email(&pool, email).await.unwrap(),
                "{email} must read as taken"
            );
        }
        assert!(
            !UserRepository::exists_by_email(&pool, "absent@example.test")
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_two_insert_paths_differ_only_in_verification(pool: PgPool) {
        let verified = seed_user(&pool, "verified@example.test", true).await;
        let unverified = seed_user(&pool, "unverified@example.test", false).await;

        let rows: Vec<(Uuid, Option<chrono::DateTime<chrono::Utc>>, String, String)> =
            sqlx::query_as(
                "SELECT id,email_verified_at,preferred_locale,display_name FROM users ORDER BY email",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
        let by_id = |id: Uuid| rows.iter().find(|row| row.0 == id).unwrap();
        assert!(by_id(verified).1.is_some());
        assert!(by_id(unverified).1.is_none());
        // Everything else is written the same way by both paths.
        assert_eq!(
            (by_id(verified).2.clone(), by_id(verified).3.clone()),
            ("en".to_owned(), "Person".to_owned())
        );
        assert_eq!(by_id(verified).2, by_id(unverified).2);
        assert_eq!(by_id(verified).3, by_id(unverified).3);
    }

    /// An installation whose only super administrator cannot act must read as
    /// having none, or onboarding hands it to whoever asks next.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_super_admin_who_cannot_act_does_not_count(pool: PgPool) {
        assert!(
            !UserRepository::active_super_admin_exists(&pool)
                .await
                .unwrap()
        );

        let unverified = seed_user(&pool, "unverified@example.test", false).await;
        grant_super_admin(&pool, unverified).await;
        assert!(
            !UserRepository::active_super_admin_exists(&pool)
                .await
                .unwrap(),
            "an unverified assignment must not claim the installation"
        );
        assert_eq!(
            UserRepository::active_super_admin_count(&pool)
                .await
                .unwrap(),
            0
        );

        let active = seed_user(&pool, "active@example.test", true).await;
        grant_super_admin(&pool, active).await;
        assert!(
            UserRepository::active_super_admin_exists(&pool)
                .await
                .unwrap()
        );
        assert_eq!(
            UserRepository::active_super_admin_count(&pool)
                .await
                .unwrap(),
            1,
            "the count must agree with the existence check"
        );

        // A revoked assignment stops counting, but the database refuses to
        // revoke the last active one: `protect_last_super_admin` in migration
        // 0027 restates this same predicate as a trigger, so an installation
        // cannot be locked out even if an application check is bypassed.
        let revoking_the_only_one =
            sqlx::query("UPDATE platform_role_assignments SET revoked_at=now() WHERE user_id=$1")
                .bind(active)
                .execute(&pool)
                .await;
        assert!(
            revoking_the_only_one.is_err(),
            "the database must refuse to revoke the last active super administrator"
        );

        let second = seed_user(&pool, "second@example.test", true).await;
        grant_super_admin(&pool, second).await;
        assert_eq!(
            UserRepository::active_super_admin_count(&pool)
                .await
                .unwrap(),
            2
        );
        sqlx::query("UPDATE platform_role_assignments SET revoked_at=now() WHERE user_id=$1")
            .bind(active)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            UserRepository::active_super_admin_count(&pool)
                .await
                .unwrap(),
            1,
            "a revoked assignment stops counting once another one remains"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn organization_owner_mail_reaches_only_owners_who_can_act(pool: PgPool) {
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Owners')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let owner = seed_user(&pool, "owner@example.test", true).await;
        let unverified_owner = seed_user(&pool, "pending@example.test", false).await;
        let disabled_owner = seed_user(&pool, "suspended@example.test", true).await;
        disable(&pool, disabled_owner).await;
        let member = seed_user(&pool, "member@example.test", true).await;
        for (user, role) in [
            (owner, "owner"),
            (unverified_owner, "owner"),
            (disabled_owner, "owner"),
            (member, "member"),
        ] {
            sqlx::query(
                "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
            )
            .bind(organization)
            .bind(user)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
        }

        assert_eq!(
            UserRepository::active_organization_owners(&pool, organization)
                .await
                .unwrap(),
            vec![("owner@example.test".to_owned(), "en".to_owned())],
            "only the owner who can act is addressable"
        );
    }

    /// The fragment is embedded into statements this module does not own, so a
    /// change to its text has to keep referring to both columns.
    #[test]
    fn the_active_fragment_names_both_conditions() {
        assert!(ACTIVE.contains("disabled_at"));
        assert!(ACTIVE.contains("email_verified_at"));
    }
}

#[cfg(test)]
mod account_statement_tests {
    use chrono::{DateTime, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::UserRepository;
    use crate::repository::MembershipRepository;
    use crate::repository::test_support::{tenant, user};

    const REPLACED_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$b3RoZXJzYWx0dmFsdWU$fedcba9876543210";
    const FIXTURE_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef";

    #[derive(Debug, FromRow)]
    struct Summary {
        id: Uuid,
        email_verified: bool,
        enabled: bool,
        is_super_admin: bool,
    }

    #[derive(Debug, FromRow)]
    struct SignIn {
        user_id: Uuid,
        password_hash: String,
        organization_id: Option<Uuid>,
        organization_slug: Option<String>,
        role: Option<String>,
        is_super_admin: bool,
        disabled_at: Option<DateTime<Utc>>,
        preferred_locale: String,
    }

    async fn summary(pool: &PgPool, id: Uuid) -> Summary {
        UserRepository::platform_page::<_, Summary>(pool, None, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.id == id)
            .unwrap()
    }

    async fn disabled_at(pool: &PgPool, id: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar("SELECT disabled_at FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// The platform page orders users by id after a cursor; disabling keeps
    /// the first disable time, and only an enabled, verified user is eligible
    /// for the super admin role.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn platform_reads_and_status_changes(pool: PgPool) {
        let mut ids = [user(&pool).await, user(&pool).await, user(&pool).await];
        ids.sort();
        let page: Vec<Summary> = UserRepository::platform_page(&pool, None, 2).await.unwrap();
        assert_eq!(page.iter().map(|s| s.id).collect::<Vec<_>>(), ids[..2]);
        let rest: Vec<Summary> = UserRepository::platform_page(&pool, Some(ids[1]), 2)
            .await
            .unwrap();
        assert_eq!(rest.iter().map(|s| s.id).collect::<Vec<_>>(), ids[2..]);
        let fresh = summary(&pool, ids[0]).await;
        assert!(fresh.email_verified && fresh.enabled && !fresh.is_super_admin);
        assert_eq!(
            UserRepository::password_hash(&pool, ids[0]).await.unwrap(),
            FIXTURE_HASH
        );

        let target = ids[0];
        assert!(
            UserRepository::eligible_for_super_admin(&pool, target)
                .await
                .unwrap()
        );
        let disabled: Summary = UserRepository::set_disabled(&pool, target, true)
            .await
            .unwrap()
            .unwrap();
        assert!(!disabled.enabled);
        let first = disabled_at(&pool, target).await;
        UserRepository::set_disabled::<_, Summary>(&pool, target, true)
            .await
            .unwrap();
        assert_eq!(
            disabled_at(&pool, target).await,
            first,
            "the first disable time stays"
        );
        assert!(
            !UserRepository::eligible_for_super_admin(&pool, target)
                .await
                .unwrap()
        );
        let enabled: Summary = UserRepository::set_disabled(&pool, target, false)
            .await
            .unwrap()
            .unwrap();
        assert!(enabled.enabled);
        assert!(
            UserRepository::set_disabled::<_, Summary>(&pool, Uuid::new_v4(), true)
                .await
                .unwrap()
                .is_none()
        );
        sqlx::query("UPDATE users SET email_verified_at=NULL WHERE id=$1")
            .bind(target)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !UserRepository::eligible_for_super_admin(&pool, target)
                .await
                .unwrap()
        );
    }

    /// Granting reinstates a revoked role, the last active super admin cannot
    /// be revoked, recovery grants without a granting user, and assigning
    /// inserts a fresh role only.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn super_admin_roles_are_granted_and_revoked(pool: PgPool) {
        let first = user(&pool).await;
        let second = user(&pool).await;
        UserRepository::assign_super_admin(&pool, first)
            .await
            .unwrap();
        let repeated = UserRepository::assign_super_admin(&pool, first)
            .await
            .unwrap_err();
        assert_eq!(
            repeated
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505")
        );
        UserRepository::grant_super_admin(&pool, second, first)
            .await
            .unwrap();
        assert!(summary(&pool, second).await.is_super_admin);
        let granted_by: Option<Uuid> = sqlx::query_scalar(
            "SELECT granted_by_user_id FROM platform_role_assignments WHERE user_id=$1",
        )
        .bind(second)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(granted_by, Some(first));

        let revoked = UserRepository::revoke_super_admin(&pool, second)
            .await
            .unwrap();
        let again = UserRepository::revoke_super_admin(&pool, second)
            .await
            .unwrap();
        assert_eq!((revoked.rows_affected(), again.rows_affected()), (1, 0));
        assert!(!summary(&pool, second).await.is_super_admin);
        let last = UserRepository::revoke_super_admin(&pool, first)
            .await
            .unwrap_err();
        assert_eq!(
            last.as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514"),
            "the last active super admin stays"
        );

        UserRepository::grant_super_admin(&pool, second, first)
            .await
            .unwrap();
        assert!(
            summary(&pool, second).await.is_super_admin,
            "a grant reinstates"
        );
        UserRepository::revoke_super_admin(&pool, second)
            .await
            .unwrap();
        UserRepository::recover_super_admin(&pool, second)
            .await
            .unwrap();
        let recovered: (Option<DateTime<Utc>>, Option<Uuid>) = sqlx::query_as(
            "SELECT revoked_at,granted_by_user_id FROM platform_role_assignments WHERE user_id=$1",
        )
        .bind(second)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(recovered, (None, None));
        let third = user(&pool).await;
        UserRepository::recover_super_admin(&pool, third)
            .await
            .unwrap();
        assert!(summary(&pool, third).await.is_super_admin);
    }

    /// The sign-in projection names the organization only when it is
    /// unambiguous: the one active organization by email, the requested one
    /// by id.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn sign_in_projections_resolve_the_organization(pool: PgPool) {
        let own = tenant(&pool, "users-sign-in").await;
        let second = tenant(&pool, "users-sign-in-second").await;
        let member = user(&pool).await;
        let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
            .bind(member)
            .fetch_one(&pool)
            .await
            .unwrap();
        let by_email = || async {
            UserRepository::sign_in_by_email::<_, SignIn>(&pool, &email)
                .await
                .unwrap()
                .unwrap()
        };
        let none = by_email().await;
        assert_eq!(none.user_id, member);
        assert_eq!(none.password_hash, FIXTURE_HASH);
        assert_eq!(none.organization_id, None);
        assert_eq!(none.preferred_locale, "en");
        assert!(!none.is_super_admin && none.disabled_at.is_none());

        MembershipRepository::insert_organization_role(&pool, own.organization_id, member, "admin")
            .await
            .unwrap();
        let one = by_email().await;
        assert_eq!(one.organization_id, Some(own.organization_id));
        assert_eq!(one.organization_slug.as_deref(), Some("users-sign-in"));
        assert_eq!(one.role.as_deref(), Some("admin"));

        MembershipRepository::insert_organization_role(
            &pool,
            second.organization_id,
            member,
            "member",
        )
        .await
        .unwrap();
        assert_eq!(by_email().await.organization_id, None, "two are ambiguous");
        let chosen: SignIn =
            UserRepository::sign_in_by_id(&pool, member, Some(second.organization_id))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(chosen.organization_id, Some(second.organization_id));
        assert_eq!(chosen.role.as_deref(), Some("member"));
        let unscoped: SignIn = UserRepository::sign_in_by_id(&pool, member, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unscoped.organization_id, None);
        assert!(
            UserRepository::sign_in_by_email::<_, SignIn>(&pool, "nobody@example.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Account updates: verification keeps its first time, the password hash
    /// is replaced, preferences keep the display name when none is given, and
    /// only an enabled user's email is read for update.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn account_updates(pool: PgPool) {
        let id = user(&pool).await;
        let verified_at = || async {
            sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
                "SELECT email_verified_at FROM users WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        sqlx::query("UPDATE users SET email_verified_at=NULL WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        UserRepository::mark_email_verified(&pool, id)
            .await
            .unwrap();
        let first = verified_at().await;
        assert!(first.is_some());
        UserRepository::mark_email_verified(&pool, id)
            .await
            .unwrap();
        assert_eq!(verified_at().await, first);

        UserRepository::set_password_hash(&pool, id, REPLACED_HASH.into())
            .await
            .unwrap();
        assert_eq!(
            UserRepository::password_hash(&pool, id).await.unwrap(),
            REPLACED_HASH
        );

        let (email, locale) = UserRepository::email_and_locale(&pool, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (email.as_str(), locale.as_str()),
            (format!("{id}@example.test").as_str(), "en")
        );
        UserRepository::update_preferences(&pool, id, "ru", Some("Ann".into()))
            .await
            .unwrap();
        UserRepository::update_preferences(&pool, id, "en", None)
            .await
            .unwrap();
        let (display_name, locale): (String, String) =
            sqlx::query_as("SELECT display_name,preferred_locale FROM users WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((display_name.as_str(), locale.as_str()), ("Ann", "en"));
        assert!(
            UserRepository::email_and_locale(&pool, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );

        let mut tx = pool.begin().await.unwrap();
        UserRepository::lock(&mut *tx, id).await.unwrap();
        let active = UserRepository::active_email_for_update(&mut *tx, id)
            .await
            .unwrap();
        assert_eq!(active.map(|(e, v)| (e, v.is_some())), Some((email, true)));
        tx.commit().await.unwrap();
        UserRepository::set_disabled::<_, Summary>(&pool, id, true)
            .await
            .unwrap();
        assert!(
            UserRepository::active_email_for_update(&pool, id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The setup lock is held for the rest of the transaction.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_setup_lock_is_held_until_commit(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        UserRepository::lock_setup(&mut *tx).await.unwrap();
        let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(1869373291)")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!taken);
        tx.commit().await.unwrap();
        let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(1869373291)")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(free);
    }
}
