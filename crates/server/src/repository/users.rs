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
//! What is deliberately absent: the sign-in projections in
//! [`crate::user_auth`], which join memberships and organizations to build one
//! endpoint's response, and the single-column reads (`password_hash` for a
//! re-authentication, `preferred_locale` for an email) that share nothing but
//! the table name.

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
