//! Session persistence.
//!
//! Almost everything written to `user_sessions` after creation is a
//! revocation, and revocation was restated at nine call sites in four shapes:
//! by session id, by token digest, for every session a user holds, and for a
//! user's sessions within one organization.
//!
//! All but one wrote `revoked_at = coalesce(revoked_at, now())`. The exception,
//! in the password-change path, wrote `revoked_at = now()` and would overwrite
//! the moment a session was first revoked had it already been. The difference
//! only shows when two requests revoke the same session concurrently, but the
//! first-revocation time is what an investigator reads to learn when access
//! actually ended, so every path here preserves it.
//!
//! # What is not here
//!
//! The session guard in [`crate::auth`] validates a token, touches
//! `last_used_at`, and projects the caller's organization role in one
//! `UPDATE … RETURNING` that joins users and memberships and correlates through
//! the session row itself. It is the authentication decision, not a lookup, and
//! splitting it would put the check and its effect in separate statements.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Queries against the `user_sessions` table.
#[derive(Clone, Copy, Debug)]
pub struct SessionRepository;

impl SessionRepository {
    /// Records a new session under the digest of its token.
    ///
    /// Only the digest is stored. The plaintext token goes to the client once
    /// and is never persisted, so a copy of this table does not grant access.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E>(
        executor: E,
        session_id: Uuid,
        user_id: Uuid,
        organization_id: Option<Uuid>,
        token_digest: &[u8],
        expires_at: DateTime<Utc>,
        privileged_until: Option<DateTime<Utc>>,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            INSERT INTO user_sessions(id, user_id, organization_id, token_hash,
                                      expires_at, privileged_until)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(organization_id)
        .bind(token_digest)
        .bind(expires_at)
        .bind(privileged_until)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Revokes one session.
    ///
    /// Idempotent, and a session already revoked keeps its original
    /// `revoked_at`: see the module documentation for why that timestamp is
    /// not allowed to move.
    pub async fn revoke<'e, E>(executor: E, session_id: Uuid) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE user_sessions SET revoked_at = coalesce(revoked_at, now())
            WHERE id = $1
            "#,
        )
        .bind(session_id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Revokes the session a client presented, identified by the digest of
    /// its token.
    ///
    /// This is the sign-out path and the replace-on-sign-in path, where the
    /// caller holds a token rather than a session id. An unknown digest is not
    /// an error: signing out with a token that no longer matches anything has
    /// nothing left to do.
    pub async fn revoke_by_token_digest<'e, E>(
        executor: E,
        token_digest: &[u8],
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE user_sessions SET revoked_at = coalesce(revoked_at, now())
            WHERE token_hash = $1
            "#,
        )
        .bind(token_digest)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Revokes every session a user holds, optionally sparing one.
    ///
    /// Disabling an account passes `None`: nothing of it may stay signed in.
    /// A password change passes the session that made the request, so the
    /// person changing their password is not signed out by doing so while
    /// every other device is.
    pub async fn revoke_all_for_user<'e, E>(
        executor: E,
        user_id: Uuid,
        except_session: Option<Uuid>,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE user_sessions SET revoked_at = coalesce(revoked_at, now())
            WHERE user_id = $1 AND ($2::uuid IS NULL OR id <> $2)
            "#,
        )
        .bind(user_id)
        .bind(except_session)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Revokes a user's sessions scoped to one organization.
    ///
    /// Removing someone from an organization ends the sessions they opened
    /// inside it and leaves their other organizations alone. A session with no
    /// organization is not touched; it never carried this organization's
    /// authority.
    pub async fn revoke_for_user_in_organization<'e, E>(
        executor: E,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE user_sessions SET revoked_at = coalesce(revoked_at, now())
            WHERE user_id = $1 AND organization_id = $2
            "#,
        )
        .bind(user_id)
        .bind(organization_id)
        .execute(executor)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SessionRepository;
    use chrono::{DateTime, Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed_user(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
        )
        .bind(id)
        .bind(format!("{id}@example.test"))
        .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef")
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn seed_organization(pool: &PgPool, user: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Sessions')")
            .bind(id)
            .bind(id.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
        )
        .bind(id)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn open(pool: &PgPool, user: Uuid, organization: Option<Uuid>) -> (Uuid, [u8; 32]) {
        let id = Uuid::new_v4();
        // Any unique 32 bytes will do; the repository never sees a plaintext.
        let mut full = [0u8; 32];
        full[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        full[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        SessionRepository::insert(
            pool,
            id,
            user,
            organization,
            &full,
            Utc::now() + Duration::hours(1),
            None,
        )
        .await
        .unwrap();
        (id, full)
    }

    async fn revoked_at(pool: &PgPool, session: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar("SELECT revoked_at FROM user_sessions WHERE id=$1")
            .bind(session)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// The first revocation time records when access actually ended. Revoking
    /// again — from a concurrent request, or a later cleanup — must not move it.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_repeated_revocation_keeps_the_first_timestamp(pool: PgPool) {
        let user = seed_user(&pool).await;
        let (session, digest) = open(&pool, user, None).await;

        SessionRepository::revoke(&pool, session).await.unwrap();
        let first = revoked_at(&pool, session).await.expect("revoked");
        // Make any later now() observably different.
        sqlx::query("SELECT pg_sleep(0.02)")
            .execute(&pool)
            .await
            .unwrap();

        SessionRepository::revoke(&pool, session).await.unwrap();
        SessionRepository::revoke_by_token_digest(&pool, &digest)
            .await
            .unwrap();
        SessionRepository::revoke_all_for_user(&pool, user, None)
            .await
            .unwrap();
        assert_eq!(
            revoked_at(&pool, session).await,
            Some(first),
            "every revocation path must preserve the first timestamp"
        );
    }

    /// Changing a password signs out every other device and keeps the one that
    /// made the change.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn revoking_all_but_one_spares_exactly_that_one(pool: PgPool) {
        let user = seed_user(&pool).await;
        let other_user = seed_user(&pool).await;
        let (current, _) = open(&pool, user, None).await;
        let (laptop, _) = open(&pool, user, None).await;
        let (phone, _) = open(&pool, user, None).await;
        let (someone_else, _) = open(&pool, other_user, None).await;

        SessionRepository::revoke_all_for_user(&pool, user, Some(current))
            .await
            .unwrap();

        assert!(revoked_at(&pool, current).await.is_none());
        assert!(revoked_at(&pool, laptop).await.is_some());
        assert!(revoked_at(&pool, phone).await.is_some());
        assert!(
            revoked_at(&pool, someone_else).await.is_none(),
            "another user's sessions are out of scope"
        );
    }

    /// Leaving an organization ends the sessions opened inside it, and nothing
    /// else — not the user's other organizations, and not a session that never
    /// carried an organization at all.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn organization_revocation_stays_inside_the_organization(pool: PgPool) {
        let user = seed_user(&pool).await;
        let left = seed_organization(&pool, user).await;
        let kept = seed_organization(&pool, user).await;
        let (in_left, _) = open(&pool, user, Some(left)).await;
        let (in_kept, _) = open(&pool, user, Some(kept)).await;
        let (unscoped, _) = open(&pool, user, None).await;

        SessionRepository::revoke_for_user_in_organization(&pool, user, left)
            .await
            .unwrap();

        assert!(revoked_at(&pool, in_left).await.is_some());
        assert!(revoked_at(&pool, in_kept).await.is_none());
        assert!(revoked_at(&pool, unscoped).await.is_none());
    }

    /// Signing out with a token that matches nothing is not an error, and a
    /// matching one revokes only its own session.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn revoking_by_digest_touches_only_the_presented_session(pool: PgPool) {
        let user = seed_user(&pool).await;
        let (presented, digest) = open(&pool, user, None).await;
        let (other, _) = open(&pool, user, None).await;

        SessionRepository::revoke_by_token_digest(&pool, &[0u8; 32])
            .await
            .unwrap();
        assert!(revoked_at(&pool, presented).await.is_none());

        SessionRepository::revoke_by_token_digest(&pool, &digest)
            .await
            .unwrap();
        assert!(revoked_at(&pool, presented).await.is_some());
        assert!(revoked_at(&pool, other).await.is_none());
    }
}
