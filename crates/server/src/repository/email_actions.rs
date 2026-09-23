//! One-time email actions: the email verification and password reset links
//! mailed to a user. Only a digest of each token is stored; an action is live
//! until it is consumed, revoked or expires.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// One-time email actions: verification and password reset tokens.
#[derive(Clone, Copy, Debug)]
pub struct EmailActionRepository;

impl EmailActionRepository {
    /// Revokes the user's live actions of this purpose.
    pub async fn revoke_pending<'e, E>(
        executor: E,
        user_id: Uuid,
        purpose: &str,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE user_email_actions SET revoked_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL AND revoked_at IS NULL")
            .bind(user_id)
            .bind(purpose)
            .execute(executor)
            .await
    }

    /// Stores a new action by the digest of its token.
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        user_id: Uuid,
        purpose: &str,
        token_digest: Vec<u8>,
        expires_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO user_email_actions(id,user_id,purpose,token_digest,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(id)
            .bind(user_id)
            .bind(purpose)
            .bind(token_digest)
            .bind(expires_at)
            .execute(executor)
            .await
    }

    /// Reports whether the user was sent an action of this purpose within the
    /// last `cooldown_seconds`.
    pub async fn cooling_down<'e, E>(
        executor: E,
        user_id: Uuid,
        purpose: &str,
        cooldown_seconds: f64,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM user_email_actions WHERE user_id=$1 AND purpose=$2 AND created_at>now()-make_interval(secs=>$3))")
            .bind(user_id)
            .bind(purpose)
            .bind(cooldown_seconds)
            .fetch_one(executor)
            .await
    }

    /// Revokes the user's live email verification actions.
    pub async fn revoke_pending_verifications<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE user_email_actions SET revoked_at=now() WHERE user_id=$1 AND purpose='verify_email' AND consumed_at IS NULL AND revoked_at IS NULL")
            .bind(user_id)
            .execute(executor)
            .await
    }

    /// Consumes the live action of this purpose whose token hashes to
    /// `token_digest`, returning its user. `None` when there is none.
    pub async fn consume<'e, E>(
        executor: E,
        token_digest: Vec<u8>,
        purpose: &str,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("UPDATE user_email_actions SET consumed_at=now() WHERE id=(SELECT id FROM user_email_actions WHERE token_digest=$1 AND purpose=$2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE) RETURNING user_id")
            .bind(token_digest)
            .bind(purpose)
            .fetch_optional(executor)
            .await
    }

    /// Revokes all of the user's live actions.
    pub async fn revoke_all_pending<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE user_email_actions SET revoked_at=coalesce(revoked_at,now()) WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL")
            .bind(user_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::EmailActionRepository;
    use crate::repository::test_support::user;

    async fn issue(pool: &PgPool, user_id: Uuid, purpose: &str, digest: u8) -> Uuid {
        let id = Uuid::new_v4();
        EmailActionRepository::insert(
            pool,
            id,
            user_id,
            purpose,
            vec![digest; 32],
            Utc::now() + Duration::hours(1),
        )
        .await
        .unwrap();
        id
    }

    async fn live(pool: &PgPool, user_id: Uuid) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT purpose FROM user_email_actions WHERE user_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY purpose",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// An action is consumed once, by its token digest and purpose, while it
    /// is live.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn an_action_is_consumed_once_while_live(pool: PgPool) {
        let owner = user(&pool).await;
        issue(&pool, owner, "reset_password", 1).await;
        assert_eq!(
            EmailActionRepository::consume(&pool, vec![1; 32], "verify_email")
                .await
                .unwrap(),
            None,
            "the purpose must match"
        );
        assert_eq!(
            EmailActionRepository::consume(&pool, vec![1; 32], "reset_password")
                .await
                .unwrap(),
            Some(owner)
        );
        assert_eq!(
            EmailActionRepository::consume(&pool, vec![1; 32], "reset_password")
                .await
                .unwrap(),
            None
        );

        let expired = issue(&pool, owner, "reset_password", 2).await;
        sqlx::query(
            "UPDATE user_email_actions SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(expired)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            EmailActionRepository::consume(&pool, vec![2; 32], "reset_password")
                .await
                .unwrap(),
            None
        );
    }

    /// Revocation narrows by purpose, by verification, or takes everything
    /// live; the cooldown sees any recent action of the purpose.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn revocation_and_cooldown(pool: PgPool) {
        let owner = user(&pool).await;
        let other = user(&pool).await;
        let cooling = |purpose: &'static str| {
            let pool = pool.clone();
            async move {
                EmailActionRepository::cooling_down(&pool, owner, purpose, 60.0)
                    .await
                    .unwrap()
            }
        };
        assert!(!cooling("verify_email").await);
        issue(&pool, owner, "verify_email", 1).await;
        issue(&pool, owner, "reset_password", 2).await;
        issue(&pool, other, "verify_email", 3).await;
        assert!(cooling("verify_email").await);
        sqlx::query("UPDATE user_email_actions SET created_at=now()-interval '2 minutes',expires_at=now()+interval '1 hour' WHERE user_id=$1")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!cooling("verify_email").await, "outside the window");

        EmailActionRepository::revoke_pending(&pool, owner, "reset_password")
            .await
            .unwrap();
        assert_eq!(live(&pool, owner).await, ["verify_email"]);
        EmailActionRepository::revoke_pending_verifications(&pool, owner)
            .await
            .unwrap();
        assert!(live(&pool, owner).await.is_empty());
        assert_eq!(
            live(&pool, other).await,
            ["verify_email"],
            "others keep theirs"
        );

        issue(&pool, owner, "verify_email", 4).await;
        issue(&pool, owner, "reset_password", 5).await;
        EmailActionRepository::revoke_all_pending(&pool, owner)
            .await
            .unwrap();
        assert!(live(&pool, owner).await.is_empty());
        assert_eq!(live(&pool, other).await, ["verify_email"]);
    }
}
