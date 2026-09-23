//! Application ingestion credentials: the bearer tokens agents present to
//! report events for one application. Only a digest of each token is stored.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Application ingestion credentials.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationCredentialRepository;

impl ApplicationCredentialRepository {
    /// Records a credential by the digest of its token.
    ///
    /// Selects `id`, `name`, `token_hint`, `created_at`, `last_used_at` and
    /// `revoked_at`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E, T>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        name: &str,
        credential_hash: &[u8],
        token_hint: &str,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("INSERT INTO application_ingestion_credentials(id,organization_id,project_id,application_id,name,credential_hash,token_hint) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,token_hint,created_at,last_used_at,revoked_at")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(name)
            .bind(credential_hash)
            .bind(token_hint)
            .fetch_one(executor)
            .await
    }

    /// The application's credentials with the columns of [`Self::insert`].
    pub async fn list<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,name,token_hint,created_at,last_used_at,revoked_at FROM application_ingestion_credentials WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 ORDER BY created_at,id")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_all(executor)
            .await
    }

    /// Revokes one of the application's credentials, keeping an earlier
    /// revocation, and returns when it was revoked.
    pub async fn revoke_in_application<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        credential_id: Uuid,
    ) -> Result<Option<Option<DateTime<Utc>>>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Option<DateTime<Utc>>>("UPDATE application_ingestion_credentials SET revoked_at=coalesce(revoked_at,now()) WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 RETURNING revoked_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(credential_id)
            .fetch_optional(executor)
            .await
    }

    /// Resolves an unrevoked credential by its hash into its id and tenant
    /// path, recording that it was used.
    pub async fn authenticate<'e, E>(
        executor: E,
        credential_hash: &[u8],
    ) -> Result<Option<(Uuid, Uuid, Uuid, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid)>("UPDATE application_ingestion_credentials SET last_used_at=now() WHERE credential_hash=$1 AND revoked_at IS NULL RETURNING id,organization_id,project_id,application_id")
            .bind(credential_hash)
            .fetch_optional(executor)
            .await
    }

    /// Reports whether the credential still belongs to the application and
    /// is not revoked.
    pub async fn is_active<'e, E>(
        executor: E,
        credential_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM application_ingestion_credentials WHERE id=$1 AND organization_id=$2 AND project_id=$3 AND application_id=$4 AND revoked_at IS NULL)")
            .bind(credential_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// Revokes a credential, keeping an earlier revocation time.
    pub async fn revoke<'e, E>(
        executor: E,
        credential_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE application_ingestion_credentials SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1")
            .bind(credential_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use sqlx::FromRow;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::ApplicationCredentialRepository;
    use crate::repository::test_support::tenant;

    #[derive(Debug, FromRow)]
    struct Summary {
        id: Uuid,
        name: String,
        token_hint: String,
        last_used_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    }

    /// Credentials authenticate by hash while unrevoked, recording use, and
    /// revoke once, keeping the first revocation.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn credentials_authenticate_until_revoked(pool: PgPool) {
        let own = tenant(&pool, "credentials-lifecycle").await;
        let other = tenant(&pool, "credentials-lifecycle-other").await;
        let created: Summary = ApplicationCredentialRepository::insert(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            own.application_id,
            "ci",
            &[4; 32],
            "okt_…abcd",
        )
        .await
        .unwrap();
        assert_eq!(
            (created.name.as_str(), created.token_hint.as_str()),
            ("ci", "okt_…abcd")
        );
        assert!(created.last_used_at.is_none() && created.revoked_at.is_none());
        let active = |organization_id: Uuid| {
            let pool = pool.clone();
            async move {
                ApplicationCredentialRepository::is_active(
                    &pool,
                    created.id,
                    organization_id,
                    own.project_id,
                    own.application_id,
                )
                .await
                .unwrap()
            }
        };
        assert!(active(own.organization_id).await);
        assert!(!active(other.organization_id).await);

        assert_eq!(
            ApplicationCredentialRepository::authenticate(&pool, &[4; 32])
                .await
                .unwrap(),
            Some((
                created.id,
                own.organization_id,
                own.project_id,
                own.application_id
            ))
        );
        assert_eq!(
            ApplicationCredentialRepository::authenticate(&pool, &[5; 32])
                .await
                .unwrap(),
            None
        );
        let listed: Vec<Summary> = ApplicationCredentialRepository::list(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        let installer = listed.iter().find(|c| c.id == created.id).unwrap();
        assert!(
            installer.last_used_at.is_some(),
            "authentication records use"
        );

        let revoke = || {
            ApplicationCredentialRepository::revoke_in_application(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                created.id,
            )
        };
        let first = revoke().await.unwrap().flatten();
        assert!(first.is_some());
        assert_eq!(
            revoke().await.unwrap().flatten(),
            first,
            "the first revocation stays"
        );
        assert!(!active(own.organization_id).await);
        assert_eq!(
            ApplicationCredentialRepository::authenticate(&pool, &[4; 32])
                .await
                .unwrap(),
            None,
            "a revoked credential does not authenticate"
        );
        assert_eq!(
            ApplicationCredentialRepository::revoke_in_application(
                &pool,
                other.organization_id,
                other.project_id,
                other.application_id,
                created.id,
            )
            .await
            .unwrap(),
            None
        );
    }
}
