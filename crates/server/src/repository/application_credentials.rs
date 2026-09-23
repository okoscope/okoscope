//! Application ingestion credentials: the bearer tokens agents present to
//! report events for one application. Only a digest of each token is stored.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Application ingestion credentials.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationCredentialRepository;

impl ApplicationCredentialRepository {
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
