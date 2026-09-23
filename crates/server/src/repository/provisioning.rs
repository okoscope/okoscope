//! Provisioning idempotency keys: each key reserves one operation's result,
//! so a retried request with the same key and body replays it. Keys and
//! request fingerprints are stored as SHA-256 digests.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Idempotency keys of the provisioning API.
#[derive(Clone, Copy, Debug)]
pub struct ProvisioningKeyRepository;

impl ProvisioningKeyRepository {
    /// Reserves an idempotency key for an operation, returning the
    /// reservation id, or `None` when the key is already reserved.
    pub async fn reserve<'e, E>(
        executor: E,
        reservation_id: Uuid,
        operation: &str,
        key_hash: &[u8],
        request_fingerprint: &[u8],
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO provisioning_idempotency_keys(id,operation,key_hash,request_fingerprint) VALUES($1,$2,$3,$4) ON CONFLICT(operation,key_hash) DO NOTHING RETURNING id")
            .bind(reservation_id)
            .bind(operation)
            .bind(key_hash)
            .bind(request_fingerprint)
            .fetch_optional(executor)
            .await
    }

    /// The request fingerprint an idempotency key was reserved with, and the
    /// resource it produced once completed.
    pub async fn reservation<'e, E>(
        executor: E,
        operation: &str,
        key_hash: &[u8],
    ) -> Result<(Vec<u8>, Option<Uuid>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Vec<u8>, Option<Uuid>)>("SELECT request_fingerprint,resource_id FROM provisioning_idempotency_keys WHERE operation=$1 AND key_hash=$2")
            .bind(operation)
            .bind(key_hash)
            .fetch_one(executor)
            .await
    }

    /// Records the resource a reserved key produced.
    pub async fn complete<'e, E>(
        executor: E,
        resource_id: Uuid,
        reservation_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE provisioning_idempotency_keys SET resource_id=$1 WHERE id=$2")
            .bind(resource_id)
            .bind(reservation_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::ProvisioningKeyRepository;

    /// A key is reserved once per operation, and its reservation reports the
    /// fingerprint and, once completed, the resource.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_key_is_reserved_once_and_completed(pool: PgPool) {
        let reservation = Uuid::new_v4();
        let reserve = |id: Uuid, operation: &'static str| {
            let pool = pool.clone();
            async move {
                ProvisioningKeyRepository::reserve(&pool, id, operation, &[1; 32], &[2; 32])
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            reserve(reservation, "create_project").await,
            Some(reservation)
        );
        assert_eq!(reserve(Uuid::new_v4(), "create_project").await, None);
        assert!(
            reserve(Uuid::new_v4(), "create_application")
                .await
                .is_some()
        );

        let read = || ProvisioningKeyRepository::reservation(&pool, "create_project", &[1; 32]);
        assert_eq!(read().await.unwrap(), (vec![2; 32], None));
        let resource = Uuid::new_v4();
        ProvisioningKeyRepository::complete(&pool, resource, reservation)
            .await
            .unwrap();
        assert_eq!(read().await.unwrap(), (vec![2; 32], Some(resource)));
    }
}
