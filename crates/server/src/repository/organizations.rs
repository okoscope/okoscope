//! Organization-scoped persistence.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Queries against the `organizations` table.
#[derive(Clone, Copy, Debug)]
pub struct OrganizationRepository;

impl OrganizationRepository {
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
    use super::OrganizationRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

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
