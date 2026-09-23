//! Application-scoped persistence.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Queries against the `applications` table.
///
/// Every method takes the full tenant path (organization, project,
/// application). Narrowing an application lookup to fewer than all three
/// columns would let a caller reach an application owned by another tenant, so
/// the repository does not expose such a query.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationRepository;

impl ApplicationRepository {
    /// Reports whether the application exists within the given tenant scope.
    ///
    /// A `false` result is indistinguishable from "exists but belongs to
    /// another tenant" by design: callers map both onto `404` so that the API
    /// does not disclose the existence of other tenants' applications.
    pub async fn exists<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM applications
                WHERE organization_id = $1
                  AND project_id = $2
                  AND id = $3
            )
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_one(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        let application = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(project)
            .bind(organization)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'a','A')",
        )
        .bind(application)
        .bind(organization)
        .bind(project)
        .execute(pool)
        .await
        .unwrap();
        (organization, project, application)
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn exists_within_the_owning_tenant(pool: PgPool) {
        let (organization, project, application) = seed(&pool).await;
        assert!(
            ApplicationRepository::exists(&pool, organization, project, application)
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn hides_an_application_from_a_foreign_tenant(pool: PgPool) {
        let (organization, project, application) = seed(&pool).await;
        let (other_organization, other_project, _) = seed(&pool).await;

        // A mismatch in any segment of the tenant path must read as absent,
        // otherwise one tenant could probe another tenant's identifiers.
        assert!(
            !ApplicationRepository::exists(&pool, other_organization, project, application)
                .await
                .unwrap()
        );
        assert!(
            !ApplicationRepository::exists(&pool, organization, other_project, application)
                .await
                .unwrap()
        );
        assert!(
            !ApplicationRepository::exists(&pool, organization, project, Uuid::new_v4())
                .await
                .unwrap()
        );
    }
}
