//! Project-scoped persistence.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Queries against the `projects` table.
#[derive(Clone, Copy, Debug)]
pub struct ProjectRepository;

impl ProjectRepository {
    /// Returns the organization owning the project, or `None` when no such
    /// project exists.
    ///
    /// This is the entry point for resolving a tenant from a project path
    /// segment. Callers authorize the resulting organization before using it;
    /// the lookup itself is deliberately unauthenticated, because the caller
    /// needs the organization in order to run that authorization.
    pub async fn organization_of<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT organization_id FROM projects WHERE id = $1
            "#,
        )
        .bind(project_id)
        .fetch_optional(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::ProjectRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn resolves_the_owning_organization(pool: PgPool) {
        let organization = Uuid::new_v4();
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(project)
            .bind(organization)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            ProjectRepository::organization_of(&pool, project)
                .await
                .unwrap(),
            Some(organization)
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn reports_an_unknown_project_as_absent(pool: PgPool) {
        assert_eq!(
            ProjectRepository::organization_of(&pool, Uuid::new_v4())
                .await
                .unwrap(),
            None
        );
    }
}
