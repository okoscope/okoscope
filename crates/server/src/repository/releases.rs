//! Release persistence.
//!
//! A release belongs to an application, so every lookup here is scoped by the
//! full path — organization, project, application — and that path was restated
//! as three positional `Uuid` binds at five call sites. [`ApplicationScope`]
//! carries it as one value, the way [`crate::repository::GroupKey`] carries a
//! group's identity.
//!
//! # What is not here
//!
//! Creation stays with the code that owns each kind of release. A manual
//! release is created by the releases API, whose statement returns a joined
//! projection for its response; an observed release is created by
//! [`crate::release_discovery`] under its own advisory lock and conflict
//! protocol. The release listings and the diff queries in [`crate::attention`]
//! are endpoint-specific projections.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// The tenant path of an application, which scopes every release lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
}

/// Scalar subqueries aggregating an application's releases.
pub mod aggregates {
    /// Counts the releases of an application. Expects `applications` aliased
    /// as `a`.
    ///
    /// Carries the full tenant path. One of its three call sites matched on
    /// `application_id` alone; the composite foreign key makes that equivalent,
    /// so the count does not change.
    pub const COUNT_FOR_APPLICATION: &str = "(SELECT count(*) FROM releases r \
         WHERE r.organization_id=a.organization_id AND r.project_id=a.project_id \
           AND r.application_id=a.id)";
}

/// Queries against the `releases` table.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseRepository;

impl ReleaseRepository {
    /// Reports whether the release belongs to the application.
    ///
    /// `false` covers a release of another application as well as one that
    /// does not exist, so a caller filtering by release cannot reach another
    /// tenant's.
    pub async fn exists<'e, E>(
        executor: E,
        scope: ApplicationScope,
        release_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS(SELECT 1 FROM releases
                          WHERE organization_id = $1 AND project_id = $2
                            AND application_id = $3 AND id = $4)
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(release_id)
        .fetch_one(executor)
        .await
    }

    /// Resolves a release id used as a pagination cursor into the key the
    /// release listings are ordered by, `(deployed_at, id)`.
    ///
    /// Two listings — the releases API and the inventory release presence —
    /// page over an application's releases newest first and each looked this
    /// up separately. `None` means the cursor names no release of this
    /// application, which callers report as an invalid cursor.
    pub async fn cursor<'e, E>(
        executor: E,
        scope: ApplicationScope,
        release_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT deployed_at, id FROM releases
            WHERE organization_id = $1 AND project_id = $2
              AND application_id = $3 AND id = $4
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(release_id)
        .fetch_optional(executor)
        .await
    }

    /// Returns the release of the application with this version string.
    ///
    /// Versions are unique per application (`UNIQUE (application_id,
    /// version)`), so there is at most one. Ingestion uses this to attribute an
    /// event to the release its agent reported.
    pub async fn id_by_version<'e, E>(
        executor: E,
        scope: ApplicationScope,
        version: &str,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM releases
            WHERE organization_id = $1 AND project_id = $2
              AND application_id = $3 AND version = $4
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(version)
        .fetch_optional(executor)
        .await
    }

    /// Returns the observed release with this workload identity.
    ///
    /// Only observed releases carry an identity — the check constraint keeps
    /// it null on manual ones — so no `source` filter is needed to exclude
    /// them.
    pub async fn id_by_identity<'e, E>(
        executor: E,
        scope: ApplicationScope,
        identity_version: i16,
        identity_digest: &[u8],
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM releases
            WHERE organization_id = $1 AND project_id = $2 AND application_id = $3
              AND identity_version = $4 AND identity_digest = $5
            "#,
        )
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(identity_version)
        .bind(identity_digest)
        .fetch_optional(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationScope, ReleaseRepository, aggregates};
    use crate::repository::{ApplicationRepository, ProjectRepository};
    use chrono::{DateTime, Duration, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn seed_application(pool: &PgPool) -> ApplicationScope {
        let organization = Uuid::new_v4();
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Releases')")
            .bind(organization)
            .bind(organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        let project = Uuid::new_v4();
        ProjectRepository::insert(pool, project, organization, &project.to_string(), "P")
            .await
            .unwrap()
            .unwrap();
        let application = ApplicationRepository::insert(pool, Uuid::new_v4(), project, "a", "A")
            .await
            .unwrap()
            .unwrap()
            .id;
        ApplicationScope {
            organization_id: organization,
            project_id: project,
            application_id: application,
        }
    }

    async fn manual(
        pool: &PgPool,
        scope: ApplicationScope,
        version: &str,
        at: DateTime<Utc>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) \
             VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(version)
        .bind(at)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// A release id from another application must not pass for this one, in
    /// the existence check or as a pagination cursor.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_release_is_visible_only_through_its_own_application(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        let deployed_at = Utc::now() - Duration::hours(1);
        let release = manual(&pool, scope, "1.0.0", deployed_at).await;
        let foreign = manual(&pool, other, "1.0.0", deployed_at).await;

        assert!(
            ReleaseRepository::exists(&pool, scope, release)
                .await
                .unwrap()
        );
        assert!(
            !ReleaseRepository::exists(&pool, scope, foreign)
                .await
                .unwrap(),
            "another application's release must not pass"
        );

        let (at, id) = ReleaseRepository::cursor(&pool, scope, release)
            .await
            .unwrap()
            .expect("own release resolves");
        assert_eq!(
            (at.timestamp_micros(), id),
            (deployed_at.timestamp_micros(), release)
        );
        assert!(
            ReleaseRepository::cursor(&pool, scope, foreign)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The same version string in two applications names two releases.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_version_resolves_within_its_application_only(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        let release = manual(&pool, scope, "2.1.0", Utc::now()).await;
        let foreign = manual(&pool, other, "2.1.0", Utc::now()).await;

        assert_eq!(
            ReleaseRepository::id_by_version(&pool, scope, "2.1.0")
                .await
                .unwrap(),
            Some(release)
        );
        assert_eq!(
            ReleaseRepository::id_by_version(&pool, other, "2.1.0")
                .await
                .unwrap(),
            Some(foreign)
        );
        assert_eq!(
            ReleaseRepository::id_by_version(&pool, scope, "9.9.9")
                .await
                .unwrap(),
            None
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn an_identity_resolves_to_its_observed_release(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let digest = [4u8; 32];
        let observed = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at,\
             source,identity_version,identity_digest,identity_components) \
             VALUES($1,$2,$3,$4,$5,now(),'observed',1,$6,'[\"container\"]'::jsonb)",
        )
        .bind(observed)
        .bind(scope.organization_id)
        .bind(scope.project_id)
        .bind(scope.application_id)
        .bind(format!("sha256:{}", hex::encode(digest)))
        .bind(digest.as_slice())
        .execute(&pool)
        .await
        .unwrap();
        manual(&pool, scope, "manual", Utc::now()).await;

        assert_eq!(
            ReleaseRepository::id_by_identity(&pool, scope, 1, &digest)
                .await
                .unwrap(),
            Some(observed)
        );
        assert_eq!(
            ReleaseRepository::id_by_identity(&pool, scope, 2, &digest)
                .await
                .unwrap(),
            None,
            "the identity version is part of the key"
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_count_fragment_counts_an_applications_releases(pool: PgPool) {
        let scope = seed_application(&pool).await;
        let other = seed_application(&pool).await;
        manual(&pool, scope, "1", Utc::now()).await;
        manual(&pool, scope, "2", Utc::now()).await;
        manual(&pool, other, "1", Utc::now()).await;

        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT {} FROM applications a WHERE a.id=$1",
            aggregates::COUNT_FOR_APPLICATION
        ))
        .bind(scope.application_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
    }
}
