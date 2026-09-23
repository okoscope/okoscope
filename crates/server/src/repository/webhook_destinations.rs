//! Webhook destinations: where a project's notifications are delivered, each
//! with an encrypted signing secret and an optimistic-concurrency revision.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Webhook destinations of projects.
#[derive(Clone, Copy, Debug)]
pub struct WebhookDestinationRepository;

impl WebhookDestinationRepository {
    /// How many destinations are enabled across all projects.
    pub async fn enabled_count<'e, E>(executor: E) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM webhook_destinations WHERE enabled=true")
            .fetch_one(executor)
            .await
    }

    /// The project's enabled destinations by id.
    ///
    /// Selects `id` and `deliver_backfill`.
    pub async fn enabled_for_project<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,deliver_backfill FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND enabled=true ORDER BY id")
            .bind(organization_id)
            .bind(project_id)
            .fetch_all(executor)
            .await
    }

    /// The project's destinations, newest first.
    ///
    /// Selects `id`, `project_id`, `name`, `url`, `enabled`,
    /// `deliver_backfill`, `revision`, `created_at`, `updated_at` and
    /// `disabled_at`.
    pub async fn list<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 ORDER BY created_at DESC,id DESC")
            .bind(organization_id)
            .bind(project_id)
            .fetch_all(executor)
            .await
    }

    /// One destination of the project with the columns of [`Self::list`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .fetch_optional(executor)
            .await
    }

    /// Where and how to deliver to a destination.
    ///
    /// Selects `id`, `url`, `enabled`, `encrypted_secret` and `secret_nonce`.
    pub async fn target<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,url,enabled,encrypted_secret,secret_nonce FROM webhook_destinations WHERE organization_id=$1 AND project_id=$2 AND id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .fetch_optional(executor)
            .await
    }

    /// Inserts an enabled destination with its encrypted secret and returns
    /// it with the columns of [`Self::list`].
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E, T>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        name: &str,
        url: &str,
        encrypted_secret: Vec<u8>,
        secret_nonce: &[u8],
        deliver_backfill: bool,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("INSERT INTO webhook_destinations (id,organization_id,project_id,name,url,encrypted_secret,secret_nonce,deliver_backfill) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(name)
            .bind(url)
            .bind(encrypted_secret)
            .bind(secret_nonce)
            .bind(deliver_backfill)
            .fetch_one(executor)
            .await
    }

    /// Updates the given fields of a destination at `expected_revision`,
    /// bumping the revision; disabling keeps an earlier disable time and
    /// enabling clears it. `None` when there is no such destination at that
    /// revision.
    #[allow(clippy::too_many_arguments)]
    pub async fn update<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
        name: Option<&str>,
        url: Option<&str>,
        deliver_backfill: Option<bool>,
        enabled: Option<bool>,
        expected_revision: i64,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE webhook_destinations SET name=COALESCE($4,name),url=COALESCE($5,url),deliver_backfill=COALESCE($6,deliver_backfill),enabled=COALESCE($7,enabled),disabled_at=CASE WHEN $7=true THEN NULL WHEN $7=false THEN COALESCE(disabled_at,now()) ELSE disabled_at END,revision=revision+1,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 AND revision=$8 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(name)
            .bind(url)
            .bind(deliver_backfill)
            .bind(enabled)
            .bind(expected_revision)
            .fetch_optional(executor)
            .await
    }

    /// Disables a destination, keeping an earlier disable time, and bumps its
    /// revision.
    pub async fn disable<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE webhook_destinations SET enabled=false,disabled_at=COALESCE(disabled_at,now()),updated_at=now(),revision=revision+1 WHERE organization_id=$1 AND project_id=$2 AND id=$3 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .fetch_optional(executor)
            .await
    }

    /// Replaces a destination's encrypted secret and bumps its revision.
    pub async fn rotate_secret<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        destination_id: Uuid,
        encrypted_secret: Vec<u8>,
        secret_nonce: &[u8],
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE webhook_destinations SET encrypted_secret=$4,secret_nonce=$5,revision=revision+1,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND id=$3 RETURNING id,project_id,name,url,enabled,deliver_backfill,revision,created_at,updated_at,disabled_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(destination_id)
            .bind(encrypted_secret)
            .bind(secret_nonce)
            .fetch_optional(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::WebhookDestinationRepository;
    use crate::repository::test_support::{Tenant, destination, tenant};

    #[derive(Debug, FromRow)]
    struct Destination {
        id: Uuid,
        name: String,
        url: String,
        enabled: bool,
        deliver_backfill: bool,
        revision: i64,
        disabled_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, FromRow)]
    struct Target {
        id: Uuid,
        enabled: bool,
        encrypted_secret: Vec<u8>,
        secret_nonce: Vec<u8>,
    }

    #[derive(Debug, FromRow)]
    struct Snapshot {
        id: Uuid,
        deliver_backfill: bool,
    }

    async fn get(pool: &PgPool, own: &Tenant, id: Uuid) -> Option<Destination> {
        WebhookDestinationRepository::get(pool, own.organization_id, own.project_id, id)
            .await
            .unwrap()
    }

    /// Destinations update at their expected revision only, disable keeping
    /// the first disable time, re-enable clearing it, and rotate their secret.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn destinations_update_by_revision(pool: PgPool) {
        let own = tenant(&pool, "destinations-update").await;
        let first = destination(&pool, &own, "first").await;
        let created = get(&pool, &own, first).await.unwrap();
        assert_eq!(
            (created.enabled, created.deliver_backfill, created.revision),
            (true, false, 1)
        );
        let update = |name: Option<&'static str>, enabled: Option<bool>, revision: i64| {
            let pool = pool.clone();
            async move {
                WebhookDestinationRepository::update::<_, Destination>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    first,
                    name,
                    None,
                    Some(true),
                    enabled,
                    revision,
                )
                .await
                .unwrap()
            }
        };
        let renamed = update(Some("renamed"), None, 1).await.unwrap();
        assert_eq!(
            (
                renamed.name.as_str(),
                renamed.deliver_backfill,
                renamed.revision
            ),
            ("renamed", true, 2)
        );
        assert_eq!(renamed.url, created.url, "unset fields stay");
        assert!(
            update(Some("stale"), None, 1).await.is_none(),
            "a stale revision fails"
        );
        let disabled = update(None, Some(false), 2).await.unwrap();
        assert!(!disabled.enabled && disabled.disabled_at.is_some());
        let again: Destination = WebhookDestinationRepository::disable(
            &pool,
            own.organization_id,
            own.project_id,
            first,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            again.disabled_at, disabled.disabled_at,
            "the first disable time stays"
        );
        assert_eq!(again.revision, 4);
        let enabled = update(None, Some(true), 4).await.unwrap();
        assert!(enabled.enabled && enabled.disabled_at.is_none());

        let rotated: Destination = WebhookDestinationRepository::rotate_secret(
            &pool,
            own.organization_id,
            own.project_id,
            first,
            vec![9; 48],
            &[8; 24],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rotated.revision, 6);
        let target: Target =
            WebhookDestinationRepository::target(&pool, own.organization_id, own.project_id, first)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (
                target.id,
                target.enabled,
                target.encrypted_secret,
                target.secret_nonce
            ),
            (first, true, vec![9; 48], vec![8; 24])
        );
        let other = tenant(&pool, "destinations-update-other").await;
        assert!(get(&pool, &other, first).await.is_none());
    }

    /// The list is newest first; delivery snapshots take enabled
    /// destinations only.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn destinations_list_and_snapshot(pool: PgPool) {
        let own = tenant(&pool, "destinations-list").await;
        let older = destination(&pool, &own, "older").await;
        sqlx::query(
            "UPDATE webhook_destinations SET created_at=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(older)
        .execute(&pool)
        .await
        .unwrap();
        let newer = destination(&pool, &own, "newer").await;
        let listed: Vec<Destination> =
            WebhookDestinationRepository::list(&pool, own.organization_id, own.project_id)
                .await
                .unwrap();
        assert_eq!(
            listed.iter().map(|d| d.id).collect::<Vec<_>>(),
            [newer, older]
        );
        WebhookDestinationRepository::disable::<_, Destination>(
            &pool,
            own.organization_id,
            own.project_id,
            older,
        )
        .await
        .unwrap();
        let enabled: Vec<Snapshot> = WebhookDestinationRepository::enabled_for_project(
            &pool,
            own.organization_id,
            own.project_id,
        )
        .await
        .unwrap();
        assert_eq!(
            enabled
                .iter()
                .map(|d| (d.id, d.deliver_backfill))
                .collect::<Vec<_>>(),
            [(newer, false)]
        );
        let duplicate = WebhookDestinationRepository::insert::<_, Destination>(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            "newer",
            "https://example.test",
            vec![1; 48],
            &[2; 24],
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(
            duplicate
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505"),
            "names are unique per project"
        );
    }
}
