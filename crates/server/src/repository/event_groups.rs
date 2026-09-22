//! Runtime event group persistence.
//!
//! A group is the deduplicated unit the product reasons about: many raw
//! `runtime_events` rows collapse onto one `runtime_event_groups` row keyed by
//! a fingerprint. Two independent writers create groups — the live grouping
//! path in [`crate::grouping`] and the derived restart-loop projection in
//! [`crate::termination_projection`] — and both used to carry their own copy of
//! the insert, the conflict target, and the occurrence bookkeeping. They are
//! collected here so that the two remain visibly different where they must be
//! and identical where they should be.
//!
//! The analytical reads that project groups into API responses are not here.
//! An attention feed or an inventory listing is a multi-table CTE written for
//! one endpoint, and moving it would relocate the statement without giving any
//! other caller a reason to share it. What lives here is the write path, the
//! tenant lookup, and the counting predicates — the statements more than one
//! call site genuinely needs.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// The columns that uniquely identify a group.
///
/// These are exactly the nine columns of the `runtime_event_groups` unique
/// index, in its order. Passing them as one value rather than nine arguments
/// keeps a caller from silently omitting one: dropping a column here would not
/// widen a query, it would change which row the conflict target matches.
#[derive(Clone, Copy, Debug)]
pub struct GroupKey<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub namespace: &'a str,
    pub workload_kind: &'a str,
    pub workload_name: &'a str,
    pub fingerprint_version: i16,
    pub fingerprint_digest: &'a [u8],
}

/// Scalar subqueries aggregating a tenant's groups.
///
/// These are string fragments rather than methods on purpose. Every call site
/// embeds the aggregate in a paginated listing that already selects the owning
/// row, so a method would turn one query into a query per row. Sharing the text
/// is what keeps the definition in one place.
///
/// Each fragment expects the owning table under a fixed alias, named in its
/// documentation, and carries the full tenant path even where a foreign key
/// makes part of it redundant — an aggregate that reads as tenant-scoped should
/// not depend on the reader knowing the schema to see that it is.
///
/// # Two definitions of the same number
///
/// Retention purges raw events and leaves the group row behind at
/// `occurrence_count = 0`, which split every aggregate here in two: over all
/// groups, or only over groups that still have evidence. The endpoints do not
/// agree on which one they mean — `runtime_group_count` is counted one way for
/// a project and another for its applications, so an organization with
/// retention enabled cannot sum one into the other. Both readings are spelled
/// out and named rather than reconciled, because picking one changes a number
/// an API already returns.
pub mod aggregates {
    /// Counts every group of a project, evidence or not.
    /// Expects `projects` aliased as `p`.
    pub const COUNT_ALL_FOR_PROJECT: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=p.organization_id AND g.project_id=p.id)";

    /// Counts every group of an application, evidence or not.
    /// Expects `applications` aliased as `a`.
    pub const COUNT_ALL_FOR_APPLICATION: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id)";

    /// Counts an application's groups that still have raw evidence behind them.
    /// Expects `applications` aliased as `a`.
    pub const COUNT_WITH_EVIDENCE_FOR_APPLICATION: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id AND g.occurrence_count>0)";

    /// The most recent sighting across an application's groups, evidence or not.
    /// Expects `applications` aliased as `a`.
    pub const LATEST_SEEN_ALL_FOR_APPLICATION: &str = "(SELECT max(g.last_seen_at) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id)";

    /// The most recent sighting an application still holds evidence for.
    /// Expects `applications` aliased as `a`.
    pub const LATEST_SEEN_WITH_EVIDENCE_FOR_APPLICATION: &str = "(SELECT max(g.last_seen_at) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id AND g.occurrence_count>0)";
}

/// Queries against the `runtime_event_groups` table.
#[derive(Clone, Copy, Debug)]
pub struct EventGroupRepository;

impl EventGroupRepository {
    /// Returns the organization and project owning the group, or `None` when
    /// no such group exists.
    ///
    /// Like [`crate::repository::ProjectRepository::organization_of`], the
    /// lookup itself is unauthenticated: the caller needs the tenant path in
    /// order to authorize against it, and maps `None` onto `404`.
    pub async fn tenant_of<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT organization_id, project_id
            FROM runtime_event_groups
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .fetch_optional(executor)
        .await
    }

    /// Inserts a new group, returning its id, or `None` when one already
    /// exists for the key.
    ///
    /// The row starts at one occurrence with `first_seen_at` and `last_seen_at`
    /// both at the observation, and the same event as both representative and
    /// first-seen. A `None` result means another writer won the race; pair this
    /// with [`Self::lock_existing`] to obtain the winner's id.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_if_absent<'e, E>(
        executor: E,
        candidate_id: Uuid,
        key: GroupKey<'_>,
        event_kind: &str,
        semantic_summary: &Value,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            INSERT INTO runtime_event_groups (
                id, organization_id, project_id, cluster_id, application_id,
                namespace, workload_kind, workload_name,
                fingerprint_version, fingerprint_digest,
                event_kind, semantic_summary,
                first_seen_at, last_seen_at, occurrence_count,
                representative_event_id, first_seen_event_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,1,$14,$14)
            ON CONFLICT (organization_id, project_id, application_id, cluster_id,
                         namespace, workload_kind, workload_name,
                         fingerprint_version, fingerprint_digest)
            DO NOTHING
            RETURNING id
            "#,
        )
        .bind(candidate_id)
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.cluster_id)
        .bind(key.application_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .bind(event_kind)
        .bind(semantic_summary)
        .bind(observed_at)
        .bind(event_id)
        .fetch_optional(executor)
        .await
    }

    /// Locks the existing group for the key and returns its id.
    ///
    /// `FOR UPDATE` serializes concurrent writers against the same group, so
    /// the occurrence bookkeeping that follows cannot interleave. This requires
    /// a transaction; pass `&mut *tx`.
    pub async fn lock_existing<'e, E>(executor: E, key: GroupKey<'_>) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM runtime_event_groups
            WHERE organization_id = $1
              AND project_id = $2
              AND application_id = $3
              AND cluster_id = $4
              AND namespace = $5
              AND workload_kind = $6
              AND workload_name = $7
              AND fingerprint_version = $8
              AND fingerprint_digest = $9
            FOR UPDATE
            "#,
        )
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.application_id)
        .bind(key.cluster_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .fetch_one(executor)
        .await
    }

    /// Folds one further observation into an existing group.
    ///
    /// The `occurrence_count = 0` branches are not defensive padding. Retention
    /// purges raw events and decrements the count to zero while leaving the
    /// group row in place, so a group can be observed again after its window
    /// has been emptied. Extending the old window with `LEAST`/`GREATEST` would
    /// then report a first sighting whose evidence no longer exists, so a group
    /// at zero restarts its window at the new observation instead.
    pub async fn record_occurrence<'e, E>(
        executor: E,
        group_id: Uuid,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE runtime_event_groups
            SET first_seen_event_id = CASE
                    WHEN ($2,$3) < (first_seen_at, first_seen_event_id) THEN $3
                    ELSE first_seen_event_id END,
                first_seen_at = CASE
                    WHEN occurrence_count = 0 THEN $2 ELSE LEAST(first_seen_at, $2) END,
                last_seen_at = CASE
                    WHEN occurrence_count = 0 THEN $2 ELSE GREATEST(last_seen_at, $2) END,
                representative_event_id = COALESCE(representative_event_id, $3),
                occurrence_count = occurrence_count + 1,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .bind(observed_at)
        .bind(event_id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Creates or refreshes a group derived from a projection rather than from
    /// a fingerprinted event, returning its id.
    ///
    /// Unlike [`Self::insert_if_absent`] this always returns a row, because a
    /// derived group carries a recomputed summary that must overwrite the
    /// stored one on every pass. A caller tells creation from refresh by
    /// comparing the result against the candidate id it supplied.
    ///
    /// The window maintenance here is deliberately weaker than
    /// [`Self::record_occurrence`]: it advances `last_seen_at` but does not
    /// restart the window of a group retention has emptied. Both writers reach
    /// the same table, so that difference is a real inconsistency rather than a
    /// property of derived groups; it is preserved as-is because changing it
    /// moves user-visible timestamps.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_derived<'e, E>(
        executor: E,
        candidate_id: Uuid,
        key: GroupKey<'_>,
        event_kind: &str,
        semantic_summary: &Value,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            INSERT INTO runtime_event_groups (
                id, organization_id, project_id, cluster_id, application_id,
                namespace, workload_kind, workload_name,
                fingerprint_version, fingerprint_digest,
                event_kind, semantic_summary,
                first_seen_at, last_seen_at, occurrence_count,
                representative_event_id, first_seen_event_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,1,$14,$14)
            ON CONFLICT (organization_id, project_id, application_id, cluster_id,
                         namespace, workload_kind, workload_name,
                         fingerprint_version, fingerprint_digest)
            DO UPDATE SET
                semantic_summary = EXCLUDED.semantic_summary,
                last_seen_at = GREATEST(runtime_event_groups.last_seen_at,
                                        EXCLUDED.last_seen_at),
                representative_event_id = EXCLUDED.representative_event_id,
                updated_at = now()
            RETURNING id
            "#,
        )
        .bind(candidate_id)
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.cluster_id)
        .bind(key.application_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .bind(event_kind)
        .bind(semantic_summary)
        .bind(observed_at)
        .bind(event_id)
        .fetch_one(executor)
        .await
    }

    /// Adds one to a group's occurrence count without touching its window.
    ///
    /// This is the derived-projection counterpart to
    /// [`Self::record_occurrence`], used where the caller has already written
    /// the window through [`Self::upsert_derived`].
    pub async fn increment_occurrence<'e, E>(executor: E, group_id: Uuid) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE runtime_event_groups
            SET occurrence_count = occurrence_count + 1
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .execute(executor)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EventGroupRepository, GroupKey};
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use uuid::Uuid;

    const DIGEST: [u8; 32] = [7u8; 32];

    struct Fixture {
        organization: Uuid,
        project: Uuid,
        application: Uuid,
        cluster: Uuid,
        agent: Uuid,
    }

    impl Fixture {
        fn key(&self) -> GroupKey<'_> {
            GroupKey {
                organization_id: self.organization,
                project_id: self.project,
                application_id: self.application,
                cluster_id: self.cluster,
                namespace: "default",
                workload_kind: "Deployment",
                workload_name: "api",
                fingerprint_version: 1,
                fingerprint_digest: &DIGEST,
            }
        }
    }

    fn at(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, minute, 0).unwrap()
    }

    async fn seed(pool: &PgPool) -> Fixture {
        let fixture = Fixture {
            organization: Uuid::new_v4(),
            project: Uuid::new_v4(),
            application: Uuid::new_v4(),
            cluster: Uuid::new_v4(),
            agent: Uuid::new_v4(),
        };
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(fixture.organization)
            .bind(fixture.organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(fixture.project)
            .bind(fixture.organization)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'a','A')",
        )
        .bind(fixture.application)
        .bind(fixture.organization)
        .bind(fixture.project)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,'c','C')",
        )
        .bind(fixture.cluster)
        .bind(fixture.organization)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node','0.0.0')",
        )
        .bind(fixture.agent)
        .bind(fixture.organization)
        .bind(fixture.cluster)
        .execute(pool)
        .await
        .unwrap();
        fixture
    }

    /// `representative_event_id` and `first_seen_event_id` are foreign keys, so
    /// every group needs a real event behind it.
    async fn seed_event(pool: &PgPool, fixture: &Fixture, observed_at: DateTime<Utc>) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO runtime_events(id,event_id,organization_id,project_id,cluster_id,application_id,agent_id,observed_at,node_name,namespace,pod_uid,pod_name,container_id,container_name,workload_uid,workload_kind,workload_name,cgroup_id,pid,tgid,process_command,event_kind,event_schema_version,payload) \
             VALUES($1,$1,$2,$3,$4,$5,$6,$7,'node','default','pod-uid','pod','container','container','workload-uid','Deployment','api',1,1,1,'cmd','process.exec',1,'{}'::jsonb)",
        )
        .bind(id)
        .bind(fixture.organization)
        .bind(fixture.project)
        .bind(fixture.cluster)
        .bind(fixture.application)
        .bind(fixture.agent)
        .bind(observed_at)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn window(pool: &PgPool, group: Uuid) -> (DateTime<Utc>, DateTime<Utc>, i64, Value) {
        sqlx::query_as(
            "SELECT first_seen_at,last_seen_at,occurrence_count,semantic_summary FROM runtime_event_groups WHERE id=$1",
        )
        .bind(group)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn resolves_the_owning_tenant(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        assert_eq!(
            EventGroupRepository::tenant_of(&pool, group).await.unwrap(),
            Some((fixture.organization, fixture.project))
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn reports_an_unknown_group_as_absent(pool: PgPool) {
        assert_eq!(
            EventGroupRepository::tenant_of(&pool, Uuid::new_v4())
                .await
                .unwrap(),
            None
        );
    }

    /// The second insert for one key must not create a second group: the
    /// conflict target is what makes grouping idempotent under concurrent
    /// ingestion.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn inserts_once_per_key_and_locks_the_winner(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(0)).await;
        let winner = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                winner,
                fixture.key(),
                "process.exec",
                &json!({}),
                at(0),
                first_event,
            )
            .await
            .unwrap(),
            Some(winner)
        );

        let second_event = seed_event(&pool, &fixture, at(1)).await;
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                Uuid::new_v4(),
                fixture.key(),
                "process.exec",
                &json!({}),
                at(1),
                second_event,
            )
            .await
            .unwrap(),
            None,
            "a repeated key must not create a second group"
        );

        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            EventGroupRepository::lock_existing(&mut *tx, fixture.key())
                .await
                .unwrap(),
            winner,
            "the loser of the race must find the winner's group"
        );
        tx.commit().await.unwrap();
    }

    /// A group that differs in any one key column is a different group. The
    /// digest is the column most likely to be dropped from a hand-written
    /// conflict target, so it is the one exercised here.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn separates_groups_differing_only_by_digest(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let first = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            first,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        let other_digest = [9u8; 32];
        let mut key = fixture.key();
        key.fingerprint_digest = &other_digest;
        let second = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                second,
                key,
                "process.exec",
                &json!({}),
                at(1),
                event,
            )
            .await
            .unwrap(),
            Some(second)
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn folds_a_later_observation_into_the_window(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(10)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(10),
            first_event,
        )
        .await
        .unwrap();

        let later = seed_event(&pool, &fixture, at(20)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(20), later)
            .await
            .unwrap();
        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(10), at(20), 2));

        // An out-of-order arrival widens the window backwards rather than
        // replacing it.
        let earlier = seed_event(&pool, &fixture, at(5)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(5), earlier)
            .await
            .unwrap();
        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(5), at(20), 3));
    }

    /// Retention empties a group without deleting it. The next observation must
    /// restart the window instead of extending one whose evidence is gone —
    /// otherwise the group reports a first sighting nothing can substantiate.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn restarts_the_window_of_a_group_retention_emptied(pool: PgPool) {
        let fixture = seed(&pool).await;
        let old_event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            old_event,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE runtime_event_groups SET occurrence_count=0, representative_event_id=NULL, first_seen_event_id=NULL WHERE id=$1",
        )
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();

        let fresh = seed_event(&pool, &fixture, at(30)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(30), fresh)
            .await
            .unwrap();

        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!(
            (first_seen, last_seen, count),
            (at(30), at(30), 1),
            "an emptied group restarts its window at the new observation"
        );
        let representative: Option<Uuid> = sqlx::query_scalar(
            "SELECT representative_event_id FROM runtime_event_groups WHERE id=$1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            representative,
            Some(fresh),
            "an emptied group adopts the new event as representative"
        );
    }

    /// The derived path always returns a row, and refreshes the stored summary
    /// on every pass. The caller distinguishes creation from refresh by
    /// comparing against the candidate it supplied.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn upserts_a_derived_group_and_refreshes_its_summary(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(0)).await;
        let created = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::upsert_derived(
                &pool,
                created,
                fixture.key(),
                "container.restart_loop",
                &json!({"observed_restart_count": 3}),
                at(0),
                first_event,
            )
            .await
            .unwrap(),
            created
        );

        let later_event = seed_event(&pool, &fixture, at(15)).await;
        let candidate = Uuid::new_v4();
        let refreshed = EventGroupRepository::upsert_derived(
            &pool,
            candidate,
            fixture.key(),
            "container.restart_loop",
            &json!({"observed_restart_count": 9}),
            at(15),
            later_event,
        )
        .await
        .unwrap();
        assert_eq!(refreshed, created, "a refresh returns the existing group");
        assert_ne!(
            refreshed, candidate,
            "the candidate id marks creation, so it must not come back from a refresh"
        );

        let (first_seen, last_seen, count, summary) = window(&pool, created).await;
        assert_eq!((first_seen, last_seen), (at(0), at(15)));
        assert_eq!(
            count, 1,
            "the upsert leaves the count alone; the caller increments it"
        );
        assert_eq!(summary, json!({"observed_restart_count": 9}));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn increments_without_touching_the_window(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::upsert_derived(
            &pool,
            group,
            fixture.key(),
            "container.restart_loop",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        EventGroupRepository::increment_occurrence(&pool, group)
            .await
            .unwrap();

        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(0), at(0), 2));
    }
}
