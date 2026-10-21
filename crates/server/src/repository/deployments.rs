//! Deployment evidence: the Kubernetes workload revisions agents report for an
//! application's releases, their readiness snapshots, and the deployment
//! episodes derived from them, each linked to the episodes it replaced.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Input to [`DeploymentRepository::insert_revision`].
#[derive(Debug)]
pub struct NewDeploymentRevision<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub release_id: Uuid,
    pub identity_version: i16,
    pub identity_digest: &'a [u8],
    pub namespace: &'a str,
    pub workload_uid: &'a str,
    pub workload_kind: &'a str,
    pub workload_name: &'a str,
    pub replica_set_uid: &'a str,
    pub replica_set_name: &'a str,
    pub pod_template_hash: Option<&'a str>,
    pub observed_at: DateTime<Utc>,
}

/// Input to [`DeploymentRepository::insert_episode`].
#[derive(Debug)]
pub struct NewDeploymentEpisode<'a> {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub release_id: Uuid,
    pub revision_id: Uuid,
    pub occurrence_number: i64,
    pub transition_kind: &'a str,
    pub observed_at: DateTime<Utc>,
}

/// Input to [`DeploymentRepository::insert_snapshot`].
#[derive(Debug)]
pub struct NewDeploymentSnapshot<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub revision_id: Uuid,
    pub snapshot_id: &'a str,
    pub observed_at: DateTime<Utc>,
    pub initialized: bool,
    pub continuous: bool,
    pub pod_count: i32,
    pub ready_pod_count: i32,
    pub workload_ready_pod_count: i32,
}

/// Workload revisions, readiness snapshots and deployment episodes.
#[derive(Clone, Copy, Debug)]
pub struct DeploymentRepository;

impl DeploymentRepository {
    /// Records a workload revision, keyed by application, cluster, workload
    /// and replica set, and returns its id. Reporting it again refreshes its
    /// last observation; `None` when the replica set was recorded with a
    /// different release or identity digest.
    pub async fn insert_revision<'e, E>(
        executor: E,
        input: NewDeploymentRevision<'_>,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let NewDeploymentRevision {
            id,
            organization_id,
            project_id,
            application_id,
            cluster_id,
            release_id,
            identity_version,
            identity_digest,
            namespace,
            workload_uid,
            workload_kind,
            workload_name,
            replica_set_uid,
            replica_set_name,
            pod_template_hash,
            observed_at,
        } = input;
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO kubernetes_workload_revisions(
                 id,organization_id,project_id,application_id,cluster_id,release_id,
                 identity_version,identity_digest,namespace,workload_uid,workload_kind,
                 workload_name,replica_set_uid,replica_set_name,pod_template_hash,
                 first_observed_at,last_observed_at
             )
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16)
             ON CONFLICT(application_id,cluster_id,workload_uid,replica_set_uid)
             DO UPDATE SET last_observed_at=GREATEST(
                 kubernetes_workload_revisions.last_observed_at,EXCLUDED.last_observed_at
             )
             WHERE kubernetes_workload_revisions.release_id=EXCLUDED.release_id
                 AND kubernetes_workload_revisions.identity_digest=EXCLUDED.identity_digest
             RETURNING id",
        )
        .bind(id)
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(cluster_id)
        .bind(release_id)
        .bind(identity_version)
        .bind(identity_digest)
        .bind(namespace)
        .bind(workload_uid)
        .bind(workload_kind)
        .bind(workload_name)
        .bind(replica_set_uid)
        .bind(replica_set_name)
        .bind(pod_template_hash)
        .bind(observed_at)
        .fetch_optional(executor)
        .await
    }

    /// Takes the transaction-scoped advisory lock for one workload revision,
    /// keyed `"{application}:{cluster}:{workload_uid}:{replica_set_uid}"`.
    pub async fn lock_revision<'e, E>(
        executor: E,
        lock_key: String,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(executor)
            .await
    }

    /// How many episodes a revision has had.
    pub async fn episode_count<'e, E>(executor: E, revision_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM deployment_episodes WHERE revision_id=$1",
        )
        .bind(revision_id)
        .fetch_one(executor)
        .await
    }

    /// The revision's episode that has not ended, if any.
    pub async fn open_episode<'e, E>(
        executor: E,
        revision_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM deployment_episodes WHERE revision_id=$1 AND state<>'inactive'",
        )
        .bind(revision_id)
        .fetch_optional(executor)
        .await
    }

    /// Marks an episode active and observed at `observed_at`, keeping its
    /// first ready time.
    pub async fn touch_episode<'e, E>(
        executor: E,
        episode_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE deployment_episodes
             SET last_observed_at=GREATEST(last_observed_at,$2),state='active',
                 first_ready_at=COALESCE(first_ready_at,$2)
             WHERE id=$1",
        )
        .bind(episode_id)
        .bind(observed_at)
        .execute(executor)
        .await
    }

    /// The application's active episodes in the cluster with their release,
    /// most recently observed first.
    pub async fn active_episodes<'e, E>(
        executor: E,
        organization_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT id,release_id
             FROM deployment_episodes
             WHERE organization_id=$1
                 AND application_id=$2
                 AND cluster_id=$3
                 AND state='active'
             ORDER BY last_observed_at DESC,id DESC",
        )
        .bind(organization_id)
        .bind(application_id)
        .bind(cluster_id)
        .fetch_all(executor)
        .await
    }

    /// Opens an active, ready episode of a revision.
    pub async fn insert_episode<'e, E>(
        executor: E,
        input: NewDeploymentEpisode<'_>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let NewDeploymentEpisode {
            id,
            organization_id,
            project_id,
            application_id,
            cluster_id,
            release_id,
            revision_id,
            occurrence_number,
            transition_kind,
            observed_at,
        } = input;
        sqlx::query(
            "INSERT INTO deployment_episodes(
                 id,organization_id,project_id,application_id,cluster_id,release_id,
                 revision_id,occurrence_number,state,transition_kind,first_observed_at,
                 first_ready_at,last_observed_at
             )
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$10,$10)",
        )
        .bind(id)
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(cluster_id)
        .bind(release_id)
        .bind(revision_id)
        .bind(occurrence_number)
        .bind(transition_kind)
        .bind(observed_at)
        .execute(executor)
        .await
    }

    /// Records that an episode began while another was active.
    pub async fn link_predecessor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        episode_id: Uuid,
        predecessor_episode_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO deployment_episode_predecessors(
                 organization_id,project_id,application_id,episode_id,predecessor_episode_id,
                 observed_at,concurrent
             )
             VALUES($1,$2,$3,$4,$5,$6,true)
             ON CONFLICT
             DO NOTHING",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(episode_id)
        .bind(predecessor_episode_id)
        .bind(observed_at)
        .execute(executor)
        .await
    }

    /// The application's revision in the cluster with this identity digest.
    pub async fn revision_by_digest<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        identity_digest: &[u8],
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id
             FROM kubernetes_workload_revisions
             WHERE organization_id=$1
                 AND project_id=$2
                 AND application_id=$3
                 AND cluster_id=$4
                 AND identity_digest=$5",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(cluster_id)
        .bind(identity_digest)
        .fetch_optional(executor)
        .await
    }

    /// Records a readiness snapshot of a revision, once per snapshot id.
    pub async fn insert_snapshot<'e, E>(
        executor: E,
        input: NewDeploymentSnapshot<'_>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let NewDeploymentSnapshot {
            organization_id,
            project_id,
            application_id,
            cluster_id,
            revision_id,
            snapshot_id,
            observed_at,
            initialized,
            continuous,
            pod_count,
            ready_pod_count,
            workload_ready_pod_count,
        } = input;
        sqlx::query(
            "INSERT INTO kubernetes_revision_snapshots(
                 organization_id,project_id,application_id,cluster_id,revision_id,
                 snapshot_id,observed_at,initialized,continuous,pod_count,ready_pod_count,
                 workload_ready_pod_count
             )
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT
             DO NOTHING",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(cluster_id)
        .bind(revision_id)
        .bind(snapshot_id)
        .bind(observed_at)
        .bind(initialized)
        .bind(continuous)
        .bind(pod_count)
        .bind(ready_pod_count)
        .bind(workload_ready_pod_count)
        .execute(executor)
        .await
    }

    /// Ends the revision's open episode when it has had no pods for
    /// `stabilization_seconds` since it was last observed.
    pub async fn end_episode<'e, E>(
        executor: E,
        revision_id: Uuid,
        workload_ready_pod_count: i32,
        observed_at: DateTime<Utc>,
        stabilization_seconds: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE deployment_episodes
             SET pod_count=0,ready_pod_count=0,workload_ready_pod_count=$2,
                 snapshot_observed_at=$3,state='inactive',ended_at=$3
             WHERE revision_id=$1
                 AND state<>'inactive'
                 AND $3>=last_observed_at+($4::double precision*interval '1 second')",
        )
        .bind(revision_id)
        .bind(workload_ready_pod_count)
        .bind(observed_at)
        .bind(stabilization_seconds)
        .execute(executor)
        .await
    }

    /// Records the pod counts of the revision's open episode.
    pub async fn record_episode_pods<'e, E>(
        executor: E,
        revision_id: Uuid,
        pod_count: i32,
        ready_pod_count: i32,
        workload_ready_pod_count: i32,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE deployment_episodes
             SET pod_count=$2,ready_pod_count=$3,workload_ready_pod_count=$4,
                 snapshot_observed_at=$5,last_observed_at=GREATEST(last_observed_at,$5)
             WHERE revision_id=$1
                 AND state<>'inactive'",
        )
        .bind(revision_id)
        .bind(pod_count)
        .bind(ready_pod_count)
        .bind(workload_ready_pod_count)
        .bind(observed_at)
        .execute(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{NewDeploymentEpisode, NewDeploymentRevision, NewDeploymentSnapshot};
    use crate::repository::releases::ObservedRelease;
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::DeploymentRepository;
    use crate::repository::ReleaseRepository;
    use crate::repository::test_support::{Tenant, tenant};

    async fn release(pool: &PgPool, own: &Tenant, digest: u8) -> Uuid {
        ReleaseRepository::insert_observed(
            pool,
            ObservedRelease {
                id: Uuid::new_v4(),
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                version: format!("sha-{digest}"),
                deployed_at: Utc::now(),
                identity_version: 1,
                identity_digest: &[digest; 32],
                identity_components: json!([{"container": "app"}]),
            },
        )
        .await
        .unwrap()
    }

    async fn revision(pool: &PgPool, own: &Tenant, release_id: Uuid, digest: u8) -> Option<Uuid> {
        DeploymentRepository::insert_revision(
            pool,
            NewDeploymentRevision {
                id: Uuid::new_v4(),
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                cluster_id: own.cluster_id,
                release_id,
                identity_version: 1,
                identity_digest: &[digest; 32],
                namespace: "production",
                workload_uid: "workload-a",
                workload_kind: "Deployment",
                workload_name: "api",
                replica_set_uid: &format!("rs-{digest}"),
                replica_set_name: &format!("api-{digest}"),
                pod_template_hash: Some("abc"),
                observed_at: Utc::now(),
            },
        )
        .await
        .unwrap()
    }

    async fn episode_state(pool: &PgPool, id: Uuid) -> (String, i32, Option<DateTime<Utc>>) {
        sqlx::query_as("SELECT state,pod_count,ended_at FROM deployment_episodes WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Observed releases resolve by identity; a revision is recorded per
    /// replica set, refusing a conflicting digest, and resolves by its digest.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn releases_and_revisions_are_recorded_once(pool: PgPool) {
        let own = tenant(&pool, "deployments-revisions").await;
        let first = release(&pool, &own, 1).await;
        assert_eq!(
            release(&pool, &own, 1).await,
            first,
            "the same identity resolves"
        );
        assert_ne!(release(&pool, &own, 2).await, first);
        let rev = revision(&pool, &own, first, 7).await.unwrap();
        assert_eq!(
            revision(&pool, &own, first, 7).await,
            Some(rev),
            "the same revision"
        );
        let conflicting = DeploymentRepository::insert_revision(
            &pool,
            NewDeploymentRevision {
                id: Uuid::new_v4(),
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                cluster_id: own.cluster_id,
                release_id: first,
                identity_version: 1,
                identity_digest: &[9; 32],
                namespace: "production",
                workload_uid: "workload-a",
                workload_kind: "Deployment",
                workload_name: "api",
                replica_set_uid: "rs-7",
                replica_set_name: "api-7",
                pod_template_hash: None,
                observed_at: Utc::now(),
            },
        )
        .await
        .unwrap();
        assert_eq!(conflicting, None, "the replica set with another digest");
        assert_eq!(
            DeploymentRepository::revision_by_digest(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                own.cluster_id,
                &[7; 32],
            )
            .await
            .unwrap(),
            Some(rev)
        );
        let key = format!("{}:{}:workload-a:rs-7", own.application_id, own.cluster_id);
        let mut tx = pool.begin().await.unwrap();
        DeploymentRepository::lock_revision(&mut *tx, key.clone())
            .await
            .unwrap();
        let taken: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!taken);
        tx.commit().await.unwrap();
    }

    /// Episodes open per revision, stay active while observed, link to the
    /// episodes they replaced, track pods, and end after a stable empty
    /// snapshot.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn episodes_open_track_and_end(pool: PgPool) {
        let own = tenant(&pool, "deployments-episodes").await;
        let now = Utc::now().trunc_subsecs(0);
        let first_release = release(&pool, &own, 1).await;
        let rev = revision(&pool, &own, first_release, 7).await.unwrap();
        assert_eq!(
            DeploymentRepository::episode_count(&pool, rev)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            DeploymentRepository::open_episode(&pool, rev)
                .await
                .unwrap(),
            None
        );
        let first = Uuid::new_v4();
        DeploymentRepository::insert_episode(
            &pool,
            NewDeploymentEpisode {
                id: first,
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                cluster_id: own.cluster_id,
                release_id: first_release,
                revision_id: rev,
                occurrence_number: 1,
                transition_kind: "unknown",
                observed_at: now,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            DeploymentRepository::episode_count(&pool, rev)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            DeploymentRepository::open_episode(&pool, rev)
                .await
                .unwrap(),
            Some(first)
        );
        DeploymentRepository::touch_episode(&pool, first, now + Duration::minutes(5))
            .await
            .unwrap();
        let last: DateTime<Utc> =
            sqlx::query_scalar("SELECT last_observed_at FROM deployment_episodes WHERE id=$1")
                .bind(first)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(last, now + Duration::minutes(5));

        let second_release = release(&pool, &own, 2).await;
        let second_rev = revision(&pool, &own, second_release, 8).await.unwrap();
        let second = Uuid::new_v4();
        DeploymentRepository::insert_episode(
            &pool,
            NewDeploymentEpisode {
                id: second,
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                cluster_id: own.cluster_id,
                release_id: second_release,
                revision_id: second_rev,
                occurrence_number: 1,
                transition_kind: "rollout",
                observed_at: now + Duration::minutes(6),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            DeploymentRepository::active_episodes(
                &pool,
                own.organization_id,
                own.application_id,
                own.cluster_id,
            )
            .await
            .unwrap(),
            [(second, second_release), (first, first_release)],
            "most recently observed first"
        );
        DeploymentRepository::link_predecessor(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            second,
            first,
            now + Duration::minutes(6),
        )
        .await
        .unwrap();
        let concurrent: bool = sqlx::query_scalar(
            "SELECT concurrent
             FROM deployment_episode_predecessors
             WHERE episode_id=$1
                 AND predecessor_episode_id=$2",
        )
        .bind(second)
        .bind(first)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(concurrent);

        DeploymentRepository::insert_snapshot(
            &pool,
            NewDeploymentSnapshot {
                organization_id: own.organization_id,
                project_id: own.project_id,
                application_id: own.application_id,
                cluster_id: own.cluster_id,
                revision_id: rev,
                snapshot_id: "snapshot-1",
                observed_at: now + Duration::minutes(7),
                initialized: true,
                continuous: true,
                pod_count: 2,
                ready_pod_count: 1,
                workload_ready_pod_count: 1,
            },
        )
        .await
        .unwrap();
        DeploymentRepository::record_episode_pods(&pool, rev, 2, 1, 1, now + Duration::minutes(7))
            .await
            .unwrap();
        assert_eq!(episode_state(&pool, first).await.1, 2);
        DeploymentRepository::end_episode(&pool, rev, 0, now + Duration::minutes(7), 600)
            .await
            .unwrap();
        assert_eq!(
            episode_state(&pool, first).await.0,
            "active",
            "not stable long enough"
        );
        DeploymentRepository::end_episode(&pool, rev, 0, now + Duration::minutes(30), 600)
            .await
            .unwrap();
        let (state, pods, ended) = episode_state(&pool, first).await;
        assert_eq!((state.as_str(), pods), ("inactive", 0));
        assert_eq!(ended, Some(now + Duration::minutes(30)));
        assert_eq!(
            DeploymentRepository::open_episode(&pool, rev)
                .await
                .unwrap(),
            None
        );
    }
}
