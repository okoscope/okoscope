use event_model::{
    ReleaseIdentity, RevisionReadinessSnapshot, WorkloadRevisionEvidence, revision_digest,
};
use serde_json::to_value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{application_credentials::ApplicationCredentialScope, auth::SessionScope};

const DEFAULT_EPISODE_STABILIZATION_SECONDS: i64 = 120;
const MIN_EPISODE_STABILIZATION_SECONDS: i64 = 30;
const MAX_EPISODE_STABILIZATION_SECONDS: i64 = 3600;

fn stabilization_seconds(value: Option<&str>) -> i64 {
    value
        .and_then(|value| value.parse().ok())
        .filter(|value| {
            (MIN_EPISODE_STABILIZATION_SECONDS..=MAX_EPISODE_STABILIZATION_SECONDS).contains(value)
        })
        .unwrap_or(DEFAULT_EPISODE_STABILIZATION_SECONDS)
}

pub async fn persist_revision_evidence(
    pool: &PgPool,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    evidence: &WorkloadRevisionEvidence,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_revision(&mut tx, scope, application, evidence).await?;
    let release_id = resolve_observed_release(
        &mut tx,
        scope.organization_id,
        application.project_id,
        application.application_id,
        &evidence.release_identity,
        evidence.observed_at,
    )
    .await?;
    let digest = revision_digest(evidence);
    let revision_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO kubernetes_workload_revisions(id,organization_id,project_id,application_id,cluster_id,release_id,identity_version,identity_digest,namespace,workload_uid,workload_kind,workload_name,replica_set_uid,replica_set_name,pod_template_hash,first_observed_at,last_observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16) ON CONFLICT(application_id,cluster_id,workload_uid,replica_set_uid) DO UPDATE SET last_observed_at=GREATEST(kubernetes_workload_revisions.last_observed_at,EXCLUDED.last_observed_at) WHERE kubernetes_workload_revisions.release_id=EXCLUDED.release_id AND kubernetes_workload_revisions.identity_digest=EXCLUDED.identity_digest RETURNING id",
    )
    .bind(Uuid::new_v4()).bind(scope.organization_id).bind(application.project_id)
    .bind(application.application_id).bind(scope.cluster_id).bind(release_id)
    .bind(i16::try_from(evidence.release_identity.version).unwrap_or(i16::MAX)).bind(digest.as_slice())
    .bind(&evidence.namespace).bind(&evidence.workload_uid).bind(&evidence.workload_kind)
    .bind(&evidence.workload_name).bind(&evidence.replica_set_uid).bind(&evidence.replica_set_name)
    .bind(&evidence.pod_template_hash).bind(evidence.observed_at).fetch_optional(&mut *tx).await?;
    let Some(revision_id) = revision_id else {
        return Err(sqlx::Error::Protocol(
            "conflicting immutable identity for Kubernetes ReplicaSet".into(),
        ));
    };
    if evidence.ready {
        open_episode(
            &mut tx,
            scope,
            application,
            release_id,
            revision_id,
            evidence.observed_at,
        )
        .await?;
    }
    tracing::debug!(application_id=%application.application_id, cluster_id=%scope.cluster_id, release_id=%release_id, revision_id=%revision_id, ready=evidence.ready, "Kubernetes revision evidence accepted");
    tx.commit().await
}

async fn lock_revision(
    tx: &mut Transaction<'_, Postgres>,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    evidence: &WorkloadRevisionEvidence,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "{}:{}:{}:{}",
            application.application_id,
            scope.cluster_id,
            evidence.workload_uid,
            evidence.replica_set_uid
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn resolve_observed_release(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    identity: &ReleaseIdentity,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Uuid, sqlx::Error> {
    let version = format!("sha256:{}", hex::encode(identity.digest));
    sqlx::query_scalar(
        "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at,source,identity_version,identity_digest,identity_components) VALUES($1,$2,$3,$4,$5,$6,'observed',$7,$8,$9) ON CONFLICT(application_id,version) DO UPDATE SET identity_components=EXCLUDED.identity_components WHERE releases.organization_id=EXCLUDED.organization_id AND releases.project_id=EXCLUDED.project_id AND releases.source='observed' AND releases.identity_version=EXCLUDED.identity_version AND releases.identity_digest=EXCLUDED.identity_digest RETURNING id",
    ).bind(Uuid::new_v4()).bind(organization_id).bind(project_id)
      .bind(application_id).bind(version).bind(observed_at)
      .bind(i16::try_from(identity.version).unwrap_or(i16::MAX)).bind(identity.digest.as_slice())
      .bind(to_value(&identity.containers).expect("release components serialize"))
      .fetch_one(&mut **tx).await
}

async fn open_episode(
    tx: &mut Transaction<'_, Postgres>,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    release_id: Uuid,
    revision_id: Uuid,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    let prior_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM deployment_episodes WHERE revision_id=$1")
            .bind(revision_id)
            .fetch_one(&mut **tx)
            .await?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM deployment_episodes WHERE revision_id=$1 AND state<>'inactive'",
    )
    .bind(revision_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(id) = existing {
        sqlx::query("UPDATE deployment_episodes SET last_observed_at=GREATEST(last_observed_at,$2),state='active',first_ready_at=COALESCE(first_ready_at,$2) WHERE id=$1")
            .bind(id).bind(observed_at).execute(&mut **tx).await?;
        return Ok(());
    }
    let predecessors: Vec<(Uuid, Uuid)> = sqlx::query_as("SELECT id,release_id FROM deployment_episodes WHERE organization_id=$1 AND application_id=$2 AND cluster_id=$3 AND state='active' ORDER BY last_observed_at DESC,id DESC")
        .bind(scope.organization_id).bind(application.application_id).bind(scope.cluster_id)
        .fetch_all(&mut **tx).await?;
    let predecessor_releases: Vec<_> = predecessors.iter().map(|(_, id)| *id).collect();
    let transition = transition_kind(prior_count, release_id, &predecessor_releases);
    let episode_id = Uuid::new_v4();
    sqlx::query("INSERT INTO deployment_episodes(id,organization_id,project_id,application_id,cluster_id,release_id,revision_id,occurrence_number,state,transition_kind,first_observed_at,first_ready_at,last_observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$10,$10)")
        .bind(episode_id).bind(scope.organization_id).bind(application.project_id).bind(application.application_id)
        .bind(scope.cluster_id).bind(release_id).bind(revision_id).bind(prior_count+1).bind(transition).bind(observed_at)
        .execute(&mut **tx).await?;
    for (predecessor_id, _) in predecessors {
        sqlx::query("INSERT INTO deployment_episode_predecessors(organization_id,project_id,application_id,episode_id,predecessor_episode_id,observed_at,concurrent) VALUES($1,$2,$3,$4,$5,$6,true) ON CONFLICT DO NOTHING")
            .bind(scope.organization_id).bind(application.project_id).bind(application.application_id)
            .bind(episode_id).bind(predecessor_id).bind(observed_at).execute(&mut **tx).await?;
    }
    Ok(())
}

fn transition_kind(prior_count: i64, release_id: Uuid, predecessors: &[Uuid]) -> &'static str {
    if prior_count > 0 && predecessors.iter().any(|id| *id != release_id) {
        "rollback_candidate"
    } else {
        match predecessors.len() {
            0 => "unknown",
            1 => "rollout",
            _ => "concurrent",
        }
    }
}

pub async fn persist_readiness_snapshot(
    pool: &PgPool,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    snapshot: &RevisionReadinessSnapshot,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let revision_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM kubernetes_workload_revisions WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND cluster_id=$4 AND identity_digest=$5")
        .bind(scope.organization_id).bind(application.project_id).bind(application.application_id)
        .bind(scope.cluster_id).bind(snapshot.revision_digest.as_slice()).fetch_optional(&mut *tx).await?;
    let Some(revision_id) = revision_id else {
        tracing::warn!(application_id=%application.application_id, cluster_id=%scope.cluster_id, "readiness snapshot has no known scoped revision");
        return tx.commit().await;
    };
    sqlx::query("INSERT INTO kubernetes_revision_snapshots(organization_id,project_id,application_id,cluster_id,revision_id,snapshot_id,observed_at,initialized,continuous,pod_count,ready_pod_count,workload_ready_pod_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING")
        .bind(scope.organization_id).bind(application.project_id).bind(application.application_id).bind(scope.cluster_id)
        .bind(revision_id).bind(&snapshot.snapshot_id).bind(snapshot.observed_at).bind(snapshot.initialized).bind(snapshot.continuous)
        .bind(i32::try_from(snapshot.pod_count).unwrap_or(i32::MAX)).bind(i32::try_from(snapshot.ready_pod_count).unwrap_or(i32::MAX))
        .bind(i32::try_from(snapshot.workload_ready_pod_count).unwrap_or(i32::MAX)).execute(&mut *tx).await?;
    let pod_count = i32::try_from(snapshot.pod_count).unwrap_or(i32::MAX);
    let ready_count = i32::try_from(snapshot.ready_pod_count).unwrap_or(i32::MAX);
    let workload_ready = i32::try_from(snapshot.workload_ready_pod_count).unwrap_or(i32::MAX);
    if snapshot.initialized && snapshot.continuous && snapshot.pod_count == 0 {
        let stabilization = stabilization_seconds(
            std::env::var("OKOSCOPE_RELEASE_EPISODE_STABILIZATION_SECONDS")
                .ok()
                .as_deref(),
        );
        sqlx::query("UPDATE deployment_episodes SET pod_count=0,ready_pod_count=0,workload_ready_pod_count=$2,snapshot_observed_at=$3,state='inactive',ended_at=$3 WHERE revision_id=$1 AND state<>'inactive' AND $3>=last_observed_at+($4::double precision*interval '1 second')")
            .bind(revision_id).bind(workload_ready).bind(snapshot.observed_at).bind(stabilization)
            .execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE deployment_episodes SET pod_count=$2,ready_pod_count=$3,workload_ready_pod_count=$4,snapshot_observed_at=$5,last_observed_at=GREATEST(last_observed_at,$5) WHERE revision_id=$1 AND state<>'inactive'")
            .bind(revision_id).bind(pod_count).bind(ready_count).bind(workload_ready)
            .bind(snapshot.observed_at).execute(&mut *tx).await?;
    }
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapConfig, bootstrap};
    use event_model::{ContainerCategory, ReleaseIdentity};

    #[test]
    fn stabilization_configuration_is_bounded() {
        assert_eq!(stabilization_seconds(None), 120);
        assert_eq!(stabilization_seconds(Some("30")), 30);
        assert_eq!(stabilization_seconds(Some("3600")), 3600);
        for invalid in ["", "29", "3601", "no"] {
            assert_eq!(stabilization_seconds(Some(invalid)), 120);
        }
    }

    #[test]
    fn transition_classification_is_conservative_and_deterministic() {
        let current = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert_eq!(transition_kind(0, current, &[]), "unknown");
        assert_eq!(transition_kind(0, current, &[other]), "rollout");
        assert_eq!(transition_kind(0, current, &[other, current]), "concurrent");
        assert_eq!(transition_kind(1, current, &[other]), "rollback_candidate");
        assert_eq!(transition_kind(1, current, &[current]), "rollout");
    }

    fn config() -> BootstrapConfig {
        BootstrapConfig {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            cluster_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            organization_slug: "release-state-machine".into(),
            organization_name: "Release State Machine".into(),
            project_slug: "project".into(),
            project_name: "Project".into(),
            cluster_external_id: "cluster".into(),
            cluster_name: "Cluster".into(),
            application_slug: "application".into(),
            application_name: "Application".into(),
            cluster_credential: "cluster-credential".into(),
            api_credential: "api-credential".into(),
        }
    }

    fn evidence(
        digest: &str,
        replica_set_uid: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> WorkloadRevisionEvidence {
        WorkloadRevisionEvidence {
            evidence_id: format!("pod-{replica_set_uid}"),
            observed_at,
            namespace: "production".into(),
            workload_uid: "deployment-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "application".into(),
            replica_set_uid: replica_set_uid.into(),
            replica_set_name: replica_set_uid.into(),
            pod_uid: format!("pod-{replica_set_uid}"),
            pod_template_hash: Some(replica_set_uid.into()),
            release_identity: ReleaseIdentity::from_images([(
                ContainerCategory::Application,
                "application",
                "registry/application:tag",
                format!("registry/application@sha256:{digest}"),
            )])
            .unwrap(),
            ready: true,
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn rollout_concurrency_and_rollback_are_idempotent(pool: PgPool) {
        let ids = bootstrap(&pool, &config()).await.unwrap();
        let scope = SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        };
        let application = ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: ids.organization_id,
            project_id: ids.project_id,
            application_id: ids.application_id,
        };
        let now = chrono::Utc::now();
        let release_a = evidence(&"aa".repeat(32), "rs-a", now);
        let release_b = evidence(&"bb".repeat(32), "rs-b", now + chrono::Duration::seconds(1));
        persist_revision_evidence(&pool, scope, application, &release_a)
            .await
            .unwrap();
        persist_revision_evidence(&pool, scope, application, &release_a)
            .await
            .unwrap();
        persist_revision_evidence(&pool, scope, application, &release_b)
            .await
            .unwrap();
        let revision_b = revision_digest(&release_b);
        let zero_snapshot = RevisionReadinessSnapshot {
            snapshot_id: "zero-b".into(),
            observed_at: now + chrono::Duration::seconds(2),
            initialized: false,
            continuous: true,
            revision_digest: revision_b,
            pod_count: 0,
            ready_pod_count: 0,
            workload_ready_pod_count: 0,
        };
        persist_readiness_snapshot(&pool, scope, application, &zero_snapshot)
            .await
            .unwrap();
        persist_readiness_snapshot(&pool, scope, application, &zero_snapshot)
            .await
            .unwrap();
        let share: Option<f64> = sqlx::query_scalar("SELECT CASE WHEN workload_ready_pod_count>0 THEN ready_pod_count::double precision/workload_ready_pod_count::double precision END FROM deployment_episodes e JOIN kubernetes_workload_revisions r ON r.id=e.revision_id WHERE r.replica_set_uid='rs-b'")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(share, None);
        let revision_a = revision_digest(&release_a);
        persist_readiness_snapshot(
            &pool,
            scope,
            application,
            &RevisionReadinessSnapshot {
                snapshot_id: "partial-a".into(),
                observed_at: now + chrono::Duration::minutes(3),
                initialized: false,
                continuous: false,
                revision_digest: revision_a,
                pod_count: 0,
                ready_pod_count: 0,
                workload_ready_pod_count: 1,
            },
        )
        .await
        .unwrap();
        let state: String = sqlx::query_scalar("SELECT state FROM deployment_episodes e JOIN kubernetes_workload_revisions r ON r.id=e.revision_id WHERE r.replica_set_uid='rs-a'")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(state, "active");
        persist_readiness_snapshot(
            &pool,
            scope,
            application,
            &RevisionReadinessSnapshot {
                snapshot_id: "complete-a".into(),
                observed_at: now + chrono::Duration::minutes(6),
                initialized: true,
                continuous: true,
                revision_digest: revision_a,
                pod_count: 0,
                ready_pod_count: 0,
                workload_ready_pod_count: 1,
            },
        )
        .await
        .unwrap();
        let mut returned_a = release_a.clone();
        returned_a.observed_at = now + chrono::Duration::minutes(7);
        persist_revision_evidence(&pool, scope, application, &returned_a)
            .await
            .unwrap();
        let rows: Vec<(String, i64)> = sqlx::query_as("SELECT e.transition_kind,e.occurrence_number FROM deployment_episodes e JOIN kubernetes_workload_revisions r ON r.id=e.revision_id WHERE r.replica_set_uid='rs-a' ORDER BY e.occurrence_number")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(
            rows,
            vec![("unknown".into(), 1), ("rollback_candidate".into(), 2)]
        );
        let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM releases),(SELECT count(*) FROM kubernetes_workload_revisions),(SELECT count(*) FROM deployment_episodes)")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(counts, (2, 2, 3));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn concurrent_reports_converge_and_conflicts_roll_back(pool: PgPool) {
        let ids = bootstrap(&pool, &config()).await.unwrap();
        let scope = SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        };
        let application = ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: ids.organization_id,
            project_id: ids.project_id,
            application_id: ids.application_id,
        };
        let now = chrono::Utc::now();
        let report = evidence(&"cc".repeat(32), "rs-concurrent", now);
        let first = persist_revision_evidence(&pool, scope, application, &report);
        let second = persist_revision_evidence(&pool, scope, application, &report);
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM releases),(SELECT count(*) FROM kubernetes_workload_revisions),(SELECT count(*) FROM deployment_episodes)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 1, 1));

        let conflicting = evidence(&"dd".repeat(32), "rs-concurrent", now);
        assert!(
            persist_revision_evidence(&pool, scope, application, &conflicting)
                .await
                .is_err()
        );
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM releases),(SELECT count(*) FROM kubernetes_workload_revisions)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 1));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires a PostgreSQL server with DATABASE_URL"]
    async fn failed_rollout_and_deployment_recreation_preserve_release_identity(pool: PgPool) {
        let ids = bootstrap(&pool, &config()).await.unwrap();
        let scope = SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        };
        let application = ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: ids.organization_id,
            project_id: ids.project_id,
            application_id: ids.application_id,
        };
        let now = chrono::Utc::now();
        let mut failed = evidence(&"ee".repeat(32), "rs-failed", now);
        failed.ready = false;
        persist_revision_evidence(&pool, scope, application, &failed)
            .await
            .unwrap();
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM releases),(SELECT count(*) FROM kubernetes_workload_revisions),(SELECT count(*) FROM deployment_episodes)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 1, 0));

        let mut recreated = failed.clone();
        recreated.evidence_id = "pod-recreated".into();
        recreated.workload_uid = "deployment-recreated".into();
        recreated.replica_set_uid = "rs-recreated".into();
        recreated.replica_set_name = "rs-recreated".into();
        recreated.pod_uid = "pod-recreated".into();
        recreated.pod_template_hash = Some("recreated".into());
        recreated.observed_at = now + chrono::Duration::seconds(1);
        recreated.ready = true;
        persist_revision_evidence(&pool, scope, application, &recreated)
            .await
            .unwrap();
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM releases),(SELECT count(*) FROM kubernetes_workload_revisions),(SELECT count(*) FROM deployment_episodes)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 2, 1));
    }
}
