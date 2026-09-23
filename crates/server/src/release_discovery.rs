use crate::repository::deployments::DeploymentRepository;
use crate::repository::releases::ReleaseRepository;
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
    let revision_id: Option<Uuid> = DeploymentRepository::insert_revision(
        &mut *tx,
        Uuid::new_v4(),
        scope.organization_id,
        application.project_id,
        application.application_id,
        scope.cluster_id,
        release_id,
        i16::try_from(evidence.release_identity.version).unwrap_or(i16::MAX),
        digest.as_slice(),
        &evidence.namespace,
        &evidence.workload_uid,
        &evidence.workload_kind,
        &evidence.workload_name,
        &evidence.replica_set_uid,
        &evidence.replica_set_name,
        evidence.pod_template_hash.as_deref(),
        evidence.observed_at,
    )
    .await?;
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
    DeploymentRepository::lock_revision(
        &mut **tx,
        format!(
            "{}:{}:{}:{}",
            application.application_id,
            scope.cluster_id,
            evidence.workload_uid,
            evidence.replica_set_uid
        ),
    )
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
    ReleaseRepository::insert_observed(
        &mut **tx,
        Uuid::new_v4(),
        organization_id,
        project_id,
        application_id,
        version,
        observed_at,
        i16::try_from(identity.version).unwrap_or(i16::MAX),
        identity.digest.as_slice(),
        to_value(&identity.containers).expect("release components serialize"),
    )
    .await
}

async fn open_episode(
    tx: &mut Transaction<'_, Postgres>,
    scope: SessionScope,
    application: ApplicationCredentialScope,
    release_id: Uuid,
    revision_id: Uuid,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    let prior_count: i64 = DeploymentRepository::episode_count(&mut **tx, revision_id).await?;
    let existing: Option<Uuid> = DeploymentRepository::open_episode(&mut **tx, revision_id).await?;
    if let Some(id) = existing {
        DeploymentRepository::touch_episode(&mut **tx, id, observed_at).await?;
        return Ok(());
    }
    let predecessors: Vec<(Uuid, Uuid)> = DeploymentRepository::active_episodes(
        &mut **tx,
        scope.organization_id,
        application.application_id,
        scope.cluster_id,
    )
    .await?;
    let predecessor_releases: Vec<_> = predecessors.iter().map(|(_, id)| *id).collect();
    let transition = transition_kind(prior_count, release_id, &predecessor_releases);
    let episode_id = Uuid::new_v4();
    DeploymentRepository::insert_episode(
        &mut **tx,
        episode_id,
        scope.organization_id,
        application.project_id,
        application.application_id,
        scope.cluster_id,
        release_id,
        revision_id,
        prior_count + 1,
        transition,
        observed_at,
    )
    .await?;
    for (predecessor_id, _) in predecessors {
        DeploymentRepository::link_predecessor(
            &mut **tx,
            scope.organization_id,
            application.project_id,
            application.application_id,
            episode_id,
            predecessor_id,
            observed_at,
        )
        .await?;
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
    let revision_id: Option<Uuid> = DeploymentRepository::revision_by_digest(
        &mut *tx,
        scope.organization_id,
        application.project_id,
        application.application_id,
        scope.cluster_id,
        snapshot.revision_digest.as_slice(),
    )
    .await?;
    let Some(revision_id) = revision_id else {
        tracing::warn!(application_id=%application.application_id, cluster_id=%scope.cluster_id, "readiness snapshot has no known scoped revision");
        return tx.commit().await;
    };
    DeploymentRepository::insert_snapshot(
        &mut *tx,
        scope.organization_id,
        application.project_id,
        application.application_id,
        scope.cluster_id,
        revision_id,
        &snapshot.snapshot_id,
        snapshot.observed_at,
        snapshot.initialized,
        snapshot.continuous,
        i32::try_from(snapshot.pod_count).unwrap_or(i32::MAX),
        i32::try_from(snapshot.ready_pod_count).unwrap_or(i32::MAX),
        i32::try_from(snapshot.workload_ready_pod_count).unwrap_or(i32::MAX),
    )
    .await?;
    let pod_count = i32::try_from(snapshot.pod_count).unwrap_or(i32::MAX);
    let ready_count = i32::try_from(snapshot.ready_pod_count).unwrap_or(i32::MAX);
    let workload_ready = i32::try_from(snapshot.workload_ready_pod_count).unwrap_or(i32::MAX);
    if snapshot.initialized && snapshot.continuous && snapshot.pod_count == 0 {
        let stabilization = stabilization_seconds(
            std::env::var("OKOSCOPE_RELEASE_EPISODE_STABILIZATION_SECONDS")
                .ok()
                .as_deref(),
        );
        DeploymentRepository::end_episode(
            &mut *tx,
            revision_id,
            workload_ready,
            snapshot.observed_at,
            stabilization,
        )
        .await?;
    } else {
        DeploymentRepository::record_episode_pods(
            &mut *tx,
            revision_id,
            pod_count,
            ready_count,
            workload_ready,
            snapshot.observed_at,
        )
        .await?;
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
