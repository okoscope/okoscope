//! Agent installations: the Helm installations an application's owners set
//! up, each holding one ingestion credential, and the status the installed
//! agents report back.
//!
//! The installation projection belongs to the onboarding endpoints, so the
//! reads returning it are generic over the row type; [`INSTALL_SELECT`] lists
//! its columns.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// The installation projection the endpoints read.
///
/// Selects `id`, `application_id`, `credential_id`, `cluster_name`,
/// `workload_namespace`, `workload_kind`, `workload_name`, `workload_labels`,
/// `chart_version`, `configuration_schema_version`, `created_at` and
/// `updated_at`.
const INSTALL_SELECT: &str = "SELECT id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at FROM application_installations";

/// Agent installations and the evidence of their connection.
#[derive(Clone, Copy, Debug)]
pub struct InstallationRepository;

impl InstallationRepository {
    /// Records the onboarding status a node reports for the application's
    /// installations.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_status<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        node_name: &str,
        state: &str,
        reason: Option<&str>,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO application_installation_status(installation_id,node_name,state,reason,observed_at) SELECT i.id,$4,$5,$6,$7 FROM application_installations i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 ORDER BY i.created_at DESC LIMIT 1 ON CONFLICT(installation_id,node_name) DO UPDATE SET state=EXCLUDED.state,reason=EXCLUDED.reason,observed_at=EXCLUDED.observed_at,updated_at=now() WHERE application_installation_status.observed_at<=EXCLUDED.observed_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(node_name)
            .bind(state)
            .bind(reason)
            .bind(observed_at)
            .execute(executor)
            .await
    }

    /// The application's installations, oldest first, with the columns of
    /// [`INSTALL_SELECT`].
    pub async fn for_application<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INSTALL_SELECT} WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 ORDER BY created_at,id"
        );
        sqlx::query_as(&query)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_all(executor)
            .await
    }

    /// One installation of the application, with the columns of
    /// [`INSTALL_SELECT`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let query = format!(
            "{INSTALL_SELECT} WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4"
        );
        sqlx::query_as(&query)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(installation_id)
            .fetch_optional(executor)
            .await
    }

    /// The organization's installation created under this idempotency key.
    ///
    /// Selects the columns of [`INSTALL_SELECT`] and `request_hash`.
    pub async fn by_idempotency_key<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at,request_hash FROM application_installations WHERE organization_id=$1 AND idempotency_key=$2")
            .bind(organization_id)
            .bind(idempotency_key)
            .fetch_optional(executor)
            .await
    }

    /// Records a new installation and returns it with the columns of
    /// [`INSTALL_SELECT`]. A repeated idempotency key violates a unique index.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E, T>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        credential_id: Uuid,
        idempotency_key: &str,
        request_hash: &[u8],
        cluster_name: &str,
        workload_namespace: &str,
        workload_kind: &str,
        workload_name: Option<&str>,
        workload_labels: Option<serde_json::Value>,
        chart_version: &str,
        configuration_schema_version: i32,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("INSERT INTO application_installations(id,organization_id,project_id,application_id,credential_id,idempotency_key,request_hash,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(credential_id)
            .bind(idempotency_key)
            .bind(request_hash)
            .bind(cluster_name)
            .bind(workload_namespace)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(workload_labels)
            .bind(chart_version)
            .bind(configuration_schema_version)
            .fetch_one(executor)
            .await
    }

    /// Updates an installation's cluster and workload intent and returns it
    /// with the columns of [`INSTALL_SELECT`]. `None` when there is no such
    /// installation in the application.
    #[allow(clippy::too_many_arguments)]
    pub async fn update<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
        cluster_name: &str,
        workload_namespace: &str,
        workload_kind: &str,
        workload_name: Option<&str>,
        workload_labels: Option<serde_json::Value>,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE application_installations SET cluster_name=$5,workload_namespace=$6,workload_kind=$7,workload_name=$8,workload_labels=$9,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 RETURNING id,application_id,credential_id,cluster_name,workload_namespace,workload_kind,workload_name,workload_labels,chart_version,configuration_schema_version,created_at,updated_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(installation_id)
            .bind(cluster_name)
            .bind(workload_namespace)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(workload_labels)
            .fetch_optional(executor)
            .await
    }

    /// Locks an installation in the application and returns its credential.
    pub async fn credential_for_update<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        installation_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT credential_id FROM application_installations WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 FOR UPDATE")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(installation_id)
            .fetch_optional(executor)
            .await
    }

    /// Points an installation at a new credential.
    pub async fn set_credential<'e, E>(
        executor: E,
        credential_id: Uuid,
        installation_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE application_installations SET credential_id=$1,updated_at=now() WHERE id=$2",
        )
        .bind(credential_id)
        .bind(installation_id)
        .execute(executor)
        .await
    }

    /// When the credential of the application's newest installation was last
    /// used and when it was revoked. `None` when there is no installation.
    pub async fn latest_credential_use<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Option<DateTime<Utc>>, Option<DateTime<Utc>>)>("SELECT c.last_used_at,c.revoked_at FROM application_installations i JOIN application_ingestion_credentials c ON c.id=i.credential_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 ORDER BY i.created_at DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// The most recently reported installation status of the application:
    /// its state and reason, when it was last reported, and by how many
    /// reports. `None` when nothing was reported.
    pub async fn latest_status<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<(String, Option<String>, DateTime<Utc>, i64)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (String, Option<String>, DateTime<Utc>, i64)>("SELECT s.state,s.reason,max(s.observed_at),count(*) FROM application_installation_status s JOIN application_installations i ON i.id=s.installation_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 GROUP BY s.state,s.reason ORDER BY max(s.observed_at) DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use serde_json::json;
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::InstallationRepository;
    use crate::repository::application_credentials::ApplicationCredentialRepository;
    use crate::repository::events::EventRepository;
    use crate::repository::test_support::{Tenant, exec, ingest, tenant};

    #[derive(Debug, FromRow)]
    struct Installation {
        id: Uuid,
        credential_id: Uuid,
        cluster_name: String,
        workload_name: Option<String>,
        workload_labels: Option<serde_json::Value>,
    }

    #[derive(Debug, FromRow)]
    struct WithHash {
        id: Uuid,
        request_hash: Vec<u8>,
    }

    async fn credential(pool: &PgPool, own: &Tenant) -> Uuid {
        let mut tx = pool.begin().await.unwrap();
        let issued = crate::application_credentials::issue(
            &mut tx,
            own.organization_id,
            own.project_id,
            own.application_id,
            &format!("test-{}", Uuid::new_v4()),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        issued.summary.id
    }

    async fn install(
        pool: &PgPool,
        own: &Tenant,
        credential_id: Uuid,
        key: &str,
    ) -> Result<Installation, sqlx::Error> {
        InstallationRepository::insert(
            pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            own.application_id,
            credential_id,
            key,
            &[1; 32],
            "cluster",
            "production",
            "Deployment",
            Some("api"),
            None,
            "1.0.0",
            1,
        )
        .await
    }

    async fn revoked_at(pool: &PgPool, credential_id: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar("SELECT revoked_at FROM application_ingestion_credentials WHERE id=$1")
            .bind(credential_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Installations are recorded once per idempotency key, updated and read
    /// within their application, and switched to a new credential.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn installations_are_recorded_updated_and_read(pool: PgPool) {
        let own = tenant(&pool, "installations-crud").await;
        let other = tenant(&pool, "installations-crud-other").await;
        let first_credential = credential(&pool, &own).await;
        let first = install(&pool, &own, first_credential, "k1").await.unwrap();
        assert_eq!(
            (first.credential_id, first.workload_name.as_deref()),
            (first_credential, Some("api"))
        );
        let repeated = install(&pool, &own, first_credential, "k1")
            .await
            .unwrap_err();
        assert_eq!(
            repeated
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505")
        );
        let keyed: WithHash =
            InstallationRepository::by_idempotency_key(&pool, own.organization_id, "k1")
                .await
                .unwrap()
                .unwrap();
        assert_eq!((keyed.id, keyed.request_hash), (first.id, vec![1; 32]));
        for (organization_id, key) in [(own.organization_id, "k2"), (other.organization_id, "k1")] {
            assert!(
                InstallationRepository::by_idempotency_key::<_, WithHash>(
                    &pool,
                    organization_id,
                    key
                )
                .await
                .unwrap()
                .is_none()
            );
        }

        let updated: Installation = InstallationRepository::update(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            first.id,
            "renamed",
            "production",
            "Deployment",
            None,
            Some(json!({"app": "api"})),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.cluster_name, "renamed");
        assert_eq!(
            (updated.workload_name, updated.workload_labels),
            (None, Some(json!({"app": "api"})))
        );
        assert!(
            InstallationRepository::update::<_, Installation>(
                &pool,
                other.organization_id,
                other.project_id,
                other.application_id,
                first.id,
                "x",
                "production",
                "Deployment",
                Some("api"),
                None,
            )
            .await
            .unwrap()
            .is_none(),
            "another application's installation is not updated"
        );

        let second = install(&pool, &own, first_credential, "k2").await.unwrap();
        let listed: Vec<Installation> = InstallationRepository::for_application(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(
            listed.iter().map(|i| i.id).collect::<Vec<_>>(),
            [first.id, second.id]
        );
        let read = |organization_id: Uuid| {
            let pool = pool.clone();
            async move {
                InstallationRepository::get::<_, Installation>(
                    &pool,
                    organization_id,
                    own.project_id,
                    own.application_id,
                    first.id,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(
            read(own.organization_id).await.map(|i| i.id),
            Some(first.id)
        );
        assert!(read(other.organization_id).await.is_none());

        let replacement = credential(&pool, &own).await;
        let locked = InstallationRepository::credential_for_update(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            first.id,
        )
        .await
        .unwrap();
        assert_eq!(locked, Some(first_credential));
        ApplicationCredentialRepository::revoke(&pool, first_credential)
            .await
            .unwrap();
        let revoked = revoked_at(&pool, first_credential).await;
        assert!(revoked.is_some());
        ApplicationCredentialRepository::revoke(&pool, first_credential)
            .await
            .unwrap();
        assert_eq!(
            revoked_at(&pool, first_credential).await,
            revoked,
            "the first revocation stays"
        );
        InstallationRepository::set_credential(&pool, replacement, first.id)
            .await
            .unwrap();
        let switched = InstallationRepository::credential_for_update(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            first.id,
        )
        .await
        .unwrap();
        assert_eq!(switched, Some(replacement));
    }

    /// Connection evidence: the event receipt window, the newest
    /// installation's credential use, and the latest reported status.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn connection_evidence(pool: PgPool) {
        let own = tenant(&pool, "installations-evidence").await;
        let window = || {
            EventRepository::received_window(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
        };
        let credential_use = || {
            InstallationRepository::latest_credential_use(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
        };
        let status = || {
            InstallationRepository::latest_status(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
        };
        assert_eq!(window().await.unwrap(), (None, None));
        assert_eq!(credential_use().await.unwrap(), None);
        assert_eq!(status().await.unwrap(), None);

        ingest(
            &pool,
            &own,
            &[
                exec(&own, "/bin/a", Utc::now()),
                exec(&own, "/bin/b", Utc::now()),
            ],
        )
        .await;
        let (earliest, latest) = window().await.unwrap();
        assert!(earliest.is_some() && earliest <= latest);

        let older_credential = credential(&pool, &own).await;
        let older = install(&pool, &own, older_credential, "older")
            .await
            .unwrap();
        sqlx::query(
            "UPDATE application_installations SET created_at=now()-interval '1 hour' WHERE id=$1",
        )
        .bind(older.id)
        .execute(&pool)
        .await
        .unwrap();
        let newest_credential = credential(&pool, &own).await;
        let newest = install(&pool, &own, newest_credential, "newest")
            .await
            .unwrap();
        assert_eq!(credential_use().await.unwrap(), Some((None, None)));
        ApplicationCredentialRepository::revoke(&pool, older_credential)
            .await
            .unwrap();
        assert_eq!(
            credential_use().await.unwrap(),
            Some((None, None)),
            "only the newest installation counts"
        );
        ApplicationCredentialRepository::revoke(&pool, newest_credential)
            .await
            .unwrap();
        assert!(credential_use().await.unwrap().unwrap().1.is_some());

        let now = Utc::now().trunc_subsecs(0);
        for (installation, node, state, reason, minutes) in [
            (older.id, "node-a", "agent_authenticated", None, 20),
            (
                newest.id,
                "node-a",
                "waiting_for_event",
                Some("event_not_observed"),
                10,
            ),
            (
                newest.id,
                "node-b",
                "waiting_for_event",
                Some("event_not_observed"),
                5,
            ),
        ] {
            sqlx::query(
                "INSERT INTO application_installation_status(installation_id,node_name,state,reason,observed_at) VALUES($1,$2,$3,$4,$5)",
            )
            .bind(installation)
            .bind(node)
            .bind(state)
            .bind(reason)
            .bind(now - Duration::minutes(minutes))
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(
            status().await.unwrap(),
            Some((
                "waiting_for_event".to_owned(),
                Some("event_not_observed".to_owned()),
                now - Duration::minutes(5),
                2
            ))
        );
    }
}
