//! Clusters and the agents in them: the clusters of an organization, the
//! credentials a cluster's agents authenticate with, the agents that
//! registered from each node, and their sessions.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Clusters, cluster credentials, agents and agent sessions.
#[derive(Clone, Copy, Debug)]
pub struct ClusterRepository;

impl ClusterRepository {
    /// Records a cluster, or renames the organization's one with this
    /// external id, and returns its id.
    pub async fn upsert<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        external_id: &str,
        name: &str,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO clusters (id, organization_id, external_id, name) VALUES ($1, $2, $3, $4) ON CONFLICT (organization_id, external_id) DO UPDATE SET name = EXCLUDED.name RETURNING id")
            .bind(id)
            .bind(organization_id)
            .bind(external_id)
            .bind(name)
            .fetch_one(executor)
            .await
    }

    /// Records a cluster credential by its hash, or reinstates a revoked one.
    pub async fn upsert_credential<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        cluster_id: Uuid,
        credential_hash: Vec<u8>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO cluster_credentials (id, organization_id, cluster_id, credential_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (credential_hash) DO UPDATE SET revoked_at = NULL")
            .bind(id)
            .bind(organization_id)
            .bind(cluster_id)
            .bind(credential_hash)
            .execute(executor)
            .await
    }

    /// Records the cluster an agent reports by its external id, or updates
    /// its name when one is given, and returns its id.
    pub async fn upsert_by_external_id<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        external_id: String,
        name: Option<&str>,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,$3,COALESCE($4,$3)) ON CONFLICT(organization_id,external_id) DO UPDATE SET name=COALESCE($4,clusters.name) RETURNING id")
            .bind(id)
            .bind(organization_id)
            .bind(external_id)
            .bind(name)
            .fetch_one(executor)
            .await
    }

    /// Records the agent of a node, or refreshes its version, platform and
    /// capabilities, and returns its id.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_agent<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        cluster_id: Uuid,
        node_name: &str,
        agent_version: &str,
        architecture: Option<&str>,
        kernel_release: Option<&str>,
        capabilities: serde_json::Value,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO agents (id, organization_id, cluster_id, node_name, agent_version, architecture, kernel_release, capabilities) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cluster_id, node_name) DO UPDATE SET agent_version=EXCLUDED.agent_version, architecture=EXCLUDED.architecture, kernel_release=EXCLUDED.kernel_release, capabilities=EXCLUDED.capabilities, last_seen_at=now() RETURNING id")
            .bind(id)
            .bind(organization_id)
            .bind(cluster_id)
            .bind(node_name)
            .bind(agent_version)
            .bind(architecture)
            .bind(kernel_release)
            .bind(capabilities)
            .fetch_one(executor)
            .await
    }

    /// Records a new agent session.
    pub async fn open_session<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        cluster_id: Uuid,
        agent_id: Uuid,
        protocol_version: i32,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO agent_sessions (id, organization_id, cluster_id, agent_id, protocol_version) VALUES ($1,$2,$3,$4,$5)")
            .bind(id)
            .bind(organization_id)
            .bind(cluster_id)
            .bind(agent_id)
            .bind(protocol_version)
            .execute(executor)
            .await
    }

    /// Records that the agent was seen now.
    pub async fn touch_agent<'e, E>(
        executor: E,
        agent_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE agents SET last_seen_at=now() WHERE id=$1")
            .bind(agent_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    #[derive(sqlx::FromRow)]
    struct Created {
        id: Uuid,
    }

    use super::ClusterRepository;
    use crate::repository::installations::InstallationRepository;
    use crate::repository::test_support::tenant;
    use crate::repository::{ApplicationRepository, OrganizationRepository, ProjectRepository};

    async fn name_of(pool: &PgPool, table: &str, id: Uuid) -> String {
        sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id=$1"))
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Bootstrap upserts create each level once by its natural key and rename
    /// it on a repeat; a cluster credential is reinstated by its hash.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn bootstrap_upserts_by_natural_key(pool: PgPool) {
        let organization =
            OrganizationRepository::upsert_by_slug(&pool, Uuid::new_v4(), "acme", "Acme")
                .await
                .unwrap();
        assert_eq!(
            OrganizationRepository::upsert_by_slug(&pool, Uuid::new_v4(), "acme", "Acme Inc")
                .await
                .unwrap(),
            organization
        );
        assert_eq!(
            name_of(&pool, "organizations", organization).await,
            "Acme Inc"
        );
        let project =
            ProjectRepository::upsert_by_slug(&pool, Uuid::new_v4(), organization, "web", "Web")
                .await
                .unwrap();
        assert_eq!(
            ProjectRepository::upsert_by_slug(&pool, Uuid::new_v4(), organization, "web", "Web 2")
                .await
                .unwrap(),
            project
        );
        let cluster =
            ClusterRepository::upsert(&pool, Uuid::new_v4(), organization, "ext-1", "One")
                .await
                .unwrap();
        assert_eq!(
            ClusterRepository::upsert(&pool, Uuid::new_v4(), organization, "ext-1", "Renamed")
                .await
                .unwrap(),
            cluster
        );
        assert_eq!(name_of(&pool, "clusters", cluster).await, "Renamed");
        let application = ApplicationRepository::upsert_by_slug(
            &pool,
            Uuid::new_v4(),
            organization,
            project,
            "api",
            "API",
        )
        .await
        .unwrap();
        assert_eq!(
            ApplicationRepository::upsert_by_slug(
                &pool,
                Uuid::new_v4(),
                organization,
                project,
                "api",
                "API 2"
            )
            .await
            .unwrap(),
            application
        );
        assert_eq!(name_of(&pool, "applications", application).await, "API 2");

        ClusterRepository::upsert_credential(
            &pool,
            Uuid::new_v4(),
            organization,
            cluster,
            vec![5; 32],
        )
        .await
        .unwrap();
        sqlx::query("UPDATE cluster_credentials SET revoked_at=now() WHERE credential_hash=$1")
            .bind(vec![5_u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        ClusterRepository::upsert_credential(
            &pool,
            Uuid::new_v4(),
            organization,
            cluster,
            vec![5; 32],
        )
        .await
        .unwrap();
        let state: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT count(*) OVER (),revoked_at FROM cluster_credentials WHERE credential_hash=$1",
        )
        .bind(vec![5_u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, (1, None), "one credential, reinstated");
    }

    /// Agents register once per node, refreshing their details; sessions and
    /// last-seen are recorded; a reported cluster is found by external id
    /// and renamed only when a name is given.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn agents_register_and_open_sessions(pool: PgPool) {
        let own = tenant(&pool, "clusters-agents").await;
        let reported = ClusterRepository::upsert_by_external_id(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            "cluster".into(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(reported, own.cluster_id, "found by external id");
        assert_eq!(
            name_of(&pool, "clusters", reported).await,
            "Cluster",
            "unnamed keeps its name"
        );
        ClusterRepository::upsert_by_external_id(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            "cluster".into(),
            Some("Prod"),
        )
        .await
        .unwrap();
        assert_eq!(name_of(&pool, "clusters", reported).await, "Prod");

        let register = |version: &'static str| {
            let pool = pool.clone();
            async move {
                ClusterRepository::register_agent(
                    &pool,
                    Uuid::new_v4(),
                    own.organization_id,
                    own.cluster_id,
                    "node-b",
                    version,
                    Some("x86_64"),
                    None,
                    json!(["exec"]),
                )
                .await
                .unwrap()
            }
        };
        let agent = register("1.0").await;
        assert_eq!(register("1.1").await, agent, "one agent per node");
        let version: String = sqlx::query_scalar("SELECT agent_version FROM agents WHERE id=$1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, "1.1");
        let session = Uuid::new_v4();
        ClusterRepository::open_session(
            &pool,
            session,
            own.organization_id,
            own.cluster_id,
            agent,
            1,
        )
        .await
        .unwrap();
        let protocol: i32 =
            sqlx::query_scalar("SELECT protocol_version FROM agent_sessions WHERE id=$1")
                .bind(session)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(protocol, 1);
        sqlx::query("UPDATE agents SET last_seen_at=now()-interval '1 day' WHERE id=$1")
            .bind(agent)
            .execute(&pool)
            .await
            .unwrap();
        ClusterRepository::touch_agent(&pool, agent).await.unwrap();
        let recent: bool = sqlx::query_scalar(
            "SELECT last_seen_at>now()-interval '1 minute' FROM agents WHERE id=$1",
        )
        .bind(agent)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(recent);

        let credential = {
            let mut tx = pool.begin().await.unwrap();
            let issued = crate::application_credentials::issue(
                &mut tx,
                own.organization_id,
                own.project_id,
                own.application_id,
                "installer",
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            issued.summary.id
        };
        let installation: Created = InstallationRepository::insert(
            &pool,
            Uuid::new_v4(),
            own.organization_id,
            own.project_id,
            own.application_id,
            credential,
            "key",
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
        .unwrap();
        InstallationRepository::record_status(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            "node-b",
            "waiting_for_event",
            Some("event_not_observed"),
            Utc::now(),
        )
        .await
        .unwrap();
        let status: (String, Option<String>) = sqlx::query_as(
            "SELECT state,reason FROM application_installation_status WHERE installation_id=$1 AND node_name='node-b'",
        )
        .bind(installation.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            status,
            (
                "waiting_for_event".into(),
                Some("event_not_observed".into())
            )
        );
    }
}
