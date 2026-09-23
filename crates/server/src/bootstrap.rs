use crate::repository::applications::ApplicationRepository;
use crate::repository::clusters::ClusterRepository;
use crate::repository::organizations::OrganizationRepository;
use crate::repository::projects::ProjectRepository;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub cluster_id: Uuid,
    pub application_id: Uuid,
    pub organization_slug: String,
    pub organization_name: String,
    pub project_slug: String,
    pub project_name: String,
    pub cluster_external_id: String,
    pub cluster_name: String,
    pub application_slug: String,
    pub application_name: String,
    pub cluster_credential: String,
    /// Legacy test-fixture value retained while integration tests move to user sessions.
    pub api_credential: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapIds {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub cluster_id: Uuid,
    pub application_id: Uuid,
}

pub async fn bootstrap(
    pool: &PgPool,
    config: &BootstrapConfig,
) -> Result<BootstrapIds, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let organization_id = upsert_organization(&mut tx, config).await?;
    let project_id = upsert_project(&mut tx, organization_id, config).await?;
    let cluster_id = upsert_cluster(&mut tx, organization_id, config).await?;
    let application_id = upsert_application(&mut tx, organization_id, project_id, config).await?;
    upsert_credential(
        &mut tx,
        organization_id,
        cluster_id,
        &config.cluster_credential,
    )
    .await?;
    tx.commit().await?;
    Ok(BootstrapIds {
        organization_id,
        project_id,
        cluster_id,
        application_id,
    })
}

async fn upsert_organization(
    tx: &mut Transaction<'_, Postgres>,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    OrganizationRepository::upsert_by_slug(
        &mut **tx,
        c.organization_id,
        &c.organization_slug,
        &c.organization_name,
    )
    .await
}

async fn upsert_project(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    ProjectRepository::upsert_by_slug(
        &mut **tx,
        c.project_id,
        organization_id,
        &c.project_slug,
        &c.project_name,
    )
    .await
}

async fn upsert_cluster(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    ClusterRepository::upsert(
        &mut **tx,
        c.cluster_id,
        organization_id,
        &c.cluster_external_id,
        &c.cluster_name,
    )
    .await
}

async fn upsert_application(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    ApplicationRepository::upsert_by_slug(
        &mut **tx,
        c.application_id,
        organization_id,
        project_id,
        &c.application_slug,
        &c.application_name,
    )
    .await
}

async fn upsert_credential(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cluster_id: Uuid,
    credential: &str,
) -> Result<(), sqlx::Error> {
    let hash = Sha256::digest(credential.as_bytes()).to_vec();
    ClusterRepository::upsert_credential(
        &mut **tx,
        Uuid::new_v4(),
        organization_id,
        cluster_id,
        hash,
    )
    .await?;
    Ok(())
}
