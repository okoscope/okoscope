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
    sqlx::query_scalar("INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3) ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id")
        .bind(c.organization_id).bind(&c.organization_slug).bind(&c.organization_name).fetch_one(&mut **tx).await
}

async fn upsert_project(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO projects (id, organization_id, slug, name) VALUES ($1, $2, $3, $4) ON CONFLICT (organization_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id")
        .bind(c.project_id).bind(organization_id).bind(&c.project_slug).bind(&c.project_name).fetch_one(&mut **tx).await
}

async fn upsert_cluster(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO clusters (id, organization_id, external_id, name) VALUES ($1, $2, $3, $4) ON CONFLICT (organization_id, external_id) DO UPDATE SET name = EXCLUDED.name RETURNING id")
        .bind(c.cluster_id).bind(organization_id).bind(&c.cluster_external_id).bind(&c.cluster_name).fetch_one(&mut **tx).await
}

async fn upsert_application(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    c: &BootstrapConfig,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO applications (id, organization_id, project_id, slug, name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (project_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id")
        .bind(c.application_id).bind(organization_id).bind(project_id).bind(&c.application_slug).bind(&c.application_name).fetch_one(&mut **tx).await
}

async fn upsert_credential(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cluster_id: Uuid,
    credential: &str,
) -> Result<(), sqlx::Error> {
    let hash = Sha256::digest(credential.as_bytes()).to_vec();
    sqlx::query("INSERT INTO cluster_credentials (id, organization_id, cluster_id, credential_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (credential_hash) DO UPDATE SET revoked_at = NULL")
        .bind(Uuid::new_v4()).bind(organization_id).bind(cluster_id).bind(hash).execute(&mut **tx).await?;
    Ok(())
}
