//! Seed only the dedicated local browser-test database through normal ingestion.
use anyhow::{Result, ensure};
use chrono::{Duration, Utc};
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    RuntimeEvent,
};
use server::{
    auth::SessionScope,
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    ingestion::{IngestionContext, persist_batch},
};
use uuid::Uuid;
fn config(name: &str) -> BootstrapConfig {
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: name.into(),
        organization_name: name.into(),
        project_slug: "project".into(),
        project_name: "Project".into(),
        cluster_external_id: "cluster".into(),
        cluster_name: "Cluster".into(),
        application_slug: "app".into(),
        application_name: "App".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn event(
    ids: &BootstrapIds,
    release: Option<&str>,
    executable: &str,
    observed_at: chrono::DateTime<Utc>,
) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at,
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: ids.project_id,
            application_id: ids.application_id,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_uid: Uuid::new_v4().to_string(),
            pod_name: "app-1".into(),
            container_id: Uuid::new_v4().to_string(),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: release.map(str::to_owned),
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 1,
            tgid: 1,
            command: "app".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: executable.into(),
            parent_command: None,
        }),
    }
}

async fn agent(pool: &sqlx::PgPool, ids: &BootstrapIds) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node','test')")
        .bind(id).bind(ids.organization_id).bind(ids.cluster_id).execute(pool).await.unwrap();
    id
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let parsed = url::Url::parse(&url)?;
    ensure!(
        matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")),
        "fixture requires localhost"
    );
    let pool = sqlx::PgPool::connect(&url).await?;
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await?;
    ensure!(
        database == "okoscope_retention_browser",
        "fixture requires dedicated browser database"
    );
    let name = format!("retention-{}", Uuid::new_v4());
    let ids = bootstrap(&pool, &config(&name)).await?;
    let other = bootstrap(&pool, &config(&format!("other-{}", Uuid::new_v4()))).await?;
    let password = "Retention-e2e-only-2026!";
    let owner_email = format!("owner-{name}@example.test");
    let member_email = format!("member-{name}@example.test");
    let other_email = format!("other-{name}@example.test");
    server::user_auth::bootstrap_owner(&pool, ids.organization_id, &owner_email, password).await?;
    server::user_auth::bootstrap_owner(&pool, other.organization_id, &other_email, password)
        .await?;
    let member = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(member)
        .bind(&member_email)
        .bind(
            server::auth::hash_password(password)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        )
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'member')",
    )
    .bind(ids.organization_id)
    .bind(member)
    .execute(&pool)
    .await?;
    let now = Utc::now();
    let baseline = seed_release(&pool, &ids, "baseline", now - Duration::days(41)).await?;
    let target = seed_release(&pool, &ids, "target", now - Duration::days(6)).await?;
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        },
        agent_id: agent(&pool, &ids).await,
    };
    let events = [
        event(&ids, Some("baseline"), "/shared", now - Duration::days(40)),
        event(&ids, Some("baseline"), "/old", now - Duration::days(40)),
        event(&ids, Some("target"), "/shared", now - Duration::days(5)),
        event(&ids, Some("target"), "/new", now - Duration::days(5)),
        event(&ids, Some("target"), "/shared", now),
    ];
    ensure!(
        persist_batch(&pool, context, &events).await? == 5,
        "expected five events"
    );
    let groups:Vec<(Uuid,serde_json::Value,i64)> = sqlx::query_as("SELECT id,semantic_summary,occurrence_count FROM runtime_event_groups WHERE project_id=$1 ORDER BY id")
        .bind(ids.project_id).fetch_all(&pool).await?;
    println!(
        "{}",
        serde_json::json!({"organization_id":ids.organization_id,"project_id":ids.project_id,"application_id":ids.application_id,"baseline_id":baseline,"target_id":target,"owner_email":owner_email,"member_email":member_email,"other_email":other_email,"other_organization_id":other.organization_id,"other_project_id":other.project_id,"groups":groups})
    );
    Ok(())
}
async fn seed_release(
    pool: &sqlx::PgPool,
    ids: &BootstrapIds,
    version: &str,
    at: chrono::DateTime<Utc>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(version).bind(at).execute(pool).await?;
    Ok(id)
}
