//! Seed a dedicated browser-test database through the normal ingestion projection.

use std::{env, net::IpAddr};

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use event_model::{
    DnsDirection, DnsName, DnsQueryType, DnsTransport, EVENT_SCHEMA_VERSION, EventPayload,
    FileActivityPath, FileModify, KubernetesAttribution, NetworkAddressFamily, NetworkConnect,
    NetworkConnectOutcome, NetworkDnsQuery, ProcessIdentity, RuntimeEvent, SyscallEvent,
};
use server::{
    auth::SessionScope,
    ingestion::{IngestionContext, persist_batch},
};
use uuid::Uuid;

fn event(
    project_id: Uuid,
    application_id: Uuid,
    command: &str,
    payload: EventPayload,
) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at: Utc::now() - Duration::seconds(2),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id,
            application_id,
            node_name: "e2e-node".into(),
            namespace: "e2e".into(),
            pod_uid: "e2e-pod-uid".into(),
            pod_name: "e2e-app-1".into(),
            container_id: "e2e-container-id".into(),
            container_name: "e2e-app".into(),
            workload_uid: "e2e-workload-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "e2e-app".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 42,
            pid: 100,
            tgid: 100,
            command: command.into(),
        },
        payload,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let organization_id = env::var("ORGANIZATION_ID")?.parse()?;
    let project_id = env::var("PROJECT_ID")?.parse()?;
    let application_id = env::var("APPLICATION_ID")?.parse()?;
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let cluster_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,'e2e-cluster','E2E Cluster')")
        .bind(cluster_id).bind(organization_id).execute(&pool).await?;
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'e2e-node','test')")
        .bind(agent_id).bind(organization_id).bind(cluster_id).execute(&pool).await?;
    let destination = || {
        EventPayload::NetworkConnect(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv4,
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                5432,
                NetworkConnectOutcome::Succeeded,
                None,
            )
            .unwrap(),
        )
    };
    let domain = || {
        EventPayload::NetworkDnsQuery(NetworkDnsQuery {
            transaction_id: 7,
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "192.0.2.53".parse().unwrap(),
            name: DnsName::new("db.example.test").unwrap(),
            query_type: DnsQueryType::A,
        })
    };
    let syscall = || {
        EventPayload::Syscall(SyscallEvent {
            name: "openat".into(),
        })
    };
    let file = || {
        EventPayload::FileModify(FileModify {
            path: FileActivityPath::new("/var/lib/e2e/data.db").unwrap(),
        })
    };
    let mut events = Vec::new();
    for command in ["r-api", "actix-rt|system"] {
        events.push(event(project_id, application_id, command, destination()));
        events.push(event(project_id, application_id, command, domain()));
        events.push(event(project_id, application_id, command, syscall()));
        events.push(event(project_id, application_id, command, file()));
    }
    let context = IngestionContext {
        scope: SessionScope {
            organization_id,
            cluster_id,
        },
        agent_id,
    };
    persist_batch(&pool, context, &events).await?;
    println!("{organization_id} {project_id} {application_id}");
    Ok(())
}
