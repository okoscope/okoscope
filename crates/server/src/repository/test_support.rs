//! Fixtures for repository tests.
//!
//! Tenants are created with the same `bootstrap` operators use, and runtime
//! data is produced by feeding events through the real ingestion pipeline, so
//! groups, memberships, inventory items and release summaries exist exactly as
//! production code creates them rather than as hand-assembled rows.

use chrono::Duration;
use chrono::{DateTime, Utc};
use event_model::{
    ContainerCategory, ContainerRestart, ContainerTermination, DnsDirection, DnsName, DnsQueryType,
    DnsTransport, EVENT_SCHEMA_VERSION, EventPayload, GenerationCorrelation, KubernetesAttribution,
    NetworkDnsQuery, ProcessExec, ProcessExit, ProcessIdentity, ProcessTermination,
    ReleaseIdentity, RuntimeEvent, UnresolvedGenerationReason, WorkloadRevisionEvidence,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::application_credentials::ApplicationCredentialScope;
use crate::auth::SessionScope;
use crate::bootstrap::{BootstrapConfig, bootstrap};
use crate::ingestion::{IngestionContext, persist_batch};
use crate::release_discovery::persist_revision_evidence;

/// A bootstrapped organization, project, cluster and application, with an
/// agent registered in the cluster to report events.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug)]
pub struct Tenant {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub cluster_id: Uuid,
    pub application_id: Uuid,
    pub agent_id: Uuid,
}

/// Bootstraps a fresh tenant. `name` must be unique within the test.
pub async fn tenant(pool: &PgPool, name: &str) -> Tenant {
    let ids = bootstrap(
        pool,
        &BootstrapConfig {
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
            application_name: "Application".into(),
            cluster_credential: format!("cluster-{name}"),
            api_credential: format!("api-{name}"),
        },
    )
    .await
    .unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-a','test')",
    )
    .bind(agent_id)
    .bind(ids.organization_id)
    .bind(ids.cluster_id)
    .execute(pool)
    .await
    .unwrap();
    Tenant {
        organization_id: ids.organization_id,
        project_id: ids.project_id,
        cluster_id: ids.cluster_id,
        application_id: ids.application_id,
        agent_id,
    }
}

/// A runtime event from the tenant's application, observed at `observed_at`.
pub fn event(tenant: &Tenant, payload: EventPayload, observed_at: DateTime<Utc>) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at,
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: tenant.project_id,
            application_id: tenant.application_id,
            node_name: "node-a".into(),
            namespace: "production".into(),
            pod_uid: Uuid::new_v4().to_string(),
            pod_name: "app-1".into(),
            container_id: Uuid::new_v4().to_string(),
            container_name: "app".into(),
            workload_uid: "workload-a".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 10,
            tgid: 10,
            command: "app".into(),
        },
        payload,
    }
}

/// A process execution of `executable`, which groups by executable.
pub fn exec(tenant: &Tenant, executable: &str, observed_at: DateTime<Utc>) -> RuntimeEvent {
    event(
        tenant,
        EventPayload::ProcessExec(ProcessExec {
            executable: executable.into(),
            parent_command: None,
        }),
        observed_at,
    )
}

/// An egress DNS query for `name` issued by `command`.
pub fn dns(tenant: &Tenant, name: &str, query_type: DnsQueryType, command: &str) -> RuntimeEvent {
    let mut value = event(
        tenant,
        EventPayload::NetworkDnsQuery(NetworkDnsQuery {
            transaction_id: rand::random(),
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: DnsName::new(name).unwrap(),
            query_type,
        }),
        Utc::now(),
    );
    value.process.command = command.into();
    value
}

/// Feeds events through ingestion as the tenant's agent would.
pub async fn ingest(pool: &PgPool, tenant: &Tenant, events: &[RuntimeEvent]) {
    persist_batch(
        pool,
        IngestionContext {
            scope: SessionScope {
                organization_id: tenant.organization_id,
                cluster_id: tenant.cluster_id,
            },
            agent_id: tenant.agent_id,
        },
        events,
    )
    .await
    .unwrap();
}

/// The ids of the tenant application's runtime groups, oldest first.
pub async fn group_ids(pool: &PgPool, tenant: &Tenant) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM runtime_event_groups WHERE organization_id=$1 AND application_id=$2 ORDER BY first_seen_at,id",
    )
    .bind(tenant.organization_id)
    .bind(tenant.application_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Reports a ready pod of a new workload revision whose application image has
/// the given 64-hex-digit digest, as the agent's revision discovery would.
/// Produces the observed release, the revision and its deployment episode,
/// and links the episode to the one it replaced. Returns the release id.
pub async fn observe_revision(
    pool: &PgPool,
    tenant: &Tenant,
    digest: &str,
    replica_set: &str,
    observed_at: DateTime<Utc>,
) -> Uuid {
    let release_identity = ReleaseIdentity::from_images([(
        ContainerCategory::Application,
        "api",
        "registry/api:latest",
        format!("registry/api@sha256:{digest}"),
    )])
    .unwrap();
    let identity_digest = release_identity.digest;
    persist_revision_evidence(
        pool,
        SessionScope {
            organization_id: tenant.organization_id,
            cluster_id: tenant.cluster_id,
        },
        ApplicationCredentialScope {
            credential_id: Uuid::new_v4(),
            organization_id: tenant.organization_id,
            project_id: tenant.project_id,
            application_id: tenant.application_id,
        },
        &WorkloadRevisionEvidence {
            evidence_id: format!("pod-{replica_set}"),
            observed_at,
            namespace: "production".into(),
            workload_uid: "deployment-api".into(),
            workload_kind: "Deployment".into(),
            workload_name: "api".into(),
            replica_set_uid: replica_set.into(),
            replica_set_name: replica_set.into(),
            pod_uid: format!("pod-{replica_set}"),
            pod_template_hash: Some(replica_set.into()),
            release_identity,
            ready: true,
        },
    )
    .await
    .unwrap();
    sqlx::query_scalar(
        "SELECT id FROM releases WHERE organization_id=$1 AND application_id=$2 AND identity_digest=$3",
    )
    .bind(tenant.organization_id)
    .bind(tenant.application_id)
    .bind(identity_digest.as_slice())
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Creates a manual release of the tenant's application.
pub async fn manual_release(
    pool: &PgPool,
    tenant: &Tenant,
    version: &str,
    deployed_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(tenant.organization_id)
    .bind(tenant.project_id)
    .bind(tenant.application_id)
    .bind(version)
    .bind(deployed_at)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// A process execution attributed to a release by its version string.
pub fn exec_in_release(
    tenant: &Tenant,
    executable: &str,
    version: &str,
    observed_at: DateTime<Utc>,
) -> RuntimeEvent {
    let mut value = exec(tenant, executable, observed_at);
    value.attribution.release = Some(version.into());
    value
}

/// A verified, active user.
pub async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,$2,$3,now())",
    )
    .bind(id)
    .bind(format!("{id}@example.test"))
    .bind("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZQ$0123456789abcdef")
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Pins an event to one pod and container, so lifecycle, kernel and restart
/// events about that container correlate with each other.
fn in_container(mut value: RuntimeEvent) -> RuntimeEvent {
    value.attribution.pod_uid = "pod-uid".into();
    value.attribution.container_id = "abc".into();
    value.attribution.container_name = "app".into();
    value
}

/// A kernel SIGKILL exit and the container OOM termination that explains it,
/// which ingestion correlates. Returns `[kernel, lifecycle]`.
pub fn correlated_termination(tenant: &Tenant, at: DateTime<Utc>) -> [RuntimeEvent; 2] {
    let kernel = in_container(event(
        tenant,
        EventPayload::ProcessExit(ProcessExit::new(
            9,
            ProcessTermination::signaled(9, "SIGKILL", false).unwrap(),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::BeforeObservation,
            },
        )),
        at,
    ));
    let lifecycle = in_container(event(
        tenant,
        EventPayload::ContainerTermination(termination(at)),
        at + Duration::seconds(1),
    ));
    [kernel, lifecycle]
}

fn termination(at: DateTime<Utc>) -> ContainerTermination {
    ContainerTermination::new(
        "abc",
        "OOMKilled",
        137,
        Some(at - Duration::seconds(2)),
        Some(at),
    )
    .unwrap()
}

/// `count` consecutive restarts of one container, a minute apart — three or
/// more form a restart loop.
pub fn restarts(tenant: &Tenant, at: DateTime<Utc>, count: u32) -> Vec<RuntimeEvent> {
    (1..=count)
        .map(|index| {
            in_container(event(
                tenant,
                EventPayload::ContainerRestart(
                    ContainerRestart::new(
                        "abc",
                        index,
                        1,
                        Some(termination(at)),
                        Some("CrashLoopBackOff".into()),
                    )
                    .unwrap(),
                ),
                at + Duration::minutes(i64::from(index)),
            ))
        })
        .collect()
}
