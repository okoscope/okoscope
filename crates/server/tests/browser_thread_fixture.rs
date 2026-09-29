use chrono::{Duration, Utc};
use event_model::{
    BaselineProvenance, EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution,
    ProcessGenerationIdentity, ProcessIdentity, RuntimeEvent, ThreadActivityWindow,
    ThreadNameAggregate,
};
use server::{
    auth::SessionScope,
    bootstrap::{BootstrapConfig, bootstrap},
    ingestion::persist_application_batch,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an isolated browser test database and scope environment"]
async fn seed_browser_thread_windows() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let organization_id = id("E2E_ORG");
    let project_id = id("E2E_PROJECT");
    let application_id = id("E2E_APP");
    let config = BootstrapConfig {
        organization_id,
        project_id,
        application_id,
        cluster_id: Uuid::new_v4(),
        organization_slug: "thread-e2e".into(),
        organization_name: "Thread E2E".into(),
        project_slug: "platform".into(),
        project_name: "Platform".into(),
        application_slug: "gateway".into(),
        application_name: "Gateway".into(),
        cluster_external_id: "browser-fixture".into(),
        cluster_name: "Fixture".into(),
        cluster_credential: "browser-fixture-cluster-credential".into(),
        api_credential: String::new(),
    };
    let ids = bootstrap(&pool, &config).await.unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,$4,'test')")
        .bind(agent_id).bind(organization_id).bind(ids.cluster_id).bind(format!("fixture-{agent_id}")).execute(&pool).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    let issued = server::application_credentials::issue(
        &mut tx,
        organization_id,
        project_id,
        application_id,
        &format!("fixture-{agent_id}"),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let credential = server::application_credentials::authenticate(&pool, issued.token())
        .await
        .unwrap()
        .unwrap();
    let epoch = Uuid::new_v4();
    let count = if std::env::var_os("E2E_SECOND_EPOCH").is_some() {
        1
    } else {
        55
    };
    let mut events: Vec<_> = (0..count)
        .map(|index| {
            thread_window_event(
                project_id,
                application_id,
                Utc::now() - Duration::minutes(i64::from(index) + 2),
                epoch,
            )
        })
        .collect();
    let scope = SessionScope {
        organization_id,
        cluster_id: ids.cluster_id,
    };
    assert_eq!(
        persist_application_batch(&pool, scope, credential, agent_id, &mut events)
            .await
            .unwrap(),
        count
    );
    assert_eq!(
        persist_application_batch(&pool, scope, credential, agent_id, &mut events)
            .await
            .unwrap(),
        0
    );
    let groups: i64 =
        sqlx::query_scalar("SELECT count(*) FROM runtime_event_groups WHERE application_id=$1")
            .bind(application_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(groups, 0);
}

fn id(name: &str) -> Uuid {
    std::env::var(name).unwrap().parse().unwrap()
}

fn thread_window_event(
    project_id: Uuid,
    application_id: Uuid,
    start: chrono::DateTime<Utc>,
    epoch: Uuid,
) -> RuntimeEvent {
    let process = ProcessIdentity {
        cgroup_id: 7,
        pid: 10,
        tgid: 10,
        command: "app".into(),
    };
    let generation = ProcessGenerationIdentity {
        generation: 1,
        observation_epoch: epoch,
        start_observed: true,
    };
    let id = Uuid::new_v4();
    RuntimeEvent {
        id,
        observed_at: start + Duration::seconds(60),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id,
            application_id,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_uid: "pod".into(),
            pod_name: "pod".into(),
            container_id: "container".into(),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: None,
            release_identity: None,
        },
        process: process.clone(),
        payload: EventPayload::ThreadActivityWindow(ThreadActivityWindow {
            id,
            process,
            generation,
            window_started_at: start,
            window_ended_at: start + Duration::seconds(60),
            created: 1,
            exited: 0,
            active_at_start: 0,
            active_at_end: 1,
            peak_active: 1,
            names: vec![ThreadNameAggregate {
                name: "worker".into(),
                created: 1,
                exited: 0,
                active: 1,
            }],
            baseline_provenance: BaselineProvenance::Observed,
            baseline_complete: true,
            name_overflow: 0,
            gaps: vec![],
        }),
    }
}
