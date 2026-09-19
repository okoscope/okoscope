use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::COOKIE},
};
use chrono::{Duration, Utc};
use event_model::{
    ContainerRestart, ContainerTermination, DnsDirection, DnsName, DnsQueryType, DnsTransport,
    EVENT_SCHEMA_VERSION, EventPayload, FileActivityPath, FileModify, GenerationCorrelation,
    KubernetesAttribution, NetworkAccept, NetworkAddressFamily, NetworkConnect,
    NetworkConnectOutcome, NetworkDnsQuery, NetworkListen, ProcessExec, ProcessExit,
    ProcessIdentity, ProcessTermination, RuntimeEvent, SyscallEvent,
};
use server::{
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    dns_group_api,
    ingestion::{IngestionContext, persist_batch},
    inventory_api,
};
use tower::ServiceExt;
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
        application_name: "Application".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn dns_event(
    ids: &BootstrapIds,
    name: &str,
    query_type: DnsQueryType,
    command: &str,
) -> RuntimeEvent {
    let mut value = event(
        ids,
        EventPayload::NetworkDnsQuery(NetworkDnsQuery {
            transaction_id: rand::random(),
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: DnsName::new(name).unwrap(),
            query_type,
        }),
        None,
    );
    value.process.command = command.into();
    value
}

fn event(ids: &BootstrapIds, payload: EventPayload, release: Option<&str>) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at: Utc::now(),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: ids.project_id,
            application_id: ids.application_id,
            node_name: "node-a".into(),
            namespace: "production".into(),
            pod_uid: Uuid::new_v4().to_string(),
            pod_name: "app-1".into(),
            container_id: Uuid::new_v4().to_string(),
            container_name: "app".into(),
            workload_uid: "workload-a".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: release.map(str::to_owned),
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

fn request(uri: &str, credential: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(COOKIE, format!("{SESSION_COOKIE}={credential}"))
        .body(Body::empty())
        .unwrap()
}

fn json_request(
    uri: &str,
    method: &str,
    credential: &str,
    value: &serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(COOKIE, format!("{SESSION_COOKIE}={credential}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(value).unwrap()))
        .unwrap()
}

async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("inventory-test-password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(ids.organization_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(ids.organization_id)
        .bind(token.digest().as_slice())
        .execute(pool)
        .await
        .unwrap();
    token.expose().to_owned()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

fn assert_summary_count_invariants(summary: &serde_json::Value) {
    let kinds = summary["kinds"].as_array().unwrap();
    let item_count: i64 = kinds
        .iter()
        .map(|kind| kind["item_count"].as_i64().unwrap())
        .sum();
    let occurrence_count: i64 = kinds
        .iter()
        .map(|kind| kind["occurrence_count"].as_i64().unwrap())
        .sum();
    assert_eq!(summary["item_count"], item_count);
    assert_eq!(summary["occurrence_count"], occurrence_count);
}

async fn release(pool: &sqlx::PgPool, ids: &BootstrapIds, version: &str, age_days: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(version)
        .bind(Utc::now() - Duration::days(age_days)).execute(pool).await.unwrap();
    id
}

async fn inventory_item(pool: &sqlx::PgPool, ids: &BootstrapIds, seed: u8) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,'process',2,$5,jsonb_build_object('executable',$6),now(),now(),1)")
        .bind(id)
        .bind(ids.organization_id)
        .bind(ids.project_id)
        .bind(ids.application_id)
        .bind(vec![seed; 32])
        .bind(format!("/app/process-{seed}"))
        .execute(pool)
        .await
        .unwrap();
    id
}

struct Sighting<'a> {
    cluster_id: Uuid,
    namespace: &'a str,
    workload_kind: &'a str,
    workload_name: &'a str,
    pod_uid: &'a str,
    container_name: &'a str,
    occurrence_count: i64,
}

async fn inventory_sighting(
    pool: &sqlx::PgPool,
    ids: &BootstrapIds,
    item_id: Uuid,
    sighting: Sighting<'_>,
) {
    sqlx::query("INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,now(),now())")
        .bind(ids.organization_id)
        .bind(ids.project_id)
        .bind(ids.application_id)
        .bind(item_id)
        .bind(sighting.cluster_id)
        .bind(sighting.namespace)
        .bind(sighting.workload_kind)
        .bind(sighting.workload_name)
        .bind(sighting.pod_uid)
        .bind(sighting.container_name)
        .bind(sighting.occurrence_count)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inventory_api_covers_kinds_filters_evidence_pagination_and_tenant_isolation(
    pool: sqlx::PgPool,
) {
    let mut first_config = config("inventory-api-first");
    let first = bootstrap(&pool, &first_config).await.unwrap();
    first_config.api_credential = owner_session(&pool, &first).await;
    let mut second_config = config("inventory-api-second");
    let second = bootstrap(&pool, &second_config).await.unwrap();
    second_config.api_credential = owner_session(&pool, &second).await;
    let observed_release = release(&pool, &first, "v1", 3).await;
    let other_evidence_release = release(&pool, &first, "v2", 2).await;
    let unknown_release = release(&pool, &first, "v3", 1).await;
    let foreign_release = release(&pool, &second, "foreign", 1).await;
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-a','test')")
        .bind(agent_id).bind(first.organization_id).bind(first.cluster_id).execute(&pool).await.unwrap();
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: first.organization_id,
            cluster_id: first.cluster_id,
        },
        agent_id,
    };
    let dns_name = DnsName::new("api.example.com").unwrap();
    let events = vec![
        event(
            &first,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/app/server".into(),
                parent_command: None,
                generation: None,
            }),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::ProcessExit(ProcessExit::new(
                0,
                ProcessTermination::exited(0),
                GenerationCorrelation::Unresolved {
                    reason: event_model::UnresolvedGenerationReason::BeforeObservation,
                },
            )),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::ContainerTermination(
                ContainerTermination::new("containerd://app", "Completed", 0, None, None).unwrap(),
            ),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::ContainerRestart(
                ContainerRestart::new("containerd://app", 3, 1, None, None).unwrap(),
            ),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::NetworkConnect(
                NetworkConnect::new(
                    NetworkAddressFamily::Ipv4,
                    "203.0.113.7".parse().unwrap(),
                    443,
                    NetworkConnectOutcome::Succeeded,
                    None,
                )
                .unwrap(),
            ),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::NetworkDnsQuery(NetworkDnsQuery {
                transaction_id: 1,
                direction: DnsDirection::Egress,
                transport: DnsTransport::Udp,
                resolver_address: "10.96.0.10".parse().unwrap(),
                name: dns_name,
                query_type: DnsQueryType::A,
            }),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::NetworkListen(
                NetworkListen::new(NetworkAddressFamily::Ipv4, "0.0.0.0".parse().unwrap(), 8080)
                    .unwrap(),
            ),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::NetworkAccept(
                NetworkAccept::new(
                    NetworkAddressFamily::Ipv4,
                    "0.0.0.0".parse().unwrap(),
                    8080,
                    "203.0.113.9".parse().unwrap(),
                    51_234,
                )
                .unwrap(),
            ),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::FileModify(FileModify {
                path: FileActivityPath::new("/app/data/state.json").unwrap(),
            }),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::Syscall(SyscallEvent {
                name: "epoll_wait".into(),
            }),
            Some("v2"),
        ),
        event(
            &first,
            EventPayload::ProcessExec(ProcessExec {
                executable: "/app/worker".into(),
                parent_command: None,
                generation: None,
            }),
            Some("v1"),
        ),
        event(
            &first,
            EventPayload::ProcessExec(ProcessExec {
                executable: "<script>alert(1)</script>".into(),
                parent_command: None,
                generation: None,
            }),
            Some("v1"),
        ),
    ];
    persist_batch(&pool, context, &events).await.unwrap();
    let process_item: Uuid =
        sqlx::query_scalar("SELECT id FROM runtime_inventory_items WHERE inventory_kind='process'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let app = inventory_api::router(pool.clone());
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory",
        first.project_id, first.application_id
    );

    let summary_response = app
        .clone()
        .oneshot(request(
            &format!("{base}/summary"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(summary_response.status(), StatusCode::OK);
    let summary = json(summary_response).await;
    assert_eq!(summary["item_count"], 11);
    assert_summary_count_invariants(&summary);
    assert_eq!(summary["kinds"].as_array().unwrap().len(), 7);
    assert_eq!(
        summary["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "destination",
            "domain",
            "inbound_endpoint",
            "file_activity",
            "lifecycle",
            "process",
            "syscall",
        ]
    );

    let inbound = app
        .clone()
        .oneshot(request(
            &format!("{base}?kind=inbound_endpoint&limit=1"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(inbound.status(), StatusCode::OK);
    let inbound = json(inbound).await;
    let endpoint = &inbound["items"][0];
    assert_eq!(endpoint["semantic_summary"]["local_address"], "0.0.0.0");
    assert_eq!(endpoint["semantic_summary"]["local_port"], 8080);
    assert_eq!(endpoint["semantic_summary"]["listener_observed"], true);
    assert_eq!(endpoint["semantic_summary"]["accept_observed"], true);
    assert!(endpoint["semantic_summary"].get("remote_address").is_none());

    for kind in ["process", "destination", "domain", "syscall", "lifecycle"] {
        let response = app
            .clone()
            .oneshot(request(
                &format!("{base}?kind={kind}&limit=1"),
                &first_config.api_credential,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["items"][0]["inventory_kind"], kind);
        let distribution = app
            .clone()
            .oneshot(request(
                &format!("{base}/distribution?kind={kind}&limit=10"),
                &first_config.api_credential,
            ))
            .await
            .unwrap();
        assert_eq!(distribution.status(), StatusCode::OK);
        assert_eq!(json(distribution).await["kind"], kind);
    }

    let lifecycle_distribution = app
        .clone()
        .oneshot(request(
            &format!("{base}/distribution?kind=lifecycle&limit=10"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(lifecycle_distribution.status(), StatusCode::OK);
    let lifecycle_distribution = json(lifecycle_distribution).await;
    let lifecycle_entries = lifecycle_distribution["entries"].as_array().unwrap();
    assert_eq!(lifecycle_entries.len(), 3);
    let process_exit = lifecycle_entries
        .iter()
        .find(|entry| entry["semantic_summary"]["event_kind"] == "process.exit")
        .unwrap();
    assert_eq!(process_exit["semantic_summary"]["identity"], "app");
    assert_eq!(
        process_exit["semantic_summary"]["termination"]["type"],
        "exited"
    );
    let container_termination = lifecycle_entries
        .iter()
        .find(|entry| entry["semantic_summary"]["event_kind"] == "container.terminated")
        .unwrap();
    assert_eq!(
        container_termination["semantic_summary"]["container_name"],
        "app"
    );
    assert_eq!(
        container_termination["semantic_summary"]["reason"],
        "Completed"
    );
    assert_eq!(container_termination["semantic_summary"]["exit_code"], 0);
    let container_restart = lifecycle_entries
        .iter()
        .find(|entry| entry["semantic_summary"]["event_kind"] == "container.restart")
        .unwrap();
    assert_eq!(
        container_restart["semantic_summary"]["container_name"],
        "app"
    );
    assert_eq!(container_restart["semantic_summary"]["restart_count"], 3);
    assert_eq!(container_restart["semantic_summary"]["restart_delta"], 1);

    let distribution_response = app
        .clone()
        .oneshot(request(
            &format!("{base}/distribution?kind=process&limit=1"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(distribution_response.status(), StatusCode::OK);
    let distribution = json(distribution_response).await;
    assert_eq!(distribution["total_item_count"], 3);
    assert_eq!(distribution["entries"].as_array().unwrap().len(), 1);
    assert_eq!(distribution["other"]["item_count"], 2);
    assert_eq!(
        distribution["entries"][0]["occurrence_count"]
            .as_i64()
            .unwrap()
            + distribution["other"]["occurrence_count"].as_i64().unwrap(),
        distribution["total_occurrence_count"].as_i64().unwrap()
    );
    let all_processes = app
        .clone()
        .oneshot(request(
            &format!("{base}/distribution?kind=process&limit=10"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    let all_processes = json(all_processes).await;
    assert!(all_processes["other"].is_null());
    let tokens: Vec<_> = all_processes["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["identity_token"].as_str().unwrap())
        .collect();
    assert!(tokens.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        all_processes["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["semantic_summary"]["executable"] == "<script>alert(1)</script>"
            })
    );

    let scoped_distribution = app
        .clone()
        .oneshot(request(
            &format!(
                "{base}/distribution?kind=process&release_id={observed_release}&cluster_id={}&namespace=production&workload_kind=Deployment&workload_name=app&container_name=app&search=worker",
                first.cluster_id
            ),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(scoped_distribution.status(), StatusCode::OK);
    assert_eq!(json(scoped_distribution).await["total_item_count"], 1);

    let empty_distribution = app
        .clone()
        .oneshot(request(
            &format!("{base}/distribution?kind=process&search=does-not-exist"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    let empty_distribution = json(empty_distribution).await;
    assert_eq!(empty_distribution["total_item_count"], 0);
    assert!(empty_distribution["entries"].as_array().unwrap().is_empty());
    assert!(empty_distribution["other"].is_null());
    let identity_token = distribution["entries"][0]["identity_token"]
        .as_str()
        .unwrap();
    let identity_filtered = app
        .clone()
        .oneshot(request(
            &format!("{base}?kind=process&identity_token={identity_token}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(identity_filtered.status(), StatusCode::OK);
    assert_eq!(
        json(identity_filtered).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let tampered = format!("{identity_token}0");
    let invalid_token = app
        .clone()
        .oneshot(request(
            &format!("{base}?kind=process&identity_token={tampered}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_token.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(invalid_token).await["error"], "invalid_identity_token");

    for invalid_limit in [0, 11] {
        let response = app
            .clone()
            .oneshot(request(
                &format!("{base}/distribution?kind=process&limit={invalid_limit}"),
                &first_config.api_credential,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let filtered = app
        .clone()
        .oneshot(request(
            &format!(
                "{base}?release_id={observed_release}&cluster_id={}&namespace=production&workload_kind=Deployment&workload_name=app&container_name=app&search=server",
                first.cluster_id
            ),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = json(filtered).await;
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    let filtered_item = &filtered["items"][0];
    let filtered_summary = app
        .clone()
        .oneshot(request(
            &format!(
                "{base}/summary?release_id={observed_release}&cluster_id={}&namespace=production&workload_kind=Deployment&workload_name=app&container_name=app&search=server",
                first.cluster_id
            ),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(filtered_summary.status(), StatusCode::OK);
    let filtered_summary = json(filtered_summary).await;
    assert_eq!(filtered_summary["item_count"], 1);
    assert_eq!(
        filtered_summary["occurrence_count"],
        filtered_item["occurrence_count"]
    );
    assert_eq!(
        filtered_summary["first_seen_at"],
        filtered_item["first_seen_at"]
    );
    assert_eq!(
        filtered_summary["last_seen_at"],
        filtered_item["last_seen_at"]
    );

    let empty_summary = app
        .clone()
        .oneshot(request(
            &format!("{base}/summary?search=does-not-exist"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(empty_summary.status(), StatusCode::OK);
    let empty_summary = json(empty_summary).await;
    assert_eq!(empty_summary["item_count"], 0);
    assert!(empty_summary["first_seen_at"].is_null());
    assert!(empty_summary["last_seen_at"].is_null());

    let invalid_summary = app
        .clone()
        .oneshot(request(
            &format!(
                "{base}/summary?observed_from=2026-08-19T00:00:00Z&observed_to=2026-08-18T00:00:00Z"
            ),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_summary.status(), StatusCode::BAD_REQUEST);

    let foreign_summary_release = app
        .clone()
        .oneshot(request(
            &format!("{base}/summary?release_id={foreign_release}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(foreign_summary_release.status(), StatusCode::BAD_REQUEST);

    let page = app
        .clone()
        .oneshot(request(
            &format!("{base}?limit=1"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    let page = json(page).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert!(page["next_cursor"].is_string());

    let detail_base = format!("{base}/{process_item}");
    for suffix in ["", "/sightings", "/groups", "/occurrences"] {
        let response = app
            .clone()
            .oneshot(request(
                &format!("{detail_base}{suffix}?limit=200"),
                &first_config.api_credential,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let releases_response = app
        .clone()
        .oneshot(request(
            &format!("{detail_base}/releases"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    let releases = json(releases_response).await;
    let states: std::collections::HashMap<Uuid, &str> = releases["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                Uuid::parse_str(item["release_id"].as_str().unwrap()).unwrap(),
                item["presence"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(states[&observed_release], "observed");
    assert_eq!(states[&other_evidence_release], "not_observed");
    assert_eq!(states[&unknown_release], "unknown");

    let invalid = app
        .clone()
        .oneshot(request(
            &format!("{base}?kind=payload&limit=201"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let foreign_filter = app
        .clone()
        .oneshot(request(
            &format!("{base}?release_id={foreign_release}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(foreign_filter.status(), StatusCode::BAD_REQUEST);

    let foreign_item = app
        .clone()
        .oneshot(request(&detail_base, &second_config.api_credential))
        .await
        .unwrap();
    assert_eq!(foreign_item.status(), StatusCode::NOT_FOUND);
    let foreign_application = app
        .clone()
        .oneshot(request(&base, &second_config.api_credential))
        .await
        .unwrap();
    assert_eq!(foreign_application.status(), StatusCode::NOT_FOUND);
    let foreign_distribution = app
        .oneshot(request(
            &format!("{base}/distribution?kind=process"),
            &second_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(foreign_distribution.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inventory_summary_normalizes_legacy_lifecycle_kinds(pool: sqlx::PgPool) {
    let mut test_config = config("inventory-summary-legacy-lifecycle");
    let ids = bootstrap(&pool, &test_config).await.unwrap();
    test_config.api_credential = owner_session(&pool, &ids).await;
    let observed_at = Utc::now();
    for (index, (kind, occurrence_count)) in [
        ("process_exit", 2_i64),
        ("container_termination", 3),
        ("container_restart", 5),
    ]
    .into_iter()
    .enumerate()
    {
        let mut digest = vec![0_u8; 32];
        digest[0] = u8::try_from(index + 1).unwrap();
        sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,$5,2,$6,'{}'::jsonb,$7,$7,$8)")
            .bind(Uuid::new_v4())
            .bind(ids.organization_id)
            .bind(ids.project_id)
            .bind(ids.application_id)
            .bind(kind)
            .bind(digest)
            .bind(observed_at)
            .bind(occurrence_count)
            .execute(&pool)
            .await
            .unwrap();
    }

    let response = inventory_api::router(pool)
        .oneshot(request(
            &format!(
                "/api/v1/projects/{}/applications/{}/runtime-inventory/summary",
                ids.project_id, ids.application_id
            ),
            &test_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let summary = json(response).await;
    assert_summary_count_invariants(&summary);
    assert_eq!(summary["item_count"], 3);
    assert_eq!(summary["occurrence_count"], 10);
    let lifecycle = summary["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|kind| kind["kind"] == "lifecycle")
        .unwrap();
    assert_eq!(lifecycle["item_count"], 3);
    assert_eq!(lifecycle["occurrence_count"], 10);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inventory_facets_deduplicate_items_and_sum_distinct_sightings(pool: sqlx::PgPool) {
    let mut test_config = config("inventory-facet-aggregates");
    let ids = bootstrap(&pool, &test_config).await.unwrap();
    test_config.api_credential = owner_session(&pool, &ids).await;
    let second_cluster = Uuid::new_v4();
    sqlx::query("INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,'second','Second cluster')")
        .bind(second_cluster)
        .bind(ids.organization_id)
        .execute(&pool)
        .await
        .unwrap();
    let item_id = inventory_item(&pool, &ids, 1).await;
    for sighting in [
        Sighting {
            cluster_id: ids.cluster_id,
            namespace: "production",
            workload_kind: "Deployment",
            workload_name: "api",
            pod_uid: "pod-a",
            container_name: "server",
            occurrence_count: 2,
        },
        Sighting {
            cluster_id: ids.cluster_id,
            namespace: "production",
            workload_kind: "Deployment",
            workload_name: "worker",
            pod_uid: "pod-b",
            container_name: "server",
            occurrence_count: 3,
        },
        Sighting {
            cluster_id: second_cluster,
            namespace: "staging",
            workload_kind: "StatefulSet",
            workload_name: "api",
            pod_uid: "pod-c",
            container_name: "sidecar",
            occurrence_count: 5,
        },
    ] {
        inventory_sighting(&pool, &ids, item_id, sighting).await;
    }
    let app = inventory_api::router(pool);
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory/facets",
        ids.project_id, ids.application_id
    );
    let response = app
        .clone()
        .oneshot(request(
            &format!("{base}/cluster?namespace=ignored-by-other-facet"),
            &test_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json(response).await["items"].as_array().unwrap().is_empty());
    let clusters = app
        .clone()
        .oneshot(request(
            &format!("{base}/cluster"),
            &test_config.api_credential,
        ))
        .await
        .unwrap();
    let clusters = json(clusters).await;
    assert_eq!(clusters["items"].as_array().unwrap().len(), 2);
    for option in clusters["items"].as_array().unwrap() {
        assert_eq!(option["item_count"], 1);
        assert_eq!(option["occurrence_count"], 5);
    }
    let namespaces = app
        .oneshot(request(
            &format!("{base}/namespace?namespace=absent&workload_name=api"),
            &test_config.api_credential,
        ))
        .await
        .unwrap();
    let namespaces = json(namespaces).await;
    assert_eq!(namespaces["items"].as_array().unwrap().len(), 2);
    assert_eq!(namespaces["items"][0]["item_count"], 1);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inventory_facets_enforce_bounds_search_cursors_and_tenant_scope(pool: sqlx::PgPool) {
    let mut first_config = config("inventory-facet-pages");
    let first = bootstrap(&pool, &first_config).await.unwrap();
    first_config.api_credential = owner_session(&pool, &first).await;
    let mut second_config = config("inventory-facet-foreign");
    let second = bootstrap(&pool, &second_config).await.unwrap();
    second_config.api_credential = owner_session(&pool, &second).await;
    for index in 0_u8..=200 {
        let item_id = inventory_item(&pool, &first, index).await;
        let namespace = format!("namespace-{index:03}");
        inventory_sighting(
            &pool,
            &first,
            item_id,
            Sighting {
                cluster_id: first.cluster_id,
                namespace: &namespace,
                workload_kind: "Deployment",
                workload_name: "api",
                pod_uid: &format!("pod-{index}"),
                container_name: "server",
                occurrence_count: 1,
            },
        )
        .await;
    }
    let app = inventory_api::router(pool);
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory/facets",
        first.project_id, first.application_id
    );
    let page = app
        .clone()
        .oneshot(request(
            &format!("{base}/namespace?limit=200"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page = json(page).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 200);
    let cursor = page["next_cursor"].as_str().unwrap();
    let next = app
        .clone()
        .oneshot(request(
            &format!("{base}/namespace?limit=200&cursor={cursor}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(json(next).await["items"].as_array().unwrap().len(), 1);
    for uri in [
        format!("{base}/workload_name?cursor={cursor}"),
        format!("{base}/namespace?cursor={cursor}&kind=domain"),
        format!("{base}/unsupported"),
    ] {
        let response = app
            .clone()
            .oneshot(request(&uri, &first_config.api_credential))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let searched = app
        .clone()
        .oneshot(request(
            &format!("{base}/namespace?facet_search=namespace-200"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(json(searched).await["items"].as_array().unwrap().len(), 1);
    let empty = app
        .clone()
        .oneshot(request(
            &format!("{base}/namespace?facet_search=absent"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert!(json(empty).await["items"].as_array().unwrap().is_empty());
    let foreign = app
        .oneshot(request(
            &format!("{base}/namespace"),
            &second_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn runtime_behavior_labels_mutate_search_and_preserve_evidence(pool: sqlx::PgPool) {
    let ids = bootstrap(&pool, &config("inventory-labels")).await.unwrap();
    let token = owner_session(&pool, &ids).await;
    let item_id = inventory_item(&pool, &ids, 91).await;
    let app = inventory_api::router(pool.clone());
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory",
        ids.project_id, ids.application_id
    );
    let label_uri = format!("{base}/{item_id}/user-label");

    let created = app
        .clone()
        .oneshot(json_request(
            &label_uri,
            "PUT",
            &token,
            &serde_json::json!({"display_name":"  Database connection  "}),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = json(created).await;
    assert_eq!(created["display_name"], "Database connection");
    let updated_at = created["updated_at"].clone();

    let detail = json(
        app.clone()
            .oneshot(request(&format!("{base}/{item_id}"), &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(detail["user_label"]["display_name"], "Database connection");
    assert_eq!(detail["semantic_summary"]["executable"], "/app/process-91");
    let searched = json(
        app.clone()
            .oneshot(request(&format!("{base}?search=database"), &token))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(searched["items"].as_array().unwrap().len(), 1);

    let stale = app.clone().oneshot(json_request(&label_uri, "PUT", &token, &serde_json::json!({"display_name":"NATS connection","expected_updated_at":"2000-01-01T00:00:00Z"}))).await.unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let retry = app.clone().oneshot(json_request(&label_uri, "PUT", &token, &serde_json::json!({"display_name":"Database connection","expected_updated_at":updated_at}))).await.unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    let invalid = app
        .clone()
        .oneshot(json_request(
            &label_uri,
            "PUT",
            &token,
            &serde_json::json!({"display_name":"bad\nname"}),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let deleted = app
        .clone()
        .oneshot(json_request(
            &label_uri,
            "DELETE",
            &token,
            &serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let unnamed = json(
        app.oneshot(request(&format!("{base}/{item_id}"), &token))
            .await
            .unwrap(),
    )
    .await;
    assert!(unnamed["user_label"].is_null());
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn logical_dns_groups_normalize_only_corroborated_same_process_evidence(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("dns-groups-first")).await.unwrap();
    let first_session = owner_session(&pool, &first).await;
    let second = bootstrap(&pool, &config("dns-groups-second"))
        .await
        .unwrap();
    let second_session = owner_session(&pool, &second).await;
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-a','test')")
        .bind(agent_id).bind(first.organization_id).bind(first.cluster_id).execute(&pool).await.unwrap();
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: first.organization_id,
            cluster_id: first.cluster_id,
        },
        agent_id,
    };
    let mut filtered_expansion = dns_event(
        &first,
        "s3.twcstorage.ru.cluster.local",
        DnsQueryType::A,
        "api",
    );
    filtered_expansion.attribution.namespace = "staging".into();
    let mut html_cluster = dns_event(
        &first,
        "html-to-pdf.rstat.svc.cluster.local",
        DnsQueryType::A,
        "dns",
    );
    let mut html_namespace = dns_event(
        &first,
        "html-to-pdf.rstat.svc.rstat.svc.cluster.local",
        DnsQueryType::Aaaa,
        "dns",
    );
    let mut html_service = dns_event(
        &first,
        "html-to-pdf.rstat.svc.svc.cluster.local",
        DnsQueryType::A,
        "dns",
    );
    for event in [&mut html_cluster, &mut html_namespace, &mut html_service] {
        event.attribution.namespace = "rstat".into();
    }
    let mut events = vec![
        dns_event(&first, "s3.twcstorage.ru", DnsQueryType::A, "api"),
        dns_event(&first, "s3.twcstorage.ru", DnsQueryType::Aaaa, "api"),
        dns_event(
            &first,
            "s3.twcstorage.ru.cluster.local",
            DnsQueryType::A,
            "api",
        ),
        dns_event(
            &first,
            "s3.twcstorage.ru.svc.cluster.local",
            DnsQueryType::A,
            "api",
        ),
        filtered_expansion,
        dns_event(
            &first,
            "s3.twcstorage.ru.corp.local",
            DnsQueryType::A,
            "api",
        ),
        dns_event(
            &first,
            "alone.example.cluster.local",
            DnsQueryType::A,
            "api",
        ),
        dns_event(&first, "s3.twcstorage.ru", DnsQueryType::A, "worker"),
        dns_event(
            &first,
            "s3.twcstorage.ru.cluster.local",
            DnsQueryType::A,
            "worker",
        ),
        html_cluster,
        html_namespace,
        html_service,
    ];
    for event in &mut events {
        event.attribution.pod_uid = "shared-resolver-context".into();
    }
    events.extend([
        dns_event(
            &first,
            "split.example.cluster.local",
            DnsQueryType::A,
            "split-context",
        ),
        dns_event(
            &first,
            "split.example.svc.cluster.local",
            DnsQueryType::A,
            "split-context",
        ),
    ]);
    persist_batch(&pool, context, &events).await.unwrap();
    let app = inventory_api::router(pool.clone()).merge(dns_group_api::router(pool.clone()));
    let base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory",
        first.project_id, first.application_id
    );
    let response = app
        .clone()
        .oneshot(request(
            &format!("{base}/dns-groups?limit=1"),
            &first_session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first_page = json(response).await;
    assert_eq!(first_page["total_group_count"], 8);
    assert_eq!(first_page["total_observation_count"], 14);
    assert!(first_page["next_cursor"].is_string());
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups?limit=1&cursor={cursor}"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(second_page["total_group_count"], 8);
    assert_ne!(
        first_page["items"][0]["group_token"],
        second_page["items"][0]["group_token"]
    );

    let grouped = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups?search=s3.twcstorage.ru.svc.cluster.local"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(grouped["items"].as_array().unwrap().len(), 1);
    assert_eq!(grouped["items"][0]["display_name"], "s3.twcstorage.ru");
    assert_eq!(
        grouped["items"][0]["grouping_reason"],
        "kubernetes_search_expansion"
    );
    assert_eq!(grouped["items"][0]["variant_count"], 4);
    assert_eq!(grouped["items"][0]["observation_count"], 4);
    assert_eq!(
        grouped["items"][0]["query_types"],
        serde_json::json!(["A", "AAAA"])
    );
    let inferred = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups?search=html-to-pdf.rstat.svc.svc.cluster.local"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(inferred["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        inferred["items"][0]["display_name"],
        "html-to-pdf.rstat.svc"
    );
    assert_eq!(
        inferred["items"][0]["grouping_reason"],
        "kubernetes_search_expansion"
    );
    assert_eq!(inferred["items"][0]["variant_count"], 3);
    assert_eq!(inferred["items"][0]["observation_count"], 3);
    let split_context = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups?search=split.example"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(split_context["items"].as_array().unwrap().len(), 2);
    assert!(
        split_context["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| {
                item["grouping_reason"] == "canonical_name" && item["variant_count"] == 1
            })
    );
    let filtered = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups?namespace=staging"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        filtered["items"][0]["display_name"],
        "s3.twcstorage.ru.cluster.local"
    );
    assert_eq!(filtered["items"][0]["grouping_reason"], "canonical_name");
    let token = grouped["items"][0]["group_token"].as_str().unwrap();
    let variants = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups/{token}/variants?limit=10"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(variants["items"].as_array().unwrap().len(), 4);
    let exact_item = variants["items"][0]["item_id"].as_str().unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(&format!("{base}/{exact_item}"), &first_session))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let distribution = json(
        app.clone()
            .oneshot(request(
                &format!("{base}/dns-groups/distribution?limit=1"),
                &first_session,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(distribution["total_group_count"], 8);
    assert_eq!(distribution["entries"][0]["group"]["observation_count"], 4);
    assert_eq!(distribution["other"]["group_count"], 7);
    assert_eq!(distribution["other"]["observation_count"], 10);

    let foreign_base = format!(
        "/api/v1/projects/{}/applications/{}/runtime-inventory/dns-groups/{token}/variants",
        second.project_id, second.application_id
    );
    assert_eq!(
        app.oneshot(request(&foreign_base, &second_session))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    sqlx::query("ANALYZE runtime_inventory_items")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE runtime_inventory_event_memberships")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE runtime_events")
        .execute(&pool)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar("EXPLAIN (ANALYZE, BUFFERS) SELECT e.id FROM runtime_inventory_items i JOIN runtime_inventory_event_memberships m ON m.item_id=i.id JOIN runtime_events e ON e.id=m.event_id WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=2 AND i.inventory_kind='domain' AND e.observed_at>=now()-interval '1 day'")
        .bind(first.organization_id).bind(first.project_id).bind(first.application_id)
        .fetch_all(&pool).await.unwrap();
    assert!(plan.iter().any(|line| line.contains("runtime_inventory")));
    eprintln!("logical DNS scoped foundation plan: {plan:?}");
}
