use std::collections::HashSet;

const LIVE_OPERATIONS: &[(&str, &str)] = &[
    ("/api/v1/runtime-groups/{group_id}/snapshots", "get"),
    (
        "/api/v1/organizations/{organization_id}/runtime-retention",
        "get",
    ),
    (
        "/api/v1/organizations/{organization_id}/runtime-retention",
        "put",
    ),
    ("/api/v1/projects/{project_id}/runtime-retention", "get"),
    ("/api/v1/projects/{project_id}/runtime-retention", "put"),
    ("/api/v1/projects/{project_id}/runtime-retention", "delete"),
    (
        "/api/v1/organizations/{organization_id}/notification-retention",
        "get",
    ),
    (
        "/api/v1/organizations/{organization_id}/notification-retention",
        "put",
    ),
    (
        "/api/v1/projects/{project_id}/notification-retention",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/notification-retention",
        "put",
    ),
    (
        "/api/v1/projects/{project_id}/notification-retention",
        "delete",
    ),
    ("/api/v1/build-info", "get"),
    ("/api/v1/setup/status", "get"),
    ("/api/v1/setup/complete", "post"),
    ("/api/v1/agent-installation-metadata", "get"),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/installations",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}",
        "patch",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/installations/{installation_id}/replace-credential",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/connection-readiness",
        "get",
    ),
    ("/api/v1/auth/register", "post"),
    ("/api/v1/auth/login", "post"),
    ("/api/v1/auth/email-verification-requests", "post"),
    ("/api/v1/auth/email-verifications", "post"),
    ("/api/v1/auth/password-reset-requests", "post"),
    ("/api/v1/auth/password-resets", "post"),
    ("/api/v1/auth/password", "put"),
    ("/api/v1/auth/preferences", "put"),
    ("/api/v1/auth/me", "get"),
    ("/api/v1/auth/logout", "post"),
    ("/api/v1/organizations", "post"),
    ("/api/v1/admin/organizations", "get"),
    (
        "/api/v1/admin/organizations/{organization_id}/projects",
        "get",
    ),
    ("/api/v1/admin/projects/{project_id}/applications", "get"),
    (
        "/api/v1/admin/projects/{project_id}/applications/{application_id}",
        "get",
    ),
    ("/api/v1/organizations/{organization_id}/projects", "post"),
    ("/api/v1/attention-summary", "get"),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/attention-summary",
        "get",
    ),
    ("/api/v1/organization", "get"),
    ("/api/v1/projects", "get"),
    ("/api/v1/projects/{project_id}", "get"),
    ("/api/v1/projects/{project_id}/applications", "get"),
    ("/api/v1/projects/{project_id}/applications", "post"),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/workers",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/credentials/{credential_id}",
        "delete",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/summary",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/facets/{facet}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/releases",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/sightings",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/groups",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/occurrences",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/preview",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/revisions",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/replace",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/enable",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policies/{policy_id}/disable",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/policy-seed",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-groups/{group_id}/policy-seed",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policy-suppressions/{suppression_id}/cancel",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/policy-recomputations/{recomputation_id}",
        "get",
    ),
    ("/api/v1/runtime-groups", "get"),
    ("/api/v1/runtime-groups/{group_id}", "get"),
    ("/api/v1/runtime-groups/{group_id}/occurrences", "get"),
    ("/api/v1/runtime-groups/{group_id}/acknowledge", "post"),
    ("/api/v1/runtime-groups/{group_id}/resolve", "post"),
    ("/api/v1/runtime-groups/{group_id}/reopen", "post"),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}/episodes",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/resources",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/resource-comparison",
        "get",
    ),
    ("/api/v1/projects/{project_id}/webhook-destinations", "get"),
    ("/api/v1/projects/{project_id}/webhook-destinations", "post"),
    (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}",
        "patch",
    ),
    (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/disable",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/rotate-secret",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/test",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/notification-deliveries",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/notification-deliveries/bulk-retry",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/retry",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/cancel",
        "post",
    ),
    (
        "/api/v1/projects/{project_id}/notification-recovery-operations",
        "get",
    ),
    (
        "/api/v1/projects/{project_id}/notification-recovery-operations/{operation_id}",
        "get",
    ),
    ("/api/v1/projects/{project_id}/notification-health", "get"),
];

#[test]
fn openapi_is_valid_unique_secure_and_matches_router_inventory() {
    let source = include_str!("../../../openapi/okoscope-v1.yaml");
    let document: serde_json::Value = serde_yaml::from_str(source).expect("valid OpenAPI YAML");
    assert_eq!(document["openapi"], "3.1.0");
    assert_all_local_refs_resolve(&document, &document);
    assert_eq!(
        document["security"][0]["sessionAuth"],
        serde_json::json!([])
    );

    let paths = document["paths"].as_object().expect("paths object");
    let mut operation_ids = HashSet::new();
    for &(path, method) in LIVE_OPERATIONS {
        let operation = &paths[path][method];
        assert!(
            operation.is_object(),
            "missing live operation {method} {path}"
        );
        let operation_id = operation["operationId"].as_str().expect("operationId");
        assert!(
            operation_ids.insert(operation_id),
            "duplicate operationId {operation_id}"
        );
        if matches!(
            path,
            "/api/v1/build-info"
                | "/api/v1/auth/register"
                | "/api/v1/auth/login"
                | "/api/v1/auth/email-verification-requests"
                | "/api/v1/auth/email-verifications"
                | "/api/v1/auth/password-reset-requests"
                | "/api/v1/auth/password-resets"
                | "/api/v1/setup/status"
                | "/api/v1/setup/complete"
        ) {
            assert_eq!(operation["security"], serde_json::json!([]));
        } else if path == "/api/v1/organizations/{organization_id}/projects"
            || path == "/api/v1/projects/{project_id}/applications" && method == "post"
            || path.starts_with(
                "/api/v1/projects/{project_id}/applications/{application_id}/credentials",
            )
        {
            assert_eq!(
                operation["security"],
                serde_json::json!([{ "sessionAuth": [] }, { "adminAuth": [] }])
            );
        } else if matches!(path, "/api/v1/organizations") || path.starts_with("/api/v1/admin/") {
            assert_eq!(
                operation["security"],
                serde_json::json!([{ "adminAuth": [] }])
            );
        } else {
            assert!(
                operation.get("security").is_none(),
                "protected route overrides session security: {method} {path}"
            );
        }
        assert_success_response_is_typed(&document, operation, path, method);
    }
    let documented = paths
        .values()
        .map(|item| {
            ["get", "post", "put", "patch", "delete"]
                .into_iter()
                .filter(|method| item.get(method).is_some())
                .count()
        })
        .sum::<usize>();
    assert_eq!(
        documented,
        LIVE_OPERATIONS.len(),
        "documented route inventory drift"
    );
    assert_navigation_and_group_contract(&document);
    assert_required_fields(
        &document,
        "AttentionRuntimeGroupResourceRef",
        &[
            "event_kind",
            "semantic_summary",
            "namespace",
            "workload_kind",
            "workload_name",
        ],
    );
    assert_network_contract(&document);
    assert_inventory_contract(&document);
    assert_policy_seed_contract(&document);
    assert_behavior_matcher_discriminator(&document);
    assert_release_display_name_contract(&document);
    assert_notification_health_contract(&document);
    assert_delivery_contract(&document);
    assert_recovery_contract(&document);
    assert_secret_and_runtime_diff_contract(&document);
    assert_auth_mail_contract(&document);
}

fn assert_auth_mail_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    for (schema, field) in [
        ("EmailActionRequest", "token"),
        ("PasswordResetRequest", "token"),
        ("PasswordResetRequest", "new_password"),
        ("PasswordChangeRequest", "current_password"),
        ("PasswordChangeRequest", "new_password"),
        ("RegisterRequest", "password"),
    ] {
        assert_eq!(schemas[schema]["properties"][field]["writeOnly"], true);
    }
    let user = &schemas["AuthenticatedUser"];
    assert!(
        user["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "email_verified")
    );
    assert!(
        user["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "preferred_locale")
    );
    for forbidden in ["password", "password_hash", "token", "token_digest", "mail"] {
        assert!(user["properties"].get(forbidden).is_none());
    }
    let created = &schemas["CreatedApplicationResponse"];
    for forbidden in ["recipients", "mail", "delivery", "smtp"] {
        assert!(created["properties"].get(forbidden).is_none());
    }
}

#[test]
fn release_identity_components_have_a_typed_hex_digest_contract() {
    let source = include_str!("../../../openapi/okoscope-v1.yaml");
    let document: serde_json::Value = serde_yaml::from_str(source).expect("valid OpenAPI YAML");
    let component = &document["components"]["schemas"]["ReleaseIdentityComponent"];
    assert_eq!(
        component["required"],
        serde_json::json!(["name", "image", "category", "digest"])
    );
    assert_eq!(component["properties"]["name"]["type"], "string");
    assert_eq!(component["properties"]["image"]["type"], "string");
    assert_eq!(component["properties"]["category"]["type"], "string");
    assert_eq!(component["properties"]["digest"]["type"], "string");
    assert_eq!(component["properties"]["digest"]["minLength"], 64);
    assert_eq!(component["properties"]["digest"]["maxLength"], 64);
    assert_eq!(
        document["components"]["schemas"]["Release"]["properties"]["identity_components"]["items"]
            ["$ref"],
        "#/components/schemas/ReleaseIdentityComponent"
    );
}

fn assert_secret_and_runtime_diff_contract(document: &serde_json::Value) {
    assert_eq!(
        document["components"]["schemas"]["IssuedApplicationCredential"]["properties"]["token"]["writeOnly"],
        true
    );
    for schema in ["ApplicationCredential", "ApplicationCredentialPage"] {
        assert!(
            document["components"]["schemas"][schema]["properties"]
                .get("token")
                .is_none(),
            "safe schema {schema} exposes plaintext token"
        );
    }
    assert_query_parameters(
        document,
        "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff",
        "get",
        &["baseline_id", "cursor", "limit"],
    );
}

fn assert_release_display_name_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    for (schema, field) in [
        ("Release", "display_name"),
        ("AttentionReleaseRef", "display_name"),
        ("DeploymentEpisode", "release_display_name"),
        ("InventoryReleaseEvidence", "release_display_name"),
        ("InventoryOccurrence", "release_display_name"),
        ("EventOccurrence", "release_display_name"),
    ] {
        assert!(
            schemas[schema]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == field),
            "{schema}.{field} must be required"
        );
        assert_eq!(schemas[schema]["properties"][field]["type"], "string");
        assert_eq!(schemas[schema]["properties"][field]["minLength"], 1);
    }
    for field in [
        "target_release_display_name",
        "baseline_release_display_name",
    ] {
        let schema = &schemas["AttentionRuntimeDiffResourceRef"];
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == field)
        );
        assert_eq!(schema["properties"][field]["type"], "string");
        assert_eq!(schema["properties"][field]["minLength"], 1);
    }
}

fn assert_behavior_matcher_discriminator(document: &serde_json::Value) {
    let mapping = &document["components"]["schemas"]["BehaviorMatcher"]["discriminator"]["mapping"];
    assert_eq!(
        mapping,
        &serde_json::json!({
            "process": "#/components/schemas/ProcessBehaviorMatcher",
            "destination": "#/components/schemas/DestinationBehaviorMatcher",
            "domain": "#/components/schemas/DomainBehaviorMatcher",
            "syscall": "#/components/schemas/SyscallBehaviorMatcher",
            "inbound_endpoint": "#/components/schemas/InboundBehaviorMatcher",
            "file_activity": "#/components/schemas/FileBehaviorMatcher",
            "lifecycle_process_exit": "#/components/schemas/LifecycleBehaviorMatcher",
            "lifecycle_container_termination": "#/components/schemas/LifecycleBehaviorMatcher",
            "lifecycle_container_restart": "#/components/schemas/LifecycleBehaviorMatcher"
        })
    );
}

fn assert_policy_seed_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    assert_eq!(
        schemas["PolicySeed"]["discriminator"]["mapping"],
        serde_json::json!({
            "available": "#/components/schemas/AvailablePolicySeed",
            "unavailable": "#/components/schemas/UnavailablePolicySeed"
        })
    );
    assert_eq!(
        schemas["AvailablePolicySeed"]["properties"]["state"]["const"],
        "available"
    );
    assert_eq!(
        schemas["UnavailablePolicySeed"]["properties"]["state"]["const"],
        "unavailable"
    );
}

fn assert_all_local_refs_resolve(document: &serde_json::Value, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
                let pointer = reference.strip_prefix('#').unwrap_or_else(|| {
                    panic!("external OpenAPI reference is unsupported: {reference}")
                });
                assert!(
                    document.pointer(pointer).is_some(),
                    "unresolved OpenAPI reference: {reference}"
                );
            }
            for nested in object.values() {
                assert_all_local_refs_resolve(document, nested);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_all_local_refs_resolve(document, item);
            }
        }
        _ => {}
    }
}

fn assert_navigation_and_group_contract(document: &serde_json::Value) {
    assert_query_parameters(
        document,
        "/api/v1/projects/{project_id}/applications/{application_id}/workers",
        "get",
        &["cursor", "limit"],
    );
    assert_query_parameters(
        document,
        "/api/v1/runtime-groups",
        "get",
        &[
            "project_id",
            "application_id",
            "event_kind",
            "status",
            "namespace",
            "workload_kind",
            "workload_name",
            "since",
            "first_seen_from",
            "first_seen_to",
            "last_seen_to",
            "release_id",
            "verdict",
            "suppressed",
            "evaluation_pending",
            "cursor",
            "limit",
        ],
    );
    for path in [
        "/api/v1/projects/{project_id}/applications/{application_id}/releases",
        "/api/v1/runtime-groups/{group_id}/occurrences",
    ] {
        assert_query_parameters(document, path, "get", &["cursor", "limit"]);
    }
    assert_required_fields(
        document,
        "ApplicationWorker",
        &[
            "agent_id",
            "cluster_id",
            "cluster_name",
            "node_name",
            "agent_version",
            "architecture",
            "kernel_release",
            "first_observed_at",
            "last_observed_at",
            "agent_last_seen_at",
        ],
    );
    assert_required_fields(
        document,
        "RuntimeGroup",
        &[
            "first_seen_event_id",
            "status_changed_at",
            "status_changed_by",
        ],
    );
}

fn assert_required_fields(document: &serde_json::Value, schema: &str, expected: &[&str]) {
    let required = document["components"]["schemas"][schema]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("{schema} required fields"));
    for field in expected {
        assert!(
            required.iter().any(|value| value == field),
            "{schema} must require {field}"
        );
    }
}

#[test]
fn inbound_contract_fixture_keeps_remote_clients_in_occurrences_only() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/fixtures/runtime-inventory.json"
    ))
    .expect("valid runtime inventory fixture");
    assert_eq!(fixture["summary"]["kinds"].as_array().unwrap().len(), 5);
    let endpoint = fixture["page"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inventory_kind"] == "inbound_endpoint")
        .expect("inbound endpoint fixture");
    assert_eq!(endpoint["semantic_summary"]["listener_observed"], true);
    assert_eq!(endpoint["semantic_summary"]["accept_observed"], true);
    assert!(endpoint["semantic_summary"].get("remote_address").is_none());
    assert!(
        fixture["inbound_group"]["semantic_summary"]
            .get("remote_address")
            .is_none()
    );
    assert_eq!(
        fixture["inbound_occurrences"]["items"][0]["payload"]["data"]["remote_address"],
        "203.0.113.9"
    );
    assert!(fixture["inbound_occurrences"]["next_cursor"].is_null());
}

#[test]
fn runtime_inventory_fixture_covers_complete_safe_contract_states() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/fixtures/runtime-inventory.json"
    ))
    .expect("valid runtime inventory fixture");
    assert_eq!(fixture["filtered_summary"]["item_count"], 1);
    assert_eq!(
        fixture["item_details"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>(),
        ["process", "destination", "domain", "syscall"]
            .map(str::to_owned)
            .into_iter()
            .collect()
    );
    for detail in fixture["item_details"].as_object().unwrap().values() {
        for field in ["releases", "sightings", "groups", "occurrences"] {
            let path = detail["evidence"][field].as_str().unwrap();
            assert!(path.starts_with("/api/v1/projects/"));
            assert!(path.ends_with(field));
            assert!(!path.contains(['?', '#', '\\']));
            assert!(!path.contains("..") && !path.contains("://"));
        }
        assert!(detail.get("policy_placement_summary").is_some());
    }
    for page in ["sightings", "groups", "occurrences"] {
        assert!(fixture[page]["items"].as_array().unwrap().len() <= 200);
        assert!(
            fixture["terminal_pages"][page]["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    for facet in [
        "cluster",
        "namespace",
        "workload_kind",
        "workload_name",
        "container_name",
    ] {
        let page = &fixture["facets"][facet];
        assert!(page["items"].as_array().unwrap().len() <= 200);
        for option in page["items"].as_array().unwrap() {
            for field in ["value", "label", "item_count", "occurrence_count"] {
                assert!(
                    option.get(field).is_some(),
                    "{facet} option missing {field}"
                );
            }
        }
    }
    for error in [
        "invalid_cursor",
        "unauthorized",
        "not_found",
        "server_error",
    ] {
        for field in ["error", "message", "request_id"] {
            assert!(fixture["errors"][error].get(field).is_some());
        }
    }
    let unsafe_values = &fixture["unsafe_display_text"];
    for field in [
        "cluster_label",
        "namespace",
        "workload_kind",
        "workload_name",
        "pod_uid",
        "pod_name",
        "container_name",
        "node_name",
    ] {
        assert!(unsafe_values[field].is_string(), "missing unsafe {field}");
    }
    for field in [
        "executable",
        "process_command",
        "destination_address",
        "name",
        "syscall",
        "operation",
        "path",
        "new_path",
    ] {
        assert!(
            unsafe_values["semantic_summary"][field].is_string(),
            "missing unsafe semantic {field}"
        );
    }
}

fn assert_inventory_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    assert_inventory_hardening_contract(document);
    assert_query_parameters(
        document,
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory",
        "get",
        &[
            "kind",
            "operation",
            "release_id",
            "cluster_id",
            "namespace",
            "workload_kind",
            "workload_name",
            "container_name",
            "observed_from",
            "observed_to",
            "search",
            "identity_token",
            "verdict",
            "suppressed",
            "evaluation_pending",
            "cursor",
            "limit",
        ],
    );
    assert_query_parameters(
        document,
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution",
        "get",
        &[
            "kind",
            "operation",
            "release_id",
            "cluster_id",
            "namespace",
            "workload_kind",
            "workload_name",
            "container_name",
            "observed_from",
            "observed_to",
            "search",
            "limit",
        ],
    );
    assert_eq!(
        schemas["InventoryDistribution"]["properties"]["entries"]["maxItems"],
        10
    );
    assert_eq!(
        schemas["InventoryKind"]["enum"],
        serde_json::json!([
            "process",
            "destination",
            "domain",
            "syscall",
            "inbound_endpoint",
            "file_activity",
            "lifecycle"
        ])
    );
    assert_inventory_lifecycle_contract(schemas);
    assert_eq!(
        schemas["InventoryReleasePresence"]["enum"],
        serde_json::json!(["observed", "not_observed", "unknown"])
    );
    for schema in [
        "InventoryProcessIdentity",
        "InventoryDestinationIdentity",
        "InventoryDomainIdentity",
        "InventorySyscallIdentity",
        "InventoryInboundEndpointIdentity",
        "FileActivitySemanticSummary",
        "InventoryItem",
        "InventoryReleaseEvidence",
        "InventorySighting",
    ] {
        assert_eq!(
            schemas[schema]["additionalProperties"], false,
            "{schema} must remain a closed safe contract"
        );
    }
    for page in [
        "InventoryItemPage",
        "InventoryReleasePresencePage",
        "InventorySightingPage",
        "InventoryGroupPage",
        "InventoryOccurrencePage",
    ] {
        assert_eq!(schemas[page]["properties"]["items"]["maxItems"], 200);
    }
    assert_inventory_policy_contract(document);
}

fn assert_inventory_hardening_contract(document: &serde_json::Value) {
    let summary_path =
        "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/summary";
    let facet_path = "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/facets/{facet}";
    let scope = [
        "operation",
        "release_id",
        "cluster_id",
        "namespace",
        "workload_kind",
        "workload_name",
        "container_name",
        "observed_from",
        "observed_to",
        "search",
    ];
    assert_query_parameters(document, summary_path, "get", &scope);
    let mut facet_parameters = vec!["kind"];
    facet_parameters.extend(scope);
    facet_parameters.extend(["facet_search", "cursor", "limit"]);
    assert_query_parameters(document, facet_path, "get", &facet_parameters);
    let schemas = &document["components"]["schemas"];
    assert_eq!(
        schemas["InventoryFacet"]["enum"],
        serde_json::json!([
            "cluster",
            "namespace",
            "workload_kind",
            "workload_name",
            "container_name"
        ])
    );
    assert_eq!(
        schemas["InventoryFacetPage"]["properties"]["items"]["maxItems"],
        200
    );
    assert!(schemas["InventoryFacetPage"].get("example").is_some());
    assert!(schemas["InventorySummary"].get("example").is_some());
    for status in ["400", "401", "404"] {
        assert_eq!(
            document["paths"][summary_path]["get"]["responses"][status]["$ref"],
            "#/components/responses/Error"
        );
        assert_eq!(
            document["paths"][facet_path]["get"]["responses"][status]["$ref"],
            "#/components/responses/Error"
        );
    }
    assert_required_fields(document, "Error", &["error", "message", "request_id"]);
    let links = &schemas["InventoryEvidenceLinks"];
    assert!(
        links["description"]
            .as_str()
            .unwrap()
            .contains("typed child routes")
    );
    for field in ["releases", "sightings", "groups", "occurrences"] {
        let pattern = links["properties"][field]["pattern"].as_str().unwrap();
        assert!(pattern.starts_with('^') && pattern.ends_with('$'));
        assert!(!pattern.contains(['?', '#']));
    }
}

fn assert_inventory_policy_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    assert_required_fields(
        document,
        "InventorySighting",
        &["policy_evaluation", "active_suppression", "actionable"],
    );
    assert!(
        schemas["InventoryItemDetail"]["allOf"][1]["required"]
            .as_array()
            .expect("InventoryItemDetail extension required fields")
            .iter()
            .any(|field| field == "policy_placement_summary")
    );
}

fn assert_inventory_lifecycle_contract(schemas: &serde_json::Value) {
    assert_eq!(
        schemas["InventoryLifecycleSemanticSummary"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    for (schema, event_kind, identity_fields) in [
        (
            "ProcessExitSemanticSummary",
            "process.exit",
            &["identity", "termination"][..],
        ),
        (
            "ContainerTerminationSemanticSummary",
            "container.terminated",
            &["container_name", "reason", "exit_code"][..],
        ),
        (
            "ContainerRestartSemanticSummary",
            "container.restart",
            &["container_name"][..],
        ),
        (
            "RestartLoopSemanticSummary",
            "container.restart_loop",
            &["container_name"][..],
        ),
    ] {
        assert_eq!(
            schemas[schema]["properties"]["event_kind"]["const"],
            event_kind
        );
        let required = schemas[schema]["required"].as_array().unwrap();
        for field in identity_fields {
            assert!(required.iter().any(|value| value == field));
        }
    }
}

fn assert_network_contract(document: &serde_json::Value) {
    let schemas = &document["components"]["schemas"];
    assert_eq!(
        schemas["NetworkConnectSemanticSummary"]["additionalProperties"],
        false
    );
    assert_eq!(
        schemas["NetworkConnectPayload"]["properties"]["data"]["additionalProperties"],
        false
    );
    for forbidden in ["payload", "dns_name", "source_port", "url", "http"] {
        assert!(
            schemas["NetworkConnectSemanticSummary"]["properties"][forbidden].is_null(),
            "network semantic summary must not expose {forbidden}"
        );
        assert!(
            schemas["NetworkConnectPayload"]["properties"]["data"]["properties"][forbidden]
                .is_null(),
            "network occurrence payload must not expose {forbidden}"
        );
    }
    for schema in [
        "InboundNetworkSemanticSummary",
        "NetworkListenPayload",
        "NetworkAcceptPayload",
    ] {
        assert_eq!(schemas[schema]["additionalProperties"], false);
    }
    for forbidden in ["remote_address", "remote_port", "payload", "http", "tls"] {
        assert!(
            schemas["InboundNetworkSemanticSummary"]["properties"][forbidden].is_null(),
            "inbound group summary must not expose {forbidden}"
        );
    }
    assert_eq!(
        schemas["NetworkAcceptPayload"]["properties"]["data"]["additionalProperties"],
        false
    );
}

fn assert_recovery_contract(document: &serde_json::Value) {
    for schema_name in [
        "DeliveryRecoveryResult",
        "BulkRecoveryResult",
        "RecoveryOperationSummary",
        "RecoveryOperationPage",
    ] {
        assert_eq!(
            document["components"]["schemas"][schema_name]["additionalProperties"], false,
            "{schema_name} must remain concrete"
        );
    }
    for path in [
        "/api/v1/projects/{project_id}/notification-deliveries/bulk-retry",
        "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/retry",
        "/api/v1/projects/{project_id}/notification-deliveries/{delivery_id}/cancel",
    ] {
        let parameters = document["paths"][path]["post"]["parameters"]
            .as_array()
            .expect("recovery command parameters");
        assert!(
            parameters
                .iter()
                .any(|parameter| { parameter["$ref"] == "#/components/parameters/IdempotencyKey" })
        );
        assert!(document["paths"][path]["post"]["responses"]["409"].is_object());
    }
}

fn assert_notification_health_contract(document: &serde_json::Value) {
    let schema = &document["components"]["schemas"]["NotificationHealth"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["state"]["enum"],
        serde_json::json!([
            "disabled",
            "idle",
            "backlogged",
            "retrying",
            "failing",
            "draining"
        ])
    );
    assert!(schema["required"].as_array().is_some_and(|fields| {
        ["state", "delivery_enabled", "observed_at"]
            .iter()
            .all(|field| fields.iter().any(|item| item == field))
    }));
}

fn assert_delivery_contract(document: &serde_json::Value) {
    let schema = &document["components"]["schemas"]["DeliverySummary"];
    let required = schema["required"]
        .as_array()
        .expect("delivery required fields");
    for field in [
        "next_attempt_at",
        "terminal_reason",
        "semantic_metadata",
        "destination",
    ] {
        assert!(required.iter().any(|item| item == field), "missing {field}");
    }
    assert_eq!(
        document["components"]["schemas"]["SafeDestination"]["additionalProperties"],
        false
    );
    assert!(
        document["components"]["schemas"]["SafeDestination"]["properties"]["url"].is_null(),
        "safe destination must not expose a URL"
    );
    assert_eq!(
        document["components"]["schemas"]["DeliverySemanticMetadata"]["additionalProperties"],
        false
    );
}

fn assert_query_parameters(
    document: &serde_json::Value,
    path: &str,
    method: &str,
    expected: &[&str],
) {
    let parameters = document["paths"][path][method]["parameters"]
        .as_array()
        .expect("operation parameters");
    let actual = parameters
        .iter()
        .map(|parameter| {
            let parameter = resolve_component(document, parameter, "parameters");
            assert_eq!(parameter["in"], "query", "non-query operation parameter");
            parameter["name"].as_str().expect("parameter name")
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        actual,
        expected.iter().copied().collect(),
        "query parameter drift for {method} {path}"
    );
}

fn assert_success_response_is_typed(
    document: &serde_json::Value,
    operation: &serde_json::Value,
    path: &str,
    method: &str,
) {
    let responses = operation["responses"]
        .as_object()
        .expect("responses object");
    let (status, response) = responses
        .iter()
        .find(|(status, _)| status.starts_with('2'))
        .unwrap_or_else(|| panic!("missing success response for {method} {path}"));
    if status.as_str() == "204" {
        assert!(response.get("content").is_none());
        return;
    }
    let response = resolve_component(document, response, "responses");
    let schema = &response["content"]["application/json"]["schema"];
    assert!(
        schema.is_object(),
        "missing JSON success schema for {method} {path}"
    );
    let schema = resolve_component(document, schema, "schemas");
    assert_ne!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(true)),
        "untyped success schema for {method} {path}"
    );
    assert!(
        schema.get("properties").is_some()
            || schema.get("items").is_some()
            || schema.get("allOf").is_some()
            || schema.get("oneOf").is_some(),
        "success schema has no declared shape for {method} {path}"
    );
}

fn resolve_component<'a>(
    document: &'a serde_json::Value,
    value: &'a serde_json::Value,
    component_kind: &str,
) -> &'a serde_json::Value {
    let Some(reference) = value.get("$ref").and_then(serde_json::Value::as_str) else {
        return value;
    };
    let name = reference
        .strip_prefix(&format!("#/components/{component_kind}/"))
        .unwrap_or_else(|| panic!("unexpected component reference {reference}"));
    resolve_component(
        document,
        &document["components"][component_kind][name],
        component_kind,
    )
}
