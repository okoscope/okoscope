use server::bootstrap::{BootstrapConfig, bootstrap};
use server::database::{MIGRATOR, REQUIRED_MIGRATION, migrate, verify_schema};
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

#[sqlx::test]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn migration_only_initializes_a_fresh_database(pool: sqlx::PgPool) {
    let report = migrate(&pool).await.expect("fresh migration succeeds");

    assert_eq!(report.required, REQUIRED_MIGRATION);
    assert_eq!(report.applied, REQUIRED_MIGRATION);
    verify_schema(&pool).await.expect("schema is current");
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn migration_only_is_idempotent_when_current(pool: sqlx::PgPool) {
    let first = migrate(&pool).await.expect("current migration succeeds");
    let second = migrate(&pool).await.expect("retry succeeds");

    assert_eq!(first, second);
    assert_eq!(second.applied, REQUIRED_MIGRATION);
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn transactional_mail_schema_has_verified_backfill_defaults_and_secret_columns(
    pool: sqlx::PgPool,
) {
    for table in ["user_email_actions", "transactional_mail_outbox"] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists, "{table} must exist");
    }
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash,email_verified_at) VALUES($1,'verified@example.com',$2,now())")
        .bind(user_id).bind("x".repeat(32)).execute(&pool).await.unwrap();
    let row: (bool, String) = sqlx::query_as(
        "SELECT email_verified_at IS NOT NULL,preferred_locale FROM users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (true, "en".into()));
    let columns: Vec<String> = sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='transactional_mail_outbox'")
        .fetch_all(&pool).await.unwrap();
    for expected in [
        "payload_ciphertext",
        "payload_nonce",
        "claimed_until",
        "attempt_count",
        "retain_until",
        "ciphertext_erased_at",
    ] {
        assert!(
            columns.iter().any(|column| column == expected),
            "missing {expected}"
        );
    }
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn navigation_latest_observation_index_exists(pool: sqlx::PgPool) {
    let definition: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename='runtime_events' AND indexname='runtime_events_application_observed_idx'",
    )
    .fetch_one(&pool)
    .await
    .expect("navigation latest-observation index exists");

    for column in [
        "organization_id",
        "project_id",
        "application_id",
        "observed_at DESC",
    ] {
        assert!(definition.contains(column), "index must include {column}");
    }
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn migration_only_reports_a_failed_migration(pool: sqlx::PgPool) {
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = $1")
        .bind(REQUIRED_MIGRATION)
        .execute(&pool)
        .await
        .expect("mark migration failed");

    migrate(&pool).await.expect_err("dirty migration must fail");
    verify_schema(&pool)
        .await
        .expect_err("failed required migration must not be ready");
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn migration_only_can_retry_after_failure_is_repaired(pool: sqlx::PgPool) {
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = $1")
        .bind(REQUIRED_MIGRATION)
        .execute(&pool)
        .await
        .expect("mark migration failed");
    migrate(&pool).await.expect_err("dirty migration must fail");

    sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE version = $1")
        .bind(REQUIRED_MIGRATION)
        .execute(&pool)
        .await
        .expect("repair migration history");
    let report = migrate(&pool).await.expect("retry succeeds after repair");

    assert_eq!(report.applied, REQUIRED_MIGRATION);
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn automatic_release_schema_preserves_manual_releases(pool: sqlx::PgPool) {
    let ids = bootstrap(&pool, &config("automatic-release-legacy"))
        .await
        .unwrap();
    let release_id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,'legacy-v1',now())")
        .bind(release_id)
        .bind(ids.organization_id)
        .bind(ids.project_id)
        .bind(ids.application_id)
        .execute(&pool)
        .await
        .unwrap();

    let row: (String, Option<i16>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT source,identity_version,identity_digest FROM releases WHERE id=$1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, ("manual".into(), None, None));
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn user_authorisation_schema_replaces_legacy_credentials(pool: sqlx::PgPool) {
    for table in ["users", "organization_memberships", "user_sessions"] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists, "{table} must exist");
    }
    let legacy_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('api_credentials') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!legacy_exists, "legacy tenant credentials must be removed");
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn inventory_schema_enforces_identity_tenant_scope_and_indexes(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("inventory-first")).await.unwrap();
    let second = bootstrap(&pool, &config("inventory-second")).await.unwrap();
    let digest = vec![7_u8; 32];
    let item_id = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,'process',1,$5,'{\"executable\":\"/app\"}'::jsonb,now(),now(),1)")
        .bind(item_id)
        .bind(first.organization_id)
        .bind(first.project_id)
        .bind(first.application_id)
        .bind(&digest)
        .execute(&pool)
        .await
        .unwrap();

    let duplicate = sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,'process',1,$5,'{}'::jsonb,now(),now(),1)")
        .bind(Uuid::new_v4())
        .bind(first.organization_id)
        .bind(first.project_id)
        .bind(first.application_id)
        .bind(&digest)
        .execute(&pool)
        .await;
    assert!(
        duplicate.is_err(),
        "semantic identity must be unique per application and version"
    );

    let cross_tenant = sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,'process',1,$5,'{}'::jsonb,now(),now(),1)")
        .bind(Uuid::new_v4())
        .bind(first.organization_id)
        .bind(first.project_id)
        .bind(second.application_id)
        .bind(vec![8_u8; 32])
        .execute(&pool)
        .await;
    assert!(
        cross_tenant.is_err(),
        "application foreign key must preserve tenant scope"
    );

    let indexes: Vec<String> = sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename LIKE 'runtime_inventory_%'")
        .fetch_all(&pool)
        .await
        .unwrap();
    for required in [
        "runtime_inventory_items_recent_idx",
        "runtime_inventory_items_kind_recent_idx",
        "runtime_inventory_releases_release_idx",
        "runtime_inventory_sightings_filter_idx",
        "runtime_inventory_sightings_item_recent_idx",
    ] {
        assert!(
            indexes.iter().any(|index| index == required),
            "missing index {required}"
        );
    }
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn managed_policy_schema_enforces_revision_and_suppression_contracts(pool: sqlx::PgPool) {
    let required_tables = [
        "runtime_policies",
        "runtime_policy_states",
        "runtime_policy_revisions",
        "runtime_policy_commands",
        "runtime_policy_suppressions",
        "runtime_policy_recomputations",
        "runtime_group_policy_evaluations",
        "runtime_sighting_policy_evaluations",
    ];
    for table in required_tables {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists, "{table} must exist");
    }

    let immutable_trigger: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='runtime_policy_revisions_immutable' AND NOT tgisinternal)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(immutable_trigger);

    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname FROM pg_constraint WHERE conrelid IN ('runtime_policies'::regclass,'runtime_policy_revisions'::regclass,'runtime_policy_commands'::regclass,'runtime_policy_suppressions'::regclass) ORDER BY conname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for expected in [
        "runtime_policies_current_revision_fkey",
        "runtime_policy_revisions_prior_fkey",
        "runtime_policy_commands_organization_id_idempotency_key_key",
        "runtime_policy_suppressions_check",
    ] {
        assert!(
            constraints.iter().any(|name| name == expected),
            "missing constraint {expected}: {constraints:?}"
        );
    }
}
