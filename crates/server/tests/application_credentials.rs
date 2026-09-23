use server::{
    application_credentials::{authenticate, issue, list, remains_active, revoke},
    bootstrap::{BootstrapConfig, bootstrap},
    database::MIGRATOR,
};
use uuid::Uuid;

use std::time::Instant;

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

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn credential_lifecycle_is_secret_safe_and_revocable(pool: sqlx::PgPool) {
    let ids = bootstrap(&pool, &config("application-credentials"))
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let first = issue(
        &mut tx,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
        "default",
    )
    .await
    .unwrap();
    let first_token = first.token().to_owned();
    tx.commit().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let second = issue(
        &mut tx,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
        "rotation",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let summaries = list(
        &pool,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
    )
    .await
    .unwrap();
    assert_eq!(summaries.len(), 2);
    assert!(
        !serde_json::to_string(&summaries)
            .unwrap()
            .contains(&first_token)
    );
    let stored_plaintext: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM application_ingestion_credentials WHERE encode(credential_hash,'escape')=$1)",
    )
    .bind(&first_token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!stored_plaintext);

    let first_scope = authenticate(&pool, &first_token).await.unwrap().unwrap();
    let second_scope = authenticate(&pool, second.token()).await.unwrap().unwrap();
    assert_eq!(first_scope.application_id, ids.application_id);
    assert_eq!(second_scope.application_id, ids.application_id);

    let revoked_at = revoke(
        &pool,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
        first.summary.id,
    )
    .await
    .unwrap()
    .unwrap();
    let repeated = revoke(
        &pool,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
        first.summary.id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(revoked_at, repeated);
    assert!(authenticate(&pool, &first_token).await.unwrap().is_none());
    let mut tx = pool.begin().await.unwrap();
    assert!(!remains_active(&mut tx, first_scope).await.unwrap());
    tx.rollback().await.unwrap();

    revoke(
        &pool,
        ids.organization_id,
        ids.project_id,
        ids.application_id,
        second.summary.id,
    )
    .await
    .unwrap();
    assert!(authenticate(&pool, second.token()).await.unwrap().is_none());
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn credential_name_and_tenant_scope_are_enforced(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("credential-scope-first"))
        .await
        .unwrap();
    let second = bootstrap(&pool, &config("credential-scope-second"))
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    issue(
        &mut tx,
        first.organization_id,
        first.project_id,
        first.application_id,
        "default",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut duplicate_tx = pool.begin().await.unwrap();
    assert!(
        issue(
            &mut duplicate_tx,
            first.organization_id,
            first.project_id,
            first.application_id,
            "default",
        )
        .await
        .is_err()
    );
    duplicate_tx.rollback().await.unwrap();

    let mut cross_tenant_tx = pool.begin().await.unwrap();
    assert!(
        issue(
            &mut cross_tenant_tx,
            first.organization_id,
            first.project_id,
            second.application_id,
            "cross-tenant",
        )
        .await
        .is_err()
    );
    cross_tenant_tx.rollback().await.unwrap();
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "acceptance benchmark requiring PostgreSQL"]
async fn credential_check_overhead_is_bounded(pool: sqlx::PgPool) {
    let ids = bootstrap(&pool, &config("credential-check-benchmark"))
        .await
        .unwrap();
    let mut tokens = Vec::with_capacity(32);
    for index in 0..32 {
        let mut tx = pool.begin().await.unwrap();
        let credential = issue(
            &mut tx,
            ids.organization_id,
            ids.project_id,
            ids.application_id,
            &format!("benchmark-{index}"),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        tokens.push(credential.token().to_owned());
    }

    for stream_count in [1_usize, 8, 16, 32] {
        let started = Instant::now();
        let checks = 1_000;
        for index in 0..checks {
            let scope = authenticate(&pool, &tokens[index % stream_count])
                .await
                .unwrap()
                .unwrap();
            let mut tx = pool.begin().await.unwrap();
            assert!(remains_active(&mut tx, scope).await.unwrap());
            tx.rollback().await.unwrap();
        }
        let elapsed = started.elapsed();
        println!(
            "credential check benchmark: streams={stream_count} checks={checks} elapsed_ms={} average_us={}",
            elapsed.as_millis(),
            elapsed.as_micros() / checks as u128
        );
    }
}
