use server::{
    database::MIGRATOR,
    notification::{
        recovery::{
            BulkRetryFilter, RecoveryActor, RecoveryConflictCode, RecoveryError, RecoveryRepository,
        },
        retention::{RetentionConfig, delete_once},
    },
};
use std::time::Duration;
use uuid::Uuid;

#[allow(clippy::struct_field_names)]
struct Fixture {
    organization_id: Uuid,
    project_id: Uuid,
    credential_id: Uuid,
    destination_id: Uuid,
}

async fn fixture(pool: &sqlx::PgPool) -> Fixture {
    let fixture = Fixture {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        credential_id: Uuid::new_v4(),
        destination_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Recovery test')")
        .bind(fixture.organization_id)
        .bind(format!("recovery-{}", fixture.organization_id))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'project','Project')",
    )
    .bind(fixture.project_id)
    .bind(fixture.organization_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(fixture.credential_id)
        .bind(format!("{}@example.test", fixture.credential_id))
        .bind(server::auth::hash_password("retention test password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO webhook_destinations(id,organization_id,project_id,name,url,encrypted_secret,secret_nonce) VALUES($1,$2,$3,'receiver','https://receiver.example/hook',$4,$5)")
        .bind(fixture.destination_id)
        .bind(fixture.organization_id)
        .bind(fixture.project_id)
        .bind(vec![4_u8; 48])
        .bind(vec![5_u8; 24])
        .execute(pool)
        .await
        .unwrap();
    fixture
}

async fn delivery(pool: &sqlx::PgPool, fixture: &Fixture, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    let terminal = matches!(status, "failed" | "succeeded" | "suppressed" | "cancelled");
    let in_flight = status == "in_flight";
    sqlx::query("INSERT INTO notification_deliveries(id,organization_id,project_id,destination_id,origin,source,event_name,payload,status,lease_owner,lease_expires_at,attempt_count,max_attempts,terminal_at,last_error_class,last_error) VALUES($1,$2,$3,$4,'test','test','okoscope.test','{}',$5,$6,CASE WHEN $6::uuid IS NULL THEN NULL ELSE now()+interval '1 minute' END,1,3,CASE WHEN $7 THEN now() ELSE NULL END,CASE WHEN $5='failed' THEN 'timeout' ELSE NULL END,CASE WHEN $5='failed' THEN 'timeout' ELSE NULL END)")
        .bind(id).bind(fixture.organization_id).bind(fixture.project_id).bind(fixture.destination_id).bind(status)
        .bind(in_flight.then(Uuid::new_v4)).bind(terminal).execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn retry_preserves_history_and_is_idempotent(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    let delivery_id = delivery(&pool, &fixture, "failed").await;
    sqlx::query("INSERT INTO notification_delivery_attempts(id,organization_id,project_id,delivery_id,recovery_generation,attempt_number,started_at,finished_at,duration_ms,outcome,error_class) VALUES($1,$2,$3,$4,0,1,now(),now(),1,'failed','timeout')")
        .bind(Uuid::new_v4()).bind(fixture.organization_id).bind(fixture.project_id).bind(delivery_id).execute(&pool).await.unwrap();
    let repository = RecoveryRepository::new(pool.clone(), [9; 32]);
    let actor = RecoveryActor {
        id: fixture.credential_id,
        request_id: "request-retry-1",
    };
    let first = repository
        .retry_delivery(
            fixture.organization_id,
            fixture.project_id,
            delivery_id,
            actor,
            "retry-command-0001",
        )
        .await
        .unwrap();
    assert_eq!(first.status, "pending");
    assert_eq!(first.recovery_generation, 1);
    assert_eq!(first.current_attempt_count, 0);
    assert_eq!(first.total_attempt_count, 1);
    assert!(!first.replayed);
    let repeated = repository
        .retry_delivery(
            fixture.organization_id,
            fixture.project_id,
            delivery_id,
            actor,
            "retry-command-0001",
        )
        .await
        .unwrap();
    assert!(repeated.replayed);
    assert_eq!(repeated.operation_id, first.operation_id);
    assert!(matches!(
        repository
            .cancel_delivery(
                fixture.organization_id,
                fixture.project_id,
                delivery_id,
                actor,
                "retry-command-0001"
            )
            .await,
        Err(RecoveryError::Conflict(
            RecoveryConflictCode::IdempotencyKeyReused
        ))
    ));
    let state: (String, i32, i32, i64) = sqlx::query_as("SELECT status,recovery_generation,attempt_count,(SELECT count(*) FROM notification_delivery_attempts WHERE delivery_id=$1) FROM notification_deliveries WHERE id=$1")
        .bind(delivery_id).fetch_one(&pool).await.unwrap();
    assert_eq!(state, ("pending".into(), 1, 0, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM notification_recovery_operation_deliveries WHERE operation_id=$1 AND delivery_id=$2"
        )
        .bind(first.operation_id)
        .bind(delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    let disabled_delivery = delivery(&pool, &fixture, "failed").await;
    sqlx::query("UPDATE webhook_destinations SET enabled=false WHERE id=$1")
        .bind(fixture.destination_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .retry_delivery(
                fixture.organization_id,
                fixture.project_id,
                disabled_delivery,
                actor,
                "retry-command-disabled-0001"
            )
            .await,
        Err(RecoveryError::Conflict(
            RecoveryConflictCode::DestinationDisabled
        ))
    ));
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn cancel_conflicts_with_lease_and_bulk_is_bounded(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    let repository = RecoveryRepository::new(pool.clone(), [8; 32]);
    let actor = RecoveryActor {
        id: fixture.credential_id,
        request_id: "request-cancel-1",
    };
    let pending = delivery(&pool, &fixture, "pending").await;
    let cancelled = repository
        .cancel_delivery(
            fixture.organization_id,
            fixture.project_id,
            pending,
            actor,
            "cancel-command-0001",
        )
        .await
        .unwrap();
    assert_eq!(cancelled.status, "cancelled");
    assert!(
        repository
            .cancel_delivery(
                fixture.organization_id,
                fixture.project_id,
                pending,
                actor,
                "cancel-command-0001"
            )
            .await
            .unwrap()
            .replayed
    );
    let in_flight = delivery(&pool, &fixture, "in_flight").await;
    assert!(matches!(
        repository
            .cancel_delivery(
                fixture.organization_id,
                fixture.project_id,
                in_flight,
                actor,
                "cancel-command-0002"
            )
            .await,
        Err(RecoveryError::Conflict(RecoveryConflictCode::ActiveLease))
    ));
    for _ in 0..3 {
        delivery(&pool, &fixture, "failed").await;
    }
    let bulk = repository
        .bulk_retry(
            fixture.organization_id,
            fixture.project_id,
            &BulkRetryFilter {
                limit: Some(2),
                ..BulkRetryFilter::default()
            },
            actor,
            "bulk-retry-command-0001",
        )
        .await
        .unwrap();
    assert_eq!(bulk.retried_count, 2);
    assert_eq!(bulk.remaining_count, 1);
    assert!(bulk.has_more);
    assert!(
        repository
            .bulk_retry(
                fixture.organization_id,
                fixture.project_id,
                &BulkRetryFilter {
                    limit: Some(2),
                    ..BulkRetryFilter::default()
                },
                actor,
                "bulk-retry-command-0001",
            )
            .await
            .unwrap()
            .replayed
    );

    let locked_delivery = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM notification_deliveries WHERE organization_id=$1 AND project_id=$2 AND status='failed' LIMIT 1",
    )
    .bind(fixture.organization_id)
    .bind(fixture.project_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM notification_deliveries WHERE id=$1 FOR UPDATE")
        .bind(locked_delivery)
        .execute(&mut *lock)
        .await
        .unwrap();
    let skipped_locked = repository
        .bulk_retry(
            fixture.organization_id,
            fixture.project_id,
            &BulkRetryFilter {
                limit: Some(1),
                ..BulkRetryFilter::default()
            },
            actor,
            "bulk-retry-command-locked-0001",
        )
        .await
        .unwrap();
    assert_eq!(skipped_locked.selected_count, 0);
    assert_eq!(skipped_locked.remaining_count, 1);
    assert!(skipped_locked.has_more);
    lock.rollback().await.unwrap();
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn retention_is_bounded_and_preserves_active_work(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    let terminal = delivery(&pool, &fixture, "failed").await;
    let active = delivery(&pool, &fixture, "pending").await;
    let recovered = delivery(&pool, &fixture, "failed").await;
    let recovery = RecoveryRepository::new(pool.clone(), [6; 32])
        .retry_delivery(
            fixture.organization_id,
            fixture.project_id,
            recovered,
            RecoveryActor {
                id: fixture.credential_id,
                request_id: "retention-recovery-request",
            },
            "retention-recovery-command-0001",
        )
        .await
        .unwrap();
    sqlx::query("UPDATE notification_recovery_operations SET completed_at=now()-interval '2 days' WHERE id=$1")
        .bind(recovery.operation_id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE notification_deliveries SET terminal_at=now()-interval '2 days',created_at=now()-interval '2 days' WHERE id=$1")
        .bind(terminal).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE notification_deliveries SET created_at=now()-interval '2 days' WHERE id=$1",
    )
    .bind(active)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE organizations SET notification_retention_enabled=true,notification_retention_days=1 WHERE id=$1")
        .bind(fixture.organization_id).execute(&pool).await.unwrap();
    let disabled = delete_once(
        &pool,
        RetentionConfig {
            enabled: false,
            batch_size: 10,
            poll_interval: Duration::from_secs(60),
        },
    )
    .await
    .unwrap();
    assert_eq!(disabled.terminal_deliveries_deleted, 0);
    let stats = delete_once(
        &pool,
        RetentionConfig {
            enabled: true,
            batch_size: 1,
            poll_interval: Duration::from_secs(60),
        },
    )
    .await
    .unwrap();
    assert_eq!(stats.terminal_deliveries_deleted, 1);
    assert_eq!(stats.recovery_operations_deleted, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries WHERE id=$1")
            .bind(terminal)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries WHERE id=$1")
            .bind(active)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries WHERE id=$1")
            .bind(recovered)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
}

fn cleanup_config(batch_size: i64) -> RetentionConfig {
    RetentionConfig {
        enabled: true,
        batch_size,
        poll_interval: Duration::from_secs(60),
    }
}

async fn enable_retention(pool: &sqlx::PgPool, fixture: &Fixture) {
    sqlx::query("UPDATE organizations SET notification_retention_enabled=true,notification_retention_days=1 WHERE id=$1")
        .bind(fixture.organization_id).execute(pool).await.unwrap();
}

async fn expire(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query("UPDATE notification_deliveries SET status='failed',terminal_at=now()-interval '2 days',lease_owner=NULL,lease_expires_at=NULL WHERE id=$1")
        .bind(id).execute(pool).await.unwrap();
}

fn actor(fixture: &Fixture) -> RecoveryActor<'_> {
    RecoveryActor {
        id: fixture.credential_id,
        request_id: "retention-test",
    }
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn unified_cleanup_removes_single_and_partial_then_final_bulk_history(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    enable_retention(&pool, &fixture).await;
    let first = delivery(&pool, &fixture, "failed").await;
    let second = delivery(&pool, &fixture, "failed").await;
    let repository = RecoveryRepository::new(pool.clone(), [9; 32]);
    let bulk = repository
        .bulk_retry(
            fixture.organization_id,
            fixture.project_id,
            &BulkRetryFilter::default(),
            actor(&fixture),
            "retention-bulk-0001",
        )
        .await
        .unwrap();
    let single = repository
        .cancel_delivery(
            fixture.organization_id,
            fixture.project_id,
            first,
            actor(&fixture),
            "retention-cancel-0001",
        )
        .await
        .unwrap();
    expire(&pool, first).await;
    let stats = delete_once(&pool, cleanup_config(1)).await.unwrap();
    assert_eq!(stats.terminal_deliveries_deleted, 1);
    assert_eq!(stats.recovery_operations_deleted, 1);
    assert!(
        repository
            .operation_detail(
                fixture.organization_id,
                fixture.project_id,
                single.operation_id
            )
            .await
            .unwrap()
            .is_none()
    );
    let detail = repository
        .operation_detail(
            fixture.organization_id,
            fixture.project_id,
            bulk.operation_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.affected_deliveries.len(), 1);
    assert_eq!(detail.affected_deliveries[0].delivery_id, second);
    let replay = repository
        .bulk_retry(
            fixture.organization_id,
            fixture.project_id,
            &BulkRetryFilter::default(),
            actor(&fixture),
            "retention-bulk-0001",
        )
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.retried_count, 2);
    assert!(
        !serde_json::to_string(&detail)
            .unwrap()
            .contains(&first.to_string())
    );
    let stored: String = sqlx::query_scalar("SELECT result::text || safe_filters::text FROM notification_recovery_operations WHERE id=$1")
        .bind(bulk.operation_id).fetch_one(&pool).await.unwrap();
    assert!(!stored.contains(&first.to_string()));
    assert!(matches!(
        repository
            .cancel_delivery(
                fixture.organization_id,
                fixture.project_id,
                first,
                actor(&fixture),
                "retention-cancel-0001"
            )
            .await,
        Err(RecoveryError::NotFound)
    ));
    expire(&pool, second).await;
    let stats = delete_once(&pool, cleanup_config(1)).await.unwrap();
    assert_eq!(stats.recovery_operations_deleted, 1);
    assert!(
        repository
            .operation_detail(
                fixture.organization_id,
                fixture.project_id,
                bulk.operation_id
            )
            .await
            .unwrap()
            .is_none()
    );
    delivery(&pool, &fixture, "failed").await;
    let fresh = repository
        .bulk_retry(
            fixture.organization_id,
            fixture.project_id,
            &BulkRetryFilter::default(),
            actor(&fixture),
            "retention-bulk-0001",
        )
        .await
        .unwrap();
    assert!(!fresh.replayed);
    assert_eq!(fresh.retried_count, 1);
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn policies_change_live_and_locked_active_and_recent_deliveries_survive(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    enable_retention(&pool, &fixture).await;
    let old = delivery(&pool, &fixture, "failed").await;
    expire(&pool, old).await;
    let recent = delivery(&pool, &fixture, "succeeded").await;
    let active = delivery(&pool, &fixture, "in_flight").await;
    sqlx::query(
        "UPDATE notification_deliveries SET created_at=now()-interval '10 days' WHERE id=$1",
    )
    .bind(active)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE projects SET notification_retention_enabled=false,notification_retention_days=1 WHERE id=$1")
        .bind(fixture.project_id).execute(&pool).await.unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        0
    );
    sqlx::query("UPDATE projects SET notification_retention_enabled=NULL,notification_retention_days=NULL WHERE id=$1")
        .bind(fixture.project_id).execute(&pool).await.unwrap();
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM notification_deliveries WHERE id=$1 FOR UPDATE")
        .bind(old)
        .execute(&mut *lock)
        .await
        .unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        0
    );
    lock.rollback().await.unwrap();
    let repository = RecoveryRepository::new(pool.clone(), [8; 32]);
    repository
        .retry_delivery(
            fixture.organization_id,
            fixture.project_id,
            old,
            actor(&fixture),
            "live-retry-0001",
        )
        .await
        .unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        0
    );
    sqlx::query(
        "UPDATE notification_deliveries SET status='succeeded',terminal_at=now() WHERE id=$1",
    )
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        0
    );
    expire(&pool, old).await;
    let (a, b) = tokio::join!(
        delete_once(&pool, cleanup_config(10)),
        delete_once(&pool, cleanup_config(10))
    );
    assert_eq!(
        a.unwrap().terminal_deliveries_deleted + b.unwrap().terminal_deliveries_deleted,
        1
    );
    let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM notification_deliveries")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(remaining.contains(&recent));
    assert!(remaining.contains(&active));
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn empty_operations_expire_under_same_policy_and_batch_limit(pool: sqlx::PgPool) {
    let fixture = fixture(&pool).await;
    enable_retention(&pool, &fixture).await;
    let repository = RecoveryRepository::new(pool.clone(), [7; 32]);
    for key in ["empty-operation-0001", "empty-operation-0002"] {
        repository
            .bulk_retry(
                fixture.organization_id,
                fixture.project_id,
                &BulkRetryFilter::default(),
                actor(&fixture),
                key,
            )
            .await
            .unwrap();
    }
    sqlx::query("UPDATE notification_recovery_operations SET completed_at=now()-interval '2 days'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(1))
            .await
            .unwrap()
            .recovery_operations_deleted,
        1
    );
    assert_eq!(
        delete_once(&pool, cleanup_config(1))
            .await
            .unwrap()
            .recovery_operations_deleted,
        1
    );
}

#[sqlx::test(migrator = "MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn retention_separates_tenant_windows_and_deletes_attempts(pool: sqlx::PgPool) {
    let short = fixture(&pool).await;
    let long = fixture(&pool).await;
    let disabled = fixture(&pool).await;
    for fixture in [&short, &long] {
        enable_retention(&pool, fixture).await;
    }
    sqlx::query("UPDATE projects SET notification_retention_enabled=true,notification_retention_days=30 WHERE id=$1")
        .bind(long.project_id).execute(&pool).await.unwrap();
    let retained = delivery(&pool, &long, "failed").await;
    let untouched = delivery(&pool, &disabled, "failed").await;
    expire(&pool, retained).await;
    expire(&pool, untouched).await;
    for status in ["succeeded", "failed", "suppressed", "cancelled"] {
        let id = delivery(&pool, &short, status).await;
        sqlx::query(
            "UPDATE notification_deliveries SET terminal_at=now()-interval '2 days' WHERE id=$1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO notification_delivery_attempts(id,organization_id,project_id,delivery_id,recovery_generation,attempt_number,started_at,finished_at,duration_ms,outcome,error_class) VALUES($1,$2,$3,$4,0,1,now(),now(),1,'failed','timeout')")
            .bind(Uuid::new_v4()).bind(short.organization_id).bind(short.project_id).bind(id)
            .execute(&pool).await.unwrap();
    }
    let stats = delete_once(&pool, cleanup_config(10)).await.unwrap();
    assert_eq!(stats.terminal_deliveries_deleted, 4);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_delivery_attempts")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    sqlx::query("UPDATE projects SET notification_retention_enabled=NULL,notification_retention_days=NULL WHERE id=$1")
        .bind(long.project_id).execute(&pool).await.unwrap();
    assert_eq!(
        delete_once(&pool, cleanup_config(10))
            .await
            .unwrap()
            .terminal_deliveries_deleted,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM notification_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap(),
        untouched
    );
}
