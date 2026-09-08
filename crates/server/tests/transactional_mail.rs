use std::sync::Arc;

use chrono::{Duration, Utc};
use server::transactional_mail::{
    CapturingSender, Locale, MailConfig, MailService, TemplateData, enqueue, process_once,
};

fn config() -> MailConfig {
    MailConfig {
        enabled: true,
        public_web_url: url::Url::parse("https://ui.example.com").unwrap(),
        encryption_key: [7; 32],
        ..MailConfig::default()
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn encrypted_outbox_is_atomic_captured_and_erased(pool: sqlx::PgPool) {
    let config = config();
    let mut rolled_back = pool.begin().await.unwrap();
    enqueue(
        &mut rolled_back,
        &config,
        "rolled-back",
        &[("owner@example.com".into(), Locale::En)],
        &TemplateData::ResetPassword {
            action_url: "https://ui.example.com/reset-password#token=secret".into(),
            expires_minutes: 30,
        },
        None,
        Some(Utc::now() + Duration::minutes(30)),
    )
    .await
    .unwrap();
    rolled_back.rollback().await.unwrap();
    assert_eq!(outbox_count(&pool).await, 0);

    let mut tx = pool.begin().await.unwrap();
    enqueue(
        &mut tx,
        &config,
        "committed",
        &[("Owner@Example.com".into(), Locale::En)],
        &TemplateData::ResetPassword {
            action_url: "https://ui.example.com/reset-password#token=secret".into(),
            expires_minutes: 30,
        },
        None,
        Some(Utc::now() + Duration::minutes(30)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT payload_ciphertext FROM transactional_mail_outbox")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("secret"));

    let sender = Arc::new(CapturingSender::default());
    let service = MailService::with_sender(pool.clone(), config, sender.clone());
    process_once(&service).await.unwrap();
    let messages = sender.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].recipient, "owner@example.com");
    assert!(messages[0].text.contains("#token=secret"));
    let erased: bool = sqlx::query_scalar("SELECT payload_ciphertext IS NULL AND delivered_at IS NOT NULL FROM transactional_mail_outbox")
        .fetch_one(&pool).await.unwrap();
    assert!(erased);
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn concurrent_workers_claim_once_and_expired_actions_are_suppressed(pool: sqlx::PgPool) {
    let config = config();
    let mut tx = pool.begin().await.unwrap();
    enqueue(
        &mut tx,
        &config,
        "concurrent",
        &[("owner@example.com".into(), Locale::Ru)],
        &TemplateData::PasswordChanged,
        None,
        None,
    )
    .await
    .unwrap();
    enqueue(
        &mut tx,
        &config,
        "expired",
        &[("expired@example.com".into(), Locale::En)],
        &TemplateData::ResetPassword {
            action_url: String::new(),
            expires_minutes: 1,
        },
        None,
        Some(Utc::now() + Duration::seconds(1)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE transactional_mail_outbox \
         SET created_at=now()-interval '2 seconds', expires_at=now()-interval '1 second' \
         WHERE logical_key='expired'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let sender = Arc::new(CapturingSender::default());
    let first = MailService::with_sender(pool.clone(), config.clone(), sender.clone());
    let second = MailService::with_sender(pool.clone(), config, sender.clone());
    let (left, right) = tokio::join!(process_once(&first), process_once(&second));
    left.unwrap();
    right.unwrap();
    assert_eq!(sender.messages().len(), 1);
    let expired_reason: String = sqlx::query_scalar(
        "SELECT terminal_reason FROM transactional_mail_outbox WHERE logical_key='expired'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(expired_reason, "action_expired");
}

async fn outbox_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM transactional_mail_outbox")
        .fetch_one(pool)
        .await
        .unwrap()
}
