//! The access audit: an append-only record of access control changes, kept
//! for a year.
//!
//! The audit endpoints own the record projection, so reads are generic over
//! the row type.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Access audit records.
#[derive(Clone, Copy, Debug)]
pub struct AccessAuditRepository;

impl AccessAuditRepository {
    /// A page of access audit records by id, within one organization when
    /// given, after the cursor when one is given.
    ///
    /// Selects every column but `retain_until`.
    pub async fn page<'e, E, T>(
        executor: E,
        organization_id: Option<Uuid>,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,actor_kind,actor_user_id,action,organization_id,project_id,target_user_id,invitation_id,previous_role,new_role,outcome,request_id,created_at FROM access_audit_records WHERE ($1::uuid IS NULL OR organization_id=$1) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3")
            .bind(organization_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::AccessAuditRepository;
    use crate::access_audit::{AccessAuditActor, AccessAuditEvent, write_access_audit};
    use crate::repository::test_support::{tenant, user};

    #[derive(Debug, FromRow)]
    struct Record {
        id: Uuid,
        actor_kind: String,
        action: String,
        organization_id: Option<Uuid>,
        outcome: String,
    }

    /// The audit pages by id after a cursor, within one organization when
    /// asked.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_audit_pages_by_id(pool: PgPool) {
        let own = tenant(&pool, "audit-page").await;
        let actor = user(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        for (organization_id, action) in [
            (
                Some(own.organization_id),
                "organization_member.role_changed",
            ),
            (None, "platform_role.granted"),
            (Some(own.organization_id), "organization_member.removed"),
        ] {
            write_access_audit(
                &mut tx,
                AccessAuditEvent {
                    actor: AccessAuditActor::User(actor),
                    action,
                    organization_id,
                    project_id: None,
                    target_user_id: None,
                    invitation_id: None,
                    previous_role: None,
                    new_role: None,
                    request_id: None,
                },
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();

        let all: Vec<Record> = AccessAuditRepository::page(&pool, None, None, 10)
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.windows(2).all(|w| w[0].id < w[1].id));
        assert!(
            all.iter()
                .all(|r| r.actor_kind == "user" && r.outcome == "succeeded")
        );
        let after: Vec<Record> = AccessAuditRepository::page(&pool, None, Some(all[0].id), 10)
            .await
            .unwrap();
        assert_eq!(
            after.iter().map(|r| r.id).collect::<Vec<_>>(),
            [all[1].id, all[2].id]
        );
        let scoped: Vec<Record> =
            AccessAuditRepository::page(&pool, Some(own.organization_id), None, 10)
                .await
                .unwrap();
        let mut actions: Vec<&str> = scoped.iter().map(|r| r.action.as_str()).collect();
        actions.sort_unstable();
        assert_eq!(
            actions,
            [
                "organization_member.removed",
                "organization_member.role_changed"
            ]
        );
        assert!(
            scoped
                .iter()
                .all(|r| r.organization_id == Some(own.organization_id))
        );
    }
}
