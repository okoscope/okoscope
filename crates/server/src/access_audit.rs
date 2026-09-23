use crate::repository::access_audit::AccessAuditRepository;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub enum AccessAuditActor {
    User(Uuid),
    SystemRecovery,
}

#[derive(Clone, Copy, Debug)]
pub struct AccessAuditEvent<'a> {
    pub actor: AccessAuditActor,
    pub action: &'a str,
    pub organization_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub invitation_id: Option<Uuid>,
    pub previous_role: Option<&'a str>,
    pub new_role: Option<&'a str>,
    pub request_id: Option<&'a str>,
}

pub async fn write_access_audit(
    tx: &mut Transaction<'_, Postgres>,
    event: AccessAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    let (actor_kind, actor_user_id) = match event.actor {
        AccessAuditActor::User(user_id) => ("user", Some(user_id)),
        AccessAuditActor::SystemRecovery => ("system_recovery", None),
    };
    AccessAuditRepository::insert(
        &mut **tx,
        Uuid::new_v4(),
        actor_kind,
        actor_user_id,
        event.action,
        event.organization_id,
        event.project_id,
        event.target_user_id,
        event.invitation_id,
        event.previous_role,
        event.new_role,
        event.request_id,
    )
    .await?;
    Ok(())
}
