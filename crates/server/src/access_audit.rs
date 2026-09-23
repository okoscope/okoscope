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
    sqlx::query("INSERT INTO access_audit_records(id,actor_kind,actor_user_id,action,organization_id,project_id,target_user_id,invitation_id,previous_role,new_role,outcome,request_id,retain_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'succeeded',$11,now()+interval '365 days')")
        .bind(Uuid::new_v4()).bind(actor_kind).bind(actor_user_id).bind(event.action)
        .bind(event.organization_id).bind(event.project_id).bind(event.target_user_id)
        .bind(event.invitation_id).bind(event.previous_role).bind(event.new_role)
        .bind(event.request_id).execute(&mut **tx).await?;
    Ok(())
}
