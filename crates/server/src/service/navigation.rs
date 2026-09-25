//! Navigation for a signed-in member of an organization: the organization,
//! the projects and applications they can see with their role in each, and
//! the agents that observed an application.
//!
//! The query types below are also the request's query strings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::access_control::ProjectRole;
use crate::auth::UserPrincipal;
use crate::repository::ApplicationRepository;
use crate::repository::navigation::NavigationRepository;
use crate::service::project_access::member_project_role;

/// Why a navigation read failed.
#[derive(Debug, Error)]
pub enum NavigationServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The resource does not exist, or the principal may not see it.
    #[error("resource not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl NavigationServiceError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

fn page_limit(limit: Option<i64>) -> Result<i64, NavigationServiceError> {
    let limit = limit.unwrap_or(50);
    if (1..=200).contains(&limit) {
        Ok(limit)
    } else {
        Err(NavigationServiceError::invalid(
            "limit must be between 1 and 200",
        ))
    }
}

#[derive(Debug, FromRow, Serialize)]
pub struct Organization {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct ProjectSummary {
    id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    application_count: i64,
    runtime_group_count: i64,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<&'static str>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

#[derive(Debug, FromRow, Serialize)]
pub struct ApplicationSummary {
    id: Uuid,
    project_id: Uuid,
    slug: String,
    name: String,
    created_at: DateTime<Utc>,
    release_count: i64,
    runtime_group_count: i64,
    latest_observed_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    effective_project_role: Option<ProjectRole>,
    #[sqlx(skip)]
    effective_access_source: Option<&'static str>,
    #[sqlx(skip)]
    capabilities: serde_json::Value,
}

fn scoped_capabilities(role: ProjectRole, organization_admin: bool) -> serde_json::Value {
    let project_admin = role == ProjectRole::Admin;
    serde_json::json!({
        "manage_platform": false,
        "manage_organization": organization_admin,
        "create_project": organization_admin,
        "manage_project_members": project_admin,
        "create_application": project_admin,
        "manage_credentials": project_admin,
        "organization_roles_grantable": if organization_admin { vec!["owner", "admin", "member"] } else { Vec::<&str>::new() },
        "project_roles_grantable": if organization_admin { vec!["admin", "member"] } else if project_admin { vec!["member"] } else { Vec::<&str>::new() },
    })
}

fn apply_project_access(
    item: &mut ProjectSummary,
    role: ProjectRole,
    source: &'static str,
    organization_admin: bool,
) {
    item.effective_project_role = Some(role);
    item.effective_access_source = Some(source);
    item.capabilities = scoped_capabilities(role, organization_admin);
}

fn apply_application_access(
    item: &mut ApplicationSummary,
    role: ProjectRole,
    source: &'static str,
    organization_admin: bool,
) {
    item.effective_project_role = Some(role);
    item.effective_access_source = Some(source);
    item.capabilities = scoped_capabilities(role, organization_admin);
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct WorkerPageQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkerCursor {
    last_observed_at: DateTime<Utc>,
    agent_id: Uuid,
}

#[derive(Debug, FromRow, Serialize)]
struct ApplicationWorker {
    agent_id: Uuid,
    cluster_id: Uuid,
    cluster_name: String,
    node_name: String,
    agent_version: String,
    architecture: Option<String>,
    kernel_release: Option<String>,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    agent_last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WorkerPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<ApplicationWorker>,
    next_cursor: Option<String>,
}

fn encode_worker_cursor(cursor: &WorkerCursor) -> Result<String, &'static str> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| "cursor cannot be encoded")
}

fn decode_worker_cursor(cursor: &str) -> Result<WorkerCursor, &'static str> {
    if cursor.len() > 1024 {
        return Err("cursor is invalid");
    }
    let bytes = hex::decode(cursor).map_err(|_| "cursor is invalid")?;
    serde_json::from_slice(&bytes).map_err(|_| "cursor is invalid")
}

async fn ensure_project(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<bool, sqlx::Error> {
    crate::repository::ProjectRepository::exists_in(pool, organization_id, project_id).await
}

async fn cursor_position(
    pool: &PgPool,
    table: &str,
    organization_id: Uuid,
    project_id: Option<Uuid>,
    cursor: Option<Uuid>,
) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if table == "projects" {
        NavigationRepository::project_cursor(pool, organization_id, cursor).await
    } else {
        NavigationRepository::application_cursor(pool, organization_id, project_id, cursor).await
    }
}

fn page<T>(items: &mut Vec<T>, limit: i64, id: impl Fn(&T) -> Uuid) -> Page<T> {
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(id)
    } else {
        None
    };
    Page {
        items: std::mem::take(items),
        next_cursor,
    }
}

/// Reads what a member can navigate to.
#[derive(Clone, Debug)]
pub struct NavigationService {
    pool: PgPool,
}

impl NavigationService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The principal's active organization.
    pub async fn organization(
        &self,
        principal: UserPrincipal,
    ) -> Result<Organization, NavigationServiceError> {
        let value = NavigationRepository::organization(&self.pool, principal.organization_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .ok_or(NavigationServiceError::NotFound)?;
        Ok(value)
    }

    /// The organization's projects the principal can see, each with the
    /// principal's role and capabilities in it.
    pub async fn projects(
        &self,
        principal: UserPrincipal,
        query: PageQuery,
    ) -> Result<Page<ProjectSummary>, NavigationServiceError> {
        let limit = page_limit(query.limit)?;
        let cursor = cursor_position(
            &self.pool,
            "projects",
            principal.organization_id,
            None,
            query.cursor,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        if query.cursor.is_some() && cursor.is_none() {
            return Err(NavigationServiceError::invalid(
                "cursor is outside this scope",
            ));
        }
        let (cursor_time, cursor_id) = cursor.unzip();
        let mut items = NavigationRepository::project_page::<_, ProjectSummary>(
            &self.pool,
            principal.organization_id,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        let organization_admin = principal.role.inherits_project_access();
        let mut visible = Vec::with_capacity(items.len());
        for mut item in items.drain(..) {
            if let Some((role, source)) = member_project_role(&self.pool, principal, item.id)
                .await
                .map_err(NavigationServiceError::Database)?
            {
                apply_project_access(&mut item, role, source, organization_admin);
                visible.push(item);
            }
        }
        items = visible;
        Ok(page(&mut items, limit, |item| item.id))
    }

    /// One project the principal can see.
    pub async fn project(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectSummary, NavigationServiceError> {
        let mut item = NavigationRepository::project::<_, ProjectSummary>(
            &self.pool,
            principal.organization_id,
            project_id,
        )
        .await
        .map_err(NavigationServiceError::Database)?
        .ok_or(NavigationServiceError::NotFound)?;
        let (role, source) = member_project_role(&self.pool, principal, project_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .ok_or(NavigationServiceError::NotFound)?;
        apply_project_access(
            &mut item,
            role,
            source,
            principal.role.inherits_project_access(),
        );
        Ok(item)
    }

    /// A visible project's applications.
    pub async fn applications(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        query: PageQuery,
    ) -> Result<Page<ApplicationSummary>, NavigationServiceError> {
        let (access_role, access_source) = member_project_role(&self.pool, principal, project_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .ok_or(NavigationServiceError::NotFound)?;
        ensure_project(&self.pool, principal.organization_id, project_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .then_some(())
            .ok_or(NavigationServiceError::NotFound)?;
        let limit = page_limit(query.limit)?;
        let cursor = cursor_position(
            &self.pool,
            "applications",
            principal.organization_id,
            Some(project_id),
            query.cursor,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        if query.cursor.is_some() && cursor.is_none() {
            return Err(NavigationServiceError::invalid(
                "cursor is outside this scope",
            ));
        }
        let (cursor_time, cursor_id) = cursor.unzip();
        let mut items = NavigationRepository::application_page::<_, ApplicationSummary>(
            &self.pool,
            principal.organization_id,
            project_id,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        for item in &mut items {
            apply_application_access(
                item,
                access_role,
                access_source,
                principal.role.inherits_project_access(),
            );
        }
        Ok(page(&mut items, limit, |item| item.id))
    }

    /// One application of a visible project.
    pub async fn application(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<ApplicationSummary, NavigationServiceError> {
        let (access_role, access_source) = member_project_role(&self.pool, principal, project_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .ok_or(NavigationServiceError::NotFound)?;
        let mut item = NavigationRepository::application::<_, ApplicationSummary>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await
        .map_err(NavigationServiceError::Database)?
        .ok_or(NavigationServiceError::NotFound)?;
        apply_application_access(
            &mut item,
            access_role,
            access_source,
            principal.role.inherits_project_access(),
        );
        Ok(item)
    }

    /// The agents that observed the application, most recently first. Like the
    /// project's other reads, it needs access to the project.
    pub async fn application_workers(
        &self,
        principal: UserPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: WorkerPageQuery,
    ) -> Result<WorkerPage, NavigationServiceError> {
        member_project_role(&self.pool, principal, project_id)
            .await
            .map_err(NavigationServiceError::Database)?
            .ok_or(NavigationServiceError::NotFound)?;
        let owned = ApplicationRepository::exists(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        if !owned {
            return Err(NavigationServiceError::NotFound);
        }
        let limit = page_limit(query.limit)?;
        let cursor = query
            .cursor
            .as_deref()
            .map(decode_worker_cursor)
            .transpose()
            .map_err(NavigationServiceError::invalid)?;
        if let Some(cursor) = &cursor {
            let valid: bool = NavigationRepository::worker_cursor_is_valid(
                &self.pool,
                principal.organization_id,
                project_id,
                application_id,
                cursor.agent_id,
                cursor.last_observed_at,
            )
            .await
            .map_err(NavigationServiceError::Database)?;
            if !valid {
                return Err(NavigationServiceError::invalid(
                    "cursor is outside this scope",
                ));
            }
        }
        let cursor_time = cursor.as_ref().map(|value| value.last_observed_at);
        let cursor_agent = cursor.as_ref().map(|value| value.agent_id);
        let mut items = NavigationRepository::worker_page::<_, ApplicationWorker>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            cursor_time,
            cursor_agent,
            limit + 1,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items
                .last()
                .map(|item| {
                    encode_worker_cursor(&WorkerCursor {
                        last_observed_at: item.last_observed_at,
                        agent_id: item.agent_id,
                    })
                })
                .transpose()
                .map_err(NavigationServiceError::invalid)?
        } else {
            None
        };
        let coverage = crate::runtime_retention::history::coverage(
            &self.pool,
            principal.organization_id,
            project_id,
        )
        .await
        .map_err(NavigationServiceError::Database)?;
        Ok(WorkerPage {
            coverage,
            items,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::OrganizationRole;
    use crate::repository::MembershipRepository;
    use crate::repository::test_support::{Tenant, exec, ingest, tenant, user};

    fn member(tenant: &Tenant, user_id: Uuid, role: OrganizationRole) -> UserPrincipal {
        UserPrincipal {
            user_id,
            session_id: Uuid::new_v4(),
            organization_id: tenant.organization_id,
            role,
        }
    }

    fn page() -> PageQuery {
        PageQuery {
            cursor: None,
            limit: None,
        }
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn members_see_only_the_projects_they_hold_a_role_in(pool: PgPool) {
        let tenant = tenant(&pool, "navigation-service-projects").await;
        let service = NavigationService::new(pool.clone());
        let owner = member(&tenant, Uuid::new_v4(), OrganizationRole::Owner);

        let organization = service.organization(owner).await.unwrap();
        assert_eq!(organization.slug, "navigation-service-projects");
        let projects = service.projects(owner, page()).await.unwrap();
        assert_eq!(projects.items.len(), 1);
        assert_eq!(
            projects.items[0].effective_access_source,
            Some("organization")
        );
        assert_eq!(
            projects.items[0].effective_project_role,
            Some(ProjectRole::Admin)
        );

        let user_id = user(&pool).await;
        MembershipRepository::insert_organization_role(
            &pool,
            tenant.organization_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let plain = member(&tenant, user_id, OrganizationRole::Member);
        assert!(
            service
                .projects(plain, page())
                .await
                .unwrap()
                .items
                .is_empty()
        );
        assert!(matches!(
            service.project(plain, tenant.project_id).await,
            Err(NavigationServiceError::NotFound)
        ));
        assert!(matches!(
            service.applications(plain, tenant.project_id, page()).await,
            Err(NavigationServiceError::NotFound)
        ));
        MembershipRepository::insert_project_role(
            &pool,
            tenant.organization_id,
            tenant.project_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let project = service.project(plain, tenant.project_id).await.unwrap();
        assert_eq!(project.effective_access_source, Some("project"));
        assert_eq!(project.effective_project_role, Some(ProjectRole::Member));
        let application = service
            .application(plain, tenant.project_id, tenant.application_id)
            .await
            .unwrap();
        assert_eq!(application.slug, "app");
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn pages_validate_limits_and_cursors(pool: PgPool) {
        let tenant = tenant(&pool, "navigation-service-pages").await;
        ingest(
            &pool,
            &tenant,
            &[exec(
                &tenant,
                "/bin/a",
                Utc::now() - chrono::Duration::minutes(1),
            )],
        )
        .await;
        let service = NavigationService::new(pool.clone());
        let owner = member(&tenant, Uuid::new_v4(), OrganizationRole::Owner);

        assert!(matches!(
            service
                .projects(
                    owner,
                    PageQuery {
                        cursor: None,
                        limit: Some(201),
                    },
                )
                .await,
            Err(NavigationServiceError::Invalid(message)) if message == "limit must be between 1 and 200"
        ));
        assert!(matches!(
            service
                .applications(
                    owner,
                    tenant.project_id,
                    PageQuery {
                        cursor: Some(Uuid::new_v4()),
                        limit: None,
                    },
                )
                .await,
            Err(NavigationServiceError::Invalid(message)) if message == "cursor is outside this scope"
        ));
        let applications = service
            .applications(owner, tenant.project_id, page())
            .await
            .unwrap();
        assert_eq!(applications.items.len(), 1);

        let workers = service
            .application_workers(
                owner,
                tenant.project_id,
                tenant.application_id,
                WorkerPageQuery {
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(workers.items.len(), 1);
        assert_eq!(workers.items[0].agent_id, tenant.agent_id);
        assert!(matches!(
            service
                .application_workers(
                    owner,
                    tenant.project_id,
                    tenant.application_id,
                    WorkerPageQuery {
                        cursor: Some("zz".into()),
                        limit: None,
                    },
                )
                .await,
            Err(NavigationServiceError::Invalid(message)) if message == "cursor is invalid"
        ));
        assert!(matches!(
            service
                .application_workers(
                    owner,
                    tenant.project_id,
                    Uuid::new_v4(),
                    WorkerPageQuery {
                        cursor: None,
                        limit: Some(0),
                    },
                )
                .await,
            Err(NavigationServiceError::NotFound)
        ));
    }

    /// Workers belong to an application of a project; a member who cannot
    /// see the project cannot see its workers either, as with the project's
    /// other reads.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn workers_need_access_to_the_project(pool: PgPool) {
        let tenant = tenant(&pool, "navigation-service-workers").await;
        ingest(
            &pool,
            &tenant,
            &[exec(
                &tenant,
                "/bin/a",
                Utc::now() - chrono::Duration::minutes(1),
            )],
        )
        .await;
        let service = NavigationService::new(pool.clone());
        let user_id = user(&pool).await;
        MembershipRepository::insert_organization_role(
            &pool,
            tenant.organization_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let plain = member(&tenant, user_id, OrganizationRole::Member);
        let workers = || WorkerPageQuery {
            cursor: None,
            limit: None,
        };

        assert!(matches!(
            service
                .application_workers(plain, tenant.project_id, tenant.application_id, workers())
                .await,
            Err(NavigationServiceError::NotFound)
        ));
        MembershipRepository::insert_project_role(
            &pool,
            tenant.organization_id,
            tenant.project_id,
            user_id,
            "member",
        )
        .await
        .unwrap();
        let page = service
            .application_workers(plain, tenant.project_id, tenant.application_id, workers())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
    }
}
