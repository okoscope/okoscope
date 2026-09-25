//! Releases of an application: recording them by hand, reading them and their
//! deployment episodes, and comparing the runtime behaviour of two releases.

use chrono::{DateTime, Utc};
use event_model::BaselineSelectionSource;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::IdentityPrincipal;
use crate::repository::transaction::TransactionRepository;
use crate::repository::{ApplicationRepository, ApplicationScope, ReleaseRepository};
use crate::runtime_retention::history::Coverage;
use crate::service::project_access::project_scope;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// Why a release use case failed.
#[derive(Debug, Error)]
pub enum ReleaseServiceError {
    /// The project, application or release does not exist, or the principal
    /// may not see it.
    #[error("release or application not found")]
    NotFound,
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// A release with this version already exists.
    #[error("release version already exists")]
    Conflict,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// The application a request names by its path.
#[derive(Clone, Copy, Debug)]
pub struct ApplicationPath {
    pub project_id: Uuid,
    pub application_id: Uuid,
}

/// A release recorded by hand.
#[derive(Clone, Debug)]
pub struct NewRelease {
    pub version: String,
    pub description: Option<String>,
    pub deployed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Release {
    pub id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub version: String,
    pub display_name: String,
    pub description: Option<String>,
    pub deployed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub identity_version: Option<i16>,
    pub identity_digest: Option<String>,
    pub identity_components: Option<sqlx::types::Json<Vec<ReleaseIdentityComponent>>>,
    pub revision_count: i64,
    pub active_episode_count: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReleaseIdentityComponent {
    pub name: String,
    pub image: String,
    pub category: String,
    #[serde(deserialize_with = "deserialize_component_digest")]
    pub digest: String,
}

fn deserialize_component_digest<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = <Vec<u8>>::deserialize(deserializer)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::invalid_length(
            bytes.len(),
            &"exactly 32 digest bytes",
        ));
    }
    Ok(hex::encode(bytes))
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct DeploymentEpisode {
    id: Uuid,
    release_id: Uuid,
    release_display_name: String,
    revision_id: Uuid,
    cluster_id: Uuid,
    occurrence_number: i64,
    state: String,
    transition_kind: String,
    first_observed_at: DateTime<Utc>,
    first_ready_at: Option<DateTime<Utc>>,
    last_observed_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    pod_count: i32,
    ready_pod_count: i32,
    workload_ready_pod_count: i32,
    ready_pod_share: Option<f64>,
    snapshot_observed_at: Option<DateTime<Utc>>,
    predecessors: Value,
}

#[derive(Debug, Serialize)]
pub struct EpisodeList {
    pub items: Vec<DeploymentEpisode>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ReleaseList {
    pub items: Vec<Release>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct DiffEntry {
    group_id: Uuid,
    classification: String,
    event_kind: String,
    semantic_summary: Value,
    baseline_occurrence_count: Option<i64>,
    baseline_first_seen_at: Option<DateTime<Utc>>,
    baseline_last_seen_at: Option<DateTime<Utc>>,
    target_occurrence_count: Option<i64>,
    target_first_seen_at: Option<DateTime<Utc>>,
    target_last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeDiff {
    coverage: Coverage,
    baseline: Option<Release>,
    target: Release,
    items: Vec<DiffEntry>,
    next_cursor: Option<Uuid>,
    baseline_selection_source: BaselineSelectionSource,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct DiffClassificationCount {
    classification: String,
    item_count: i64,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct DiffChangeEntry {
    group_id: Uuid,
    classification: String,
    event_kind: String,
    semantic_summary: Value,
    baseline_occurrence_count: i64,
    target_occurrence_count: i64,
    occurrence_delta: i64,
}

#[derive(Debug, Serialize)]
pub struct RuntimeDiffSummary {
    coverage: Coverage,
    baseline: Option<Release>,
    target: Release,
    total_item_count: i64,
    classifications: Vec<DiffClassificationCount>,
    largest_changes: Vec<DiffChangeEntry>,
    baseline_selection_source: BaselineSelectionSource,
}

/// Release use cases.
#[derive(Clone, Debug)]
pub struct ReleaseService {
    pool: PgPool,
}

impl ReleaseService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Records a release by hand. The version is trimmed and must be unique
    /// within the application.
    pub async fn create(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        input: NewRelease,
    ) -> Result<Release, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        if !self.application_owned(organization_id, path).await? {
            return Err(ReleaseServiceError::NotFound);
        }
        let version = input.version.trim();
        if version.is_empty() || version.len() > 200 {
            return Err(ReleaseServiceError::Invalid(
                "version must contain 1..=200 bytes after trimming".into(),
            ));
        }
        if input
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 2000)
        {
            return Err(ReleaseServiceError::Invalid(
                "description must not exceed 2000 bytes".into(),
            ));
        }
        let result = ReleaseRepository::create_manual::<_, Release>(
            &self.pool,
            Uuid::new_v4(),
            organization_id,
            path.project_id,
            path.application_id,
            version,
            input.description,
            input.deployed_at,
        )
        .await;
        match result {
            Ok(release) => Ok(release),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation) =>
            {
                Err(ReleaseServiceError::Conflict)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// A page of the application's releases, newest deployment first, after
    /// the cursor release when one is given.
    pub async fn list(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<ReleaseList, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        let limit = page_limit(limit)?;
        if !self.application_owned(organization_id, path).await? {
            return Err(ReleaseServiceError::NotFound);
        }
        let cursor = if let Some(id) = cursor {
            Some(
                ReleaseRepository::cursor(
                    &self.pool,
                    ApplicationScope {
                        organization_id,
                        project_id: path.project_id,
                        application_id: path.application_id,
                    },
                    id,
                )
                .await?
                .ok_or_else(|| {
                    ReleaseServiceError::Invalid("cursor does not exist in this scope".into())
                })?,
            )
        } else {
            None
        };
        let (cursor_time, cursor_id) = cursor.unzip();
        let mut items = ReleaseRepository::page::<_, Release>(
            &self.pool,
            organization_id,
            path.project_id,
            path.application_id,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
            items.pop();
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(ReleaseList { items, next_cursor })
    }

    /// One release of the application.
    pub async fn get(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        release_id: Uuid,
    ) -> Result<Release, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        self.fetch_release(organization_id, path, release_id)
            .await?
            .ok_or(ReleaseServiceError::NotFound)
    }

    /// A page of a release's deployment episodes.
    pub async fn episodes(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        release_id: Uuid,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<EpisodeList, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        self.fetch_release(organization_id, path, release_id)
            .await?
            .ok_or(ReleaseServiceError::NotFound)?;
        let limit = page_limit(limit)?;
        let mut items = ReleaseRepository::deployment_episode_page::<_, DeploymentEpisode>(
            &self.pool,
            organization_id,
            path.project_id,
            path.application_id,
            release_id,
            cursor,
            limit + 1,
        )
        .await?;
        let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
            items.pop();
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(EpisodeList { items, next_cursor })
    }

    /// A page of the runtime groups that differ between the target release
    /// and its baseline: the given one, else the release it replaced, else
    /// the previous deployment.
    pub async fn runtime_diff(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        target_id: Uuid,
        baseline_id: Option<Uuid>,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<RuntimeDiff, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        let limit = page_limit(limit)?;
        let (target, baseline, baseline_selection_source) = self
            .resolve_diff_releases(organization_id, path, target_id, baseline_id)
            .await?;
        let baseline_id = baseline.as_ref().map(|release| release.id);
        let mut items = ReleaseRepository::diff_page::<_, DiffEntry>(
            &self.pool,
            baseline_id,
            target.id,
            organization_id,
            path.project_id,
            path.application_id,
            cursor,
            limit + 1,
        )
        .await?;
        let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
            items.pop();
            items.last().map(|item| item.group_id)
        } else {
            None
        };
        Ok(RuntimeDiff {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                organization_id,
                path.project_id,
            )
            .await?,
            baseline,
            target,
            items,
            next_cursor,
            baseline_selection_source,
        })
    }

    /// Counts per classification and the largest changes between the target
    /// release and its baseline, read from one snapshot.
    pub async fn runtime_diff_summary(
        &self,
        principal: IdentityPrincipal,
        path: ApplicationPath,
        target_id: Uuid,
        baseline_id: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<RuntimeDiffSummary, ReleaseServiceError> {
        let organization_id = self
            .project_organization(principal, path.project_id)
            .await?;
        let limit = summary_limit(limit)?;
        let (target, baseline, baseline_selection_source) = self
            .resolve_diff_releases(organization_id, path, target_id, baseline_id)
            .await?;
        let Some(baseline_id) = baseline.as_ref().map(|release| release.id) else {
            return Ok(RuntimeDiffSummary {
                coverage: crate::runtime_retention::history::coverage(
                    &self.pool,
                    organization_id,
                    path.project_id,
                )
                .await?,
                baseline: None,
                target,
                total_item_count: 0,
                classifications: Vec::new(),
                largest_changes: Vec::new(),
                baseline_selection_source,
            });
        };
        let mut transaction = self.pool.begin().await?;
        TransactionRepository::begin_consistent_read(&mut *transaction).await?;
        let classifications =
            ReleaseRepository::diff_classifications::<_, DiffClassificationCount>(
                &mut *transaction,
                baseline_id,
                target.id,
                organization_id,
                path.project_id,
                path.application_id,
            )
            .await?;
        let largest_changes = ReleaseRepository::diff_largest_changes::<_, DiffChangeEntry>(
            &mut *transaction,
            baseline_id,
            target.id,
            organization_id,
            path.project_id,
            path.application_id,
            limit,
        )
        .await?;
        transaction.commit().await?;
        let total_item_count = classifications.iter().map(|row| row.item_count).sum();
        Ok(RuntimeDiffSummary {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                organization_id,
                path.project_id,
            )
            .await?,
            baseline,
            target,
            total_item_count,
            classifications,
            largest_changes,
            baseline_selection_source,
        })
    }

    /// The project's organization, when the project exists and the principal
    /// may access it.
    async fn project_organization(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<Uuid, ReleaseServiceError> {
        let scope = project_scope(&self.pool, principal, project_id)
            .await?
            .ok_or(ReleaseServiceError::NotFound)?;
        Ok(scope.organization_id)
    }

    async fn application_owned(
        &self,
        organization_id: Uuid,
        path: ApplicationPath,
    ) -> Result<bool, sqlx::Error> {
        ApplicationRepository::exists(
            &self.pool,
            organization_id,
            path.project_id,
            path.application_id,
        )
        .await
    }

    async fn fetch_release(
        &self,
        organization_id: Uuid,
        path: ApplicationPath,
        release_id: Uuid,
    ) -> Result<Option<Release>, sqlx::Error> {
        ReleaseRepository::get(
            &self.pool,
            organization_id,
            path.project_id,
            path.application_id,
            release_id,
        )
        .await
    }

    async fn resolve_diff_releases(
        &self,
        organization_id: Uuid,
        path: ApplicationPath,
        target_id: Uuid,
        baseline_id: Option<Uuid>,
    ) -> Result<(Release, Option<Release>, BaselineSelectionSource), ReleaseServiceError> {
        let target = self
            .fetch_release(organization_id, path, target_id)
            .await?
            .ok_or(ReleaseServiceError::NotFound)?;
        let (baseline, source) = if let Some(id) = baseline_id {
            (
                Some(
                    self.fetch_release(organization_id, path, id)
                        .await?
                        .ok_or(ReleaseServiceError::NotFound)?,
                ),
                BaselineSelectionSource::Explicit,
            )
        } else {
            let predecessors: Vec<Uuid> = ReleaseRepository::transition_predecessors(
                &self.pool,
                organization_id,
                path.project_id,
                path.application_id,
                target.id,
            )
            .await?;
            if let Some(id) = predecessors.first() {
                let source = if predecessors.len() == 1 {
                    BaselineSelectionSource::Transition
                } else {
                    BaselineSelectionSource::ConcurrentTransitionFallback
                };
                (
                    self.fetch_release(organization_id, path, *id).await?,
                    source,
                )
            } else {
                let legacy = ReleaseRepository::legacy_predecessor::<_, Release>(
                    &self.pool,
                    organization_id,
                    path.project_id,
                    path.application_id,
                    target.deployed_at,
                    target.id,
                )
                .await?;
                let source = if legacy.is_some() {
                    BaselineSelectionSource::LegacyDeploymentOrder
                } else {
                    BaselineSelectionSource::None
                };
                (legacy, source)
            }
        };
        Ok((target, baseline, source))
    }
}

fn page_limit(value: Option<i64>) -> Result<i64, ReleaseServiceError> {
    let value = value.unwrap_or(DEFAULT_LIMIT);
    if (1..=MAX_LIMIT).contains(&value) {
        Ok(value)
    } else {
        Err(ReleaseServiceError::Invalid(
            "limit must be between 1 and 200".into(),
        ))
    }
}

fn summary_limit(value: Option<i64>) -> Result<i64, ReleaseServiceError> {
    let value = value.unwrap_or(5);
    if (1..=10).contains(&value) {
        Ok(value)
    } else {
        Err(ReleaseServiceError::Invalid(
            "limit must be between 1 and 10".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_digest_serializes_as_fixed_width_lowercase_hex() {
        let mut bytes = vec![0_u8, 1, 10, 15];
        bytes.extend(std::iter::repeat_n(255, 28));
        let component: ReleaseIdentityComponent = serde_json::from_value(serde_json::json!({
            "name": "file-activity",
            "image": "busybox:1.37",
            "category": "application",
            "digest": bytes,
        }))
        .unwrap();

        let value = serde_json::to_value(component).unwrap();
        let digest = value["digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, format!("00010a0f{}", "ff".repeat(28)));
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn component_digest_rejects_non_sha256_byte_lengths() {
        let result = serde_json::from_value::<ReleaseIdentityComponent>(serde_json::json!({
            "name": "app",
            "image": "app:latest",
            "category": "application",
            "digest": [0, 1],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn diff_summary_limit_is_bounded() {
        assert_eq!(summary_limit(None).unwrap(), 5);
        for valid in [1, 5, 10] {
            assert_eq!(summary_limit(Some(valid)).unwrap(), valid);
        }
        for invalid in [0, 11] {
            assert!(summary_limit(Some(invalid)).is_err());
        }
    }

    mod use_cases {
        use chrono::{Duration, Utc};
        use sqlx::PgPool;
        use uuid::Uuid;

        use super::super::{ApplicationPath, NewRelease, ReleaseService, ReleaseServiceError};
        use crate::auth::{IdentityPrincipal, OrganizationRole};
        use crate::repository::test_support::{Tenant, manual_release, tenant};
        use event_model::BaselineSelectionSource;

        fn principal(organization_id: Uuid, role: OrganizationRole) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                active_organization_id: Some(organization_id),
                organization_role: Some(role),
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn owner(own: &Tenant) -> IdentityPrincipal {
            principal(own.organization_id, OrganizationRole::Owner)
        }

        fn path(own: &Tenant) -> ApplicationPath {
            ApplicationPath {
                project_id: own.project_id,
                application_id: own.application_id,
            }
        }

        fn new_release(version: &str) -> NewRelease {
            NewRelease {
                version: version.into(),
                description: None,
                deployed_at: Utc::now(),
            }
        }

        fn is_not_found<T>(result: &Result<T, ReleaseServiceError>) -> bool {
            matches!(result, Err(ReleaseServiceError::NotFound))
        }

        fn invalid_message<T>(result: Result<T, ReleaseServiceError>) -> Option<String> {
            match result {
                Err(ReleaseServiceError::Invalid(message)) => Some(message),
                _ => None,
            }
        }

        /// Access comes first: a principal of another organization, or an
        /// unknown project, gets not found even for a request that is also
        /// invalid.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn access_is_checked_before_anything_else(pool: PgPool) {
            let own = tenant(&pool, "release-service-access").await;
            let other = tenant(&pool, "release-service-access-other").await;
            let service = ReleaseService::new(pool.clone());
            let stranger = owner(&other);
            assert!(is_not_found(
                &service.create(stranger, path(&own), new_release("")).await
            ));
            assert!(is_not_found(
                &service.list(stranger, path(&own), None, Some(0)).await
            ));
            assert!(is_not_found(
                &service.get(stranger, path(&own), Uuid::new_v4()).await
            ));
            assert!(is_not_found(
                &service
                    .runtime_diff_summary(stranger, path(&own), Uuid::new_v4(), None, Some(99))
                    .await
            ));
            let unknown = ApplicationPath {
                project_id: Uuid::new_v4(),
                application_id: own.application_id,
            };
            assert!(is_not_found(
                &service.list(owner(&own), unknown, None, None).await
            ));
            let member = principal(own.organization_id, OrganizationRole::Member);
            assert!(
                is_not_found(&service.list(member, path(&own), None, None).await),
                "a member without project membership"
            );
        }

        /// Creating checks the application before the input, trims the
        /// version, and refuses a duplicate.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn create_validates_and_refuses_duplicates(pool: PgPool) {
            let own = tenant(&pool, "release-service-create").await;
            let service = ReleaseService::new(pool.clone());
            let missing_application = ApplicationPath {
                project_id: own.project_id,
                application_id: Uuid::new_v4(),
            };
            assert!(
                is_not_found(
                    &service
                        .create(owner(&own), missing_application, new_release(""))
                        .await
                ),
                "the application is checked before the version"
            );
            assert_eq!(
                invalid_message(
                    service
                        .create(owner(&own), path(&own), new_release("   "))
                        .await
                )
                .as_deref(),
                Some("version must contain 1..=200 bytes after trimming")
            );
            let long = NewRelease {
                description: Some("x".repeat(2001)),
                ..new_release("v1")
            };
            assert_eq!(
                invalid_message(service.create(owner(&own), path(&own), long).await).as_deref(),
                Some("description must not exceed 2000 bytes")
            );
            let created = service
                .create(owner(&own), path(&own), new_release("  v1  "))
                .await
                .unwrap();
            assert_eq!(created.version, "v1");
            assert!(matches!(
                service
                    .create(owner(&own), path(&own), new_release("v1"))
                    .await,
                Err(ReleaseServiceError::Conflict)
            ));
            let read = service
                .get(owner(&own), path(&own), created.id)
                .await
                .unwrap();
            assert_eq!(read.id, created.id);
        }

        /// Listing validates the limit before the application, pages newest
        /// first, and refuses a cursor from elsewhere.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn list_pages_and_validates(pool: PgPool) {
            let own = tenant(&pool, "release-service-list").await;
            let service = ReleaseService::new(pool.clone());
            let now = Utc::now();
            let oldest = manual_release(&pool, &own, "v1", now - Duration::hours(3)).await;
            let middle = manual_release(&pool, &own, "v2", now - Duration::hours(2)).await;
            let newest = manual_release(&pool, &own, "v3", now - Duration::hours(1)).await;
            let missing_application = ApplicationPath {
                project_id: own.project_id,
                application_id: Uuid::new_v4(),
            };
            assert_eq!(
                invalid_message(
                    service
                        .list(owner(&own), missing_application, None, Some(0))
                        .await
                )
                .as_deref(),
                Some("limit must be between 1 and 200"),
                "the limit is checked before the application"
            );
            let first = service
                .list(owner(&own), path(&own), None, Some(2))
                .await
                .unwrap();
            assert_eq!(
                first.items.iter().map(|r| r.id).collect::<Vec<_>>(),
                [newest, middle]
            );
            assert_eq!(first.next_cursor, Some(middle));
            let rest = service
                .list(owner(&own), path(&own), first.next_cursor, Some(2))
                .await
                .unwrap();
            assert_eq!(
                rest.items.iter().map(|r| r.id).collect::<Vec<_>>(),
                [oldest]
            );
            assert_eq!(rest.next_cursor, None);
            assert_eq!(
                invalid_message(
                    service
                        .list(owner(&own), path(&own), Some(Uuid::new_v4()), None)
                        .await
                )
                .as_deref(),
                Some("cursor does not exist in this scope")
            );
        }

        /// Episodes check the release before the limit; an unknown release is
        /// not found.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn episodes_check_the_release_first(pool: PgPool) {
            let own = tenant(&pool, "release-service-episodes").await;
            let service = ReleaseService::new(pool.clone());
            let release = manual_release(&pool, &own, "v1", Utc::now()).await;
            assert!(is_not_found(
                &service
                    .episodes(owner(&own), path(&own), Uuid::new_v4(), None, Some(0))
                    .await
            ));
            assert!(
                invalid_message(
                    service
                        .episodes(owner(&own), path(&own), release, None, Some(0))
                        .await
                )
                .is_some()
            );
            let episodes = service
                .episodes(owner(&own), path(&own), release, None, None)
                .await
                .unwrap();
            assert!(episodes.items.is_empty() && episodes.next_cursor.is_none());
        }

        /// The diff baseline is the explicit one, else the previous
        /// deployment; the summary without a baseline is empty, and its limit
        /// is bounded.
        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn diffs_select_their_baseline(pool: PgPool) {
            let own = tenant(&pool, "release-service-diff").await;
            let service = ReleaseService::new(pool.clone());
            let now = Utc::now();
            let first = manual_release(&pool, &own, "v1", now - Duration::hours(2)).await;
            let second = manual_release(&pool, &own, "v2", now - Duration::hours(1)).await;

            let legacy = service
                .runtime_diff(owner(&own), path(&own), second, None, None, None)
                .await
                .unwrap();
            assert_eq!(legacy.baseline.as_ref().map(|r| r.id), Some(first));
            assert_eq!(
                legacy.baseline_selection_source,
                BaselineSelectionSource::LegacyDeploymentOrder
            );
            let explicit = service
                .runtime_diff(owner(&own), path(&own), first, Some(second), None, None)
                .await
                .unwrap();
            assert_eq!(
                explicit.baseline_selection_source,
                BaselineSelectionSource::Explicit
            );
            assert!(is_not_found(
                &service
                    .runtime_diff(
                        owner(&own),
                        path(&own),
                        second,
                        Some(Uuid::new_v4()),
                        None,
                        None
                    )
                    .await
            ));

            let alone = service
                .runtime_diff_summary(owner(&own), path(&own), first, None, None)
                .await
                .unwrap();
            assert_eq!(
                alone.baseline_selection_source,
                BaselineSelectionSource::None
            );
            assert_eq!(alone.total_item_count, 0);
            assert!(alone.classifications.is_empty() && alone.largest_changes.is_empty());
            let compared = service
                .runtime_diff_summary(owner(&own), path(&own), second, None, Some(10))
                .await
                .unwrap();
            assert_eq!(compared.baseline.map(|r| r.id), Some(first));
            assert_eq!(
                invalid_message(
                    service
                        .runtime_diff_summary(owner(&own), path(&own), second, None, Some(11))
                        .await
                )
                .as_deref(),
                Some("limit must be between 1 and 10")
            );
        }
    }
}
