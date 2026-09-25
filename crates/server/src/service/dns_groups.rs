//! The logical DNS groups of an application: the names its processes
//! resolved, grouped by domain and process, with their variants.
//!
//! The query types below are also the request's query strings, and the scope
//! is fingerprinted into cursors, so their fields are part of the API.

use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::IdentityPrincipal;
use crate::repository::ApplicationRepository;
use crate::repository::dns_groups::{DnsGroupFilter, DnsGroupRepository};
use crate::service::project_access::project_scope;

/// Why a DNS group use case failed.
#[derive(Debug, Error)]
pub enum DnsGroupServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The project, application or group does not exist, or the principal
    /// may not see it.
    #[error("logical DNS group not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

type HmacSha256 = Hmac<Sha256>;
const TOKEN_MAX_LENGTH: usize = 4_096;

#[derive(Clone, Debug)]
struct GroupTokenCodec {
    key: Arc<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GroupTokenPayload {
    format_version: u8,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    process_command: String,
    display_name: String,
}

impl GroupTokenCodec {
    fn process_default() -> Self {
        static KEY: OnceLock<[u8; 32]> = OnceLock::new();
        let key = KEY.get_or_init(|| {
            std::env::var("OKOSCOPE_IDENTITY_TOKEN_KEY").map_or_else(
                |_| rand::random(),
                |value| {
                    assert!(
                        value.len() >= 32,
                        "OKOSCOPE_IDENTITY_TOKEN_KEY must contain at least 32 bytes"
                    );
                    Sha256::digest(value).into()
                },
            )
        });
        Self {
            key: Arc::new(*key),
        }
    }

    fn encode<T: Serialize>(&self, value: &T) -> Result<String, DnsGroupServiceError> {
        let encoded = hex::encode(
            serde_json::to_vec(value)
                .map_err(|_| DnsGroupServiceError::Invalid("token cannot be encoded".into()))?,
        );
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| DnsGroupServiceError::Invalid("token cannot be encoded".into()))?;
        mac.update(encoded.as_bytes());
        Ok(format!(
            "{encoded}.{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T, DnsGroupServiceError> {
        if token.is_empty() || token.len() > TOKEN_MAX_LENGTH {
            return Err(DnsGroupServiceError::Invalid("token is invalid".into()));
        }
        let (encoded, signature) = token
            .split_once('.')
            .ok_or_else(|| DnsGroupServiceError::Invalid("token is invalid".into()))?;
        let signature = hex::decode(signature)
            .map_err(|_| DnsGroupServiceError::Invalid("token is invalid".into()))?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| DnsGroupServiceError::Invalid("token is invalid".into()))?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| DnsGroupServiceError::Invalid("token is invalid".into()))?;
        let bytes = hex::decode(encoded)
            .map_err(|_| DnsGroupServiceError::Invalid("token is invalid".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| DnsGroupServiceError::Invalid("token is invalid".into()))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DnsGroupScope {
    release_id: Option<Uuid>,
    cluster_id: Option<Uuid>,
    namespace: Option<String>,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    container_name: Option<String>,
    observed_from: Option<DateTime<Utc>>,
    observed_to: Option<DateTime<Utc>>,
    search: Option<String>,
    verdict: Option<String>,
    suppressed: Option<bool>,
    evaluation_pending: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct GroupQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct DistributionQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct VariantQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GroupCursor {
    scope: String,
    last_seen_at: DateTime<Utc>,
    display_name: String,
    process_command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct VariantCursor {
    item_id: Uuid,
}

#[derive(Debug, FromRow)]
struct GroupRow {
    display_name: String,
    process_command: String,
    grouping_reason: String,
    confidence: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
    variant_count: i64,
    query_types: Vec<String>,
    release_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    pod_count: i64,
    container_count: i64,
    total_group_count: i64,
    total_observation_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DnsGroup {
    group_token: String,
    display_name: String,
    process_command: String,
    grouping_reason: String,
    confidence: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
    variant_count: i64,
    query_types: Vec<String>,
    release_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    pod_count: i64,
    container_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GroupPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<DnsGroup>,
    next_cursor: Option<String>,
    total_group_count: i64,
    total_observation_count: i64,
}

#[derive(Debug, FromRow, Serialize)]
pub struct VariantRow {
    item_id: Uuid,
    name: String,
    query_type: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
}

#[derive(Debug, Serialize)]
pub struct VariantPage {
    items: Vec<VariantRow>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DistributionEntry {
    group: DnsGroup,
}

#[derive(Debug, Serialize)]
pub struct DistributionOther {
    group_count: i64,
    observation_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DnsDistribution {
    coverage: crate::runtime_retention::history::Coverage,
    total_group_count: i64,
    total_observation_count: i64,
    entries: Vec<DistributionEntry>,
    other: Option<DistributionOther>,
}

#[derive(Clone, Copy)]
struct Principal {
    organization_id: Uuid,
}

impl DnsGroupScope {
    /// The repository filter for this scope within a tenant path.
    fn filter(
        &self,
        principal: Principal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> DnsGroupFilter<'_> {
        DnsGroupFilter {
            organization_id: principal.organization_id,
            project_id,
            application_id,
            release_id: self.release_id,
            cluster_id: self.cluster_id,
            namespace: self.namespace.as_deref(),
            workload_kind: self.workload_kind.as_deref(),
            workload_name: self.workload_name.as_deref(),
            container_name: self.container_name.as_deref(),
            observed_from: self.observed_from,
            observed_to: self.observed_to,
            verdict: self.verdict.as_deref(),
            suppressed: self.suppressed,
            evaluation_pending: self.evaluation_pending,
        }
    }

    fn normalize(mut self) -> Result<Self, DnsGroupServiceError> {
        for text in [
            &mut self.namespace,
            &mut self.workload_kind,
            &mut self.workload_name,
            &mut self.container_name,
            &mut self.search,
        ]
        .into_iter()
        .flatten()
        {
            *text = text.trim().to_owned();
            if text.is_empty() {
                return Err(DnsGroupServiceError::Invalid(
                    "filter values cannot be empty".into(),
                ));
            }
        }
        if self
            .search
            .as_ref()
            .is_some_and(|value| value.chars().count() > 200)
        {
            return Err(DnsGroupServiceError::Invalid(
                "search cannot exceed 200 characters".into(),
            ));
        }
        if self
            .observed_from
            .zip(self.observed_to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(DnsGroupServiceError::Invalid(
                "observed_from must not be after observed_to".into(),
            ));
        }
        if self.verdict.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "unclassified" | "expected" | "requires_review" | "policy_conflict"
            )
        }) {
            return Err(DnsGroupServiceError::Invalid("verdict is invalid".into()));
        }
        Ok(self)
    }

    fn fingerprint(&self, ids: (Uuid, Uuid, Uuid)) -> String {
        let bytes = serde_json::to_vec(&(ids, self)).expect("scope is serializable");
        hex::encode(Sha256::digest(bytes))
    }
}

fn page_limit(value: Option<i64>, default: i64, max: i64) -> Result<i64, DnsGroupServiceError> {
    let value = value.unwrap_or(default);
    (1..=max)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| DnsGroupServiceError::Invalid(format!("limit must be between 1 and {max}")))
}

fn group_from_row(
    tokens: &GroupTokenCodec,
    principal: Principal,
    project_id: Uuid,
    application_id: Uuid,
    row: &GroupRow,
) -> Result<DnsGroup, DnsGroupServiceError> {
    let group_token = tokens.encode(&GroupTokenPayload {
        format_version: 1,
        organization_id: principal.organization_id,
        project_id,
        application_id,
        process_command: row.process_command.clone(),
        display_name: row.display_name.clone(),
    })?;
    Ok(DnsGroup {
        group_token,
        display_name: row.display_name.clone(),
        process_command: row.process_command.clone(),
        grouping_reason: row.grouping_reason.clone(),
        confidence: row.confidence.clone(),
        first_seen_at: row.first_seen_at,
        last_seen_at: row.last_seen_at,
        observation_count: row.observation_count,
        variant_count: row.variant_count,
        query_types: row.query_types.clone(),
        release_count: row.release_count,
        cluster_count: row.cluster_count,
        namespace_count: row.namespace_count,
        workload_count: row.workload_count,
        pod_count: row.pod_count,
        container_count: row.container_count,
    })
}

/// Reads an application's logical DNS groups.
#[derive(Clone, Debug)]
pub struct DnsGroupService {
    pool: PgPool,
    tokens: GroupTokenCodec,
}

impl DnsGroupService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            tokens: GroupTokenCodec::process_default(),
        }
    }

    /// The logical DNS groups within the scope, most recently seen first.
    pub async fn list_groups(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: GroupQuery,
    ) -> Result<GroupPage, DnsGroupServiceError> {
        let principal = self
            .authorize_scope(identity, project_id, application_id)
            .await?;
        let scope = query.scope.normalize()?;
        let fingerprint =
            scope.fingerprint((principal.organization_id, project_id, application_id));
        let cursor: Option<GroupCursor> = query
            .cursor
            .as_deref()
            .map(|value| self.tokens.decode(value))
            .transpose()?;
        if cursor
            .as_ref()
            .is_some_and(|value| value.scope != fingerprint)
        {
            return Err(DnsGroupServiceError::Invalid(
                "cursor is invalid for this scope".into(),
            ));
        }
        let limit = page_limit(query.limit, 50, 200)?;
        let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
        let mut rows: Vec<GroupRow> = DnsGroupRepository::groups(
            &self.pool,
            scope.filter(principal, project_id, application_id),
            pattern,
            cursor.as_ref().map(|v| v.last_seen_at),
            cursor.as_ref().map(|v| v.display_name.as_str()),
            cursor.as_ref().map(|v| v.process_command.as_str()),
            limit + 1,
        )
        .await?;
        let total_group_count = rows.first().map_or(0, |row| row.total_group_count);
        let total_observation_count = rows.first().map_or(0, |row| row.total_observation_count);
        let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        if has_more {
            rows.pop();
        }
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    self.tokens.encode(&GroupCursor {
                        scope: fingerprint,
                        last_seen_at: row.last_seen_at,
                        display_name: row.display_name.clone(),
                        process_command: row.process_command.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        let items = rows
            .iter()
            .map(|row| group_from_row(&self.tokens, principal, project_id, application_id, row))
            .collect::<Result<_, _>>()?;
        let coverage = crate::runtime_retention::history::coverage(
            &self.pool,
            principal.organization_id,
            project_id,
        )
        .await?;
        Ok(GroupPage {
            coverage,
            items,
            next_cursor,
            total_group_count,
            total_observation_count,
        })
    }

    /// The groups with the most observations, and the rest folded together.
    pub async fn distribution(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: DistributionQuery,
    ) -> Result<DnsDistribution, DnsGroupServiceError> {
        let principal = self
            .authorize_scope(identity, project_id, application_id)
            .await?;
        let scope = query.scope.normalize()?;
        let limit = page_limit(query.limit, 5, 10)?;
        let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
        let rows: Vec<GroupRow> = DnsGroupRepository::distribution(
            &self.pool,
            scope.filter(principal, project_id, application_id),
            pattern,
            limit,
        )
        .await?;
        let total_group_count = rows.first().map_or(0, |row| row.total_group_count);
        let total_observation_count = rows.first().map_or(0, |row| row.total_observation_count);
        let shown_observations: i64 = rows.iter().map(|row| row.observation_count).sum();
        let shown_groups = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        let entries = rows
            .iter()
            .map(|row| {
                group_from_row(&self.tokens, principal, project_id, application_id, row)
                    .map(|group| DistributionEntry { group })
            })
            .collect::<Result<_, _>>()?;
        let other = (shown_groups < total_group_count).then_some(DistributionOther {
            group_count: total_group_count - shown_groups,
            observation_count: total_observation_count - shown_observations,
        });
        let coverage = crate::runtime_retention::history::coverage(
            &self.pool,
            principal.organization_id,
            project_id,
        )
        .await?;
        Ok(DnsDistribution {
            coverage,
            total_group_count,
            total_observation_count,
            entries,
            other,
        })
    }

    /// The names and query types behind one group, named by its token.
    pub async fn variants(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        group_token: &str,
        query: VariantQuery,
    ) -> Result<VariantPage, DnsGroupServiceError> {
        let principal = self
            .authorize_scope(identity, project_id, application_id)
            .await?;
        let token: GroupTokenPayload = self.tokens.decode(group_token)?;
        if token.format_version != 1
            || token.organization_id != principal.organization_id
            || token.project_id != project_id
            || token.application_id != application_id
        {
            return Err(DnsGroupServiceError::NotFound);
        }
        let scope = query.scope.normalize()?;
        let limit = page_limit(query.limit, 50, 200)?;
        let cursor: Option<VariantCursor> = query
            .cursor
            .as_deref()
            .map(|value| self.tokens.decode(value))
            .transpose()?;
        let mut items: Vec<VariantRow> = DnsGroupRepository::variants(
            &self.pool,
            scope.filter(principal, project_id, application_id),
            &token.display_name,
            &token.process_command,
            cursor.as_ref().map(|v| v.item_id),
            limit + 1,
        )
        .await?;
        if items.is_empty() {
            return Err(DnsGroupServiceError::NotFound);
        }
        let has_more = items.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| {
                    self.tokens.encode(&VariantCursor {
                        item_id: item.item_id,
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(VariantPage { items, next_cursor })
    }

    /// Resolves the project's organization and checks the principal may see
    /// the project; a project they cannot see does not exist for them.
    async fn project_principal(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<Principal, DnsGroupServiceError> {
        let scope = project_scope(&self.pool, identity, project_id)
            .await?
            .ok_or(DnsGroupServiceError::NotFound)?;
        Ok(Principal {
            organization_id: scope.organization_id,
        })
    }

    /// Also checks the application belongs to the project.
    async fn authorize_scope(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Principal, DnsGroupServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        let exists = ApplicationRepository::exists(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
        )
        .await?;
        exists
            .then_some(principal)
            .ok_or(DnsGroupServiceError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_deterministic_tenant_bound_and_tamper_evident() {
        let codec = GroupTokenCodec {
            key: Arc::new([9; 32]),
        };
        let payload = GroupTokenPayload {
            format_version: 1,
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            process_command: "/app".into(),
            display_name: "s3.example.com".into(),
        };
        let first = codec.encode(&payload).unwrap();
        assert_eq!(first, codec.encode(&payload).unwrap());
        let decoded: GroupTokenPayload = codec.decode(&first).unwrap();
        assert_eq!(decoded.organization_id, payload.organization_id);
        let mut tampered = first.into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        assert!(
            codec
                .decode::<GroupTokenPayload>(std::str::from_utf8(&tampered).unwrap())
                .is_err()
        );
    }

    #[test]
    fn scope_validation_rejects_ambiguous_inputs() {
        assert!(
            DnsGroupScope {
                search: Some(" ".into()),
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        assert!(
            DnsGroupScope {
                verdict: Some("maybe".into()),
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        assert!(page_limit(Some(11), 5, 10).is_err());
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::auth::OrganizationRole;
        use crate::repository::test_support::{Tenant, dns, ingest, tenant};
        use event_model::DnsQueryType;

        fn owner(tenant: &Tenant) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                active_organization_id: Some(tenant.organization_id),
                organization_role: Some(OrganizationRole::Owner),
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn groups(scope: DnsGroupScope, cursor: Option<String>, limit: Option<i64>) -> GroupQuery {
            GroupQuery {
                scope,
                cursor,
                limit,
            }
        }

        async fn seed(pool: &PgPool, tenant: &Tenant) {
            let events = [
                dns(tenant, "s3.example.com", DnsQueryType::A, "api"),
                dns(tenant, "s3.example.com", DnsQueryType::Aaaa, "api"),
                dns(tenant, "db.example.com", DnsQueryType::A, "worker"),
            ];
            ingest(pool, tenant, &events).await;
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn access_is_checked_before_the_request(pool: PgPool) {
            let other = tenant(&pool, "dns-service-other").await;
            let tenant = tenant(&pool, "dns-service-access").await;
            let service = DnsGroupService::new(pool.clone());
            let blank = DnsGroupScope {
                namespace: Some(" ".into()),
                ..DnsGroupScope::default()
            };
            let listed = service
                .list_groups(
                    owner(&other),
                    tenant.project_id,
                    tenant.application_id,
                    groups(blank.clone(), None, None),
                )
                .await;
            assert!(matches!(listed, Err(DnsGroupServiceError::NotFound)));
            let listed = service
                .list_groups(
                    owner(&tenant),
                    tenant.project_id,
                    other.application_id,
                    groups(blank.clone(), None, None),
                )
                .await;
            assert!(matches!(listed, Err(DnsGroupServiceError::NotFound)));
            let listed = service
                .list_groups(
                    owner(&tenant),
                    tenant.project_id,
                    tenant.application_id,
                    groups(blank, None, None),
                )
                .await;
            assert!(matches!(
                listed,
                Err(DnsGroupServiceError::Invalid(message)) if message == "filter values cannot be empty"
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn groups_page_by_scope_and_open_by_token(pool: PgPool) {
            let tenant = tenant(&pool, "dns-service-groups").await;
            seed(&pool, &tenant).await;
            let service = DnsGroupService::new(pool.clone());
            let (project, application) = (tenant.project_id, tenant.application_id);
            let principal = owner(&tenant);

            let first = service
                .list_groups(
                    principal,
                    project,
                    application,
                    groups(DnsGroupScope::default(), None, Some(1)),
                )
                .await
                .unwrap();
            assert_eq!(first.items.len(), 1);
            assert_eq!(first.total_group_count, 2);
            let cursor = first.next_cursor.clone().expect("a second page exists");
            let second = service
                .list_groups(
                    principal,
                    project,
                    application,
                    groups(DnsGroupScope::default(), Some(cursor.clone()), Some(1)),
                )
                .await
                .unwrap();
            assert_eq!(second.items.len(), 1);
            assert_ne!(second.items[0].display_name, first.items[0].display_name);
            // A cursor only continues the scope it was issued for.
            let narrowed = DnsGroupScope {
                namespace: Some("production".into()),
                ..DnsGroupScope::default()
            };
            assert!(matches!(
                service
                    .list_groups(principal, project, application, groups(narrowed, Some(cursor), None))
                    .await,
                Err(DnsGroupServiceError::Invalid(message)) if message == "cursor is invalid for this scope"
            ));

            let s3 = [&first.items[0], &second.items[0]]
                .into_iter()
                .find(|group| group.display_name == "s3.example.com")
                .unwrap();
            let variants = service
                .variants(
                    principal,
                    project,
                    application,
                    &s3.group_token,
                    VariantQuery {
                        scope: DnsGroupScope::default(),
                        cursor: None,
                        limit: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(variants.items.len(), 2);
            assert!(matches!(
                service
                    .variants(
                        principal,
                        project,
                        application,
                        "not-a-token",
                        VariantQuery {
                            scope: DnsGroupScope::default(),
                            cursor: None,
                            limit: None,
                        },
                    )
                    .await,
                Err(DnsGroupServiceError::Invalid(_))
            ));

            assert!(matches!(
                service
                    .distribution(
                        principal,
                        project,
                        application,
                        DistributionQuery {
                            scope: DnsGroupScope::default(),
                            limit: Some(11),
                        },
                    )
                    .await,
                Err(DnsGroupServiceError::Invalid(message)) if message == "limit must be between 1 and 10"
            ));
            let distribution = service
                .distribution(
                    principal,
                    project,
                    application,
                    DistributionQuery {
                        scope: DnsGroupScope::default(),
                        limit: Some(1),
                    },
                )
                .await
                .unwrap();
            assert_eq!(distribution.entries.len(), 1);
            assert_eq!(distribution.entries[0].group.display_name, "s3.example.com");
            let other = distribution.other.expect("one group is folded");
            assert_eq!(other.group_count, 1);
            assert_eq!(other.observation_count, 1);
        }
    }
}
