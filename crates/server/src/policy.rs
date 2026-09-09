use std::{collections::BTreeSet, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const POLICY_EVALUATOR_VERSION: i16 = 1;
pub const MAX_POLICY_EXPLANATION_REVISIONS: usize = 10;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BehaviorMatcher {
    Process {
        executable: String,
    },
    Destination {
        process_command: String,
        address_family: AddressFamily,
        destination_address: IpAddr,
        destination_port: u16,
    },
    Domain {
        process_command: String,
        name: String,
        query_type: String,
    },
    Syscall {
        process_command: String,
        syscall: String,
    },
    InboundEndpoint {
        transport: String,
        address_family: AddressFamily,
        local_address: IpAddr,
        local_port: u16,
    },
    FileActivity {
        process_command: String,
        operation: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        new_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        replaced: Option<bool>,
    },
    LifecycleProcessExit {
        identity: String,
        termination: TerminationMatcher,
    },
    LifecycleContainerTermination {
        container_name: String,
        reason: String,
        exit_code: i32,
    },
    LifecycleContainerRestart {
        container_name: String,
    },
}

impl BehaviorMatcher {
    pub const fn inventory_kind(&self) -> &'static str {
        match self {
            Self::Process { .. } => "process",
            Self::Destination { .. } => "destination",
            Self::Domain { .. } => "domain",
            Self::Syscall { .. } => "syscall",
            Self::InboundEndpoint { .. } => "inbound_endpoint",
            Self::FileActivity { .. } => "file_activity",
            Self::LifecycleProcessExit { .. }
            | Self::LifecycleContainerTermination { .. }
            | Self::LifecycleContainerRestart { .. } => "lifecycle",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminationMatcher {
    Exited { status: u8 },
    Signaled { signal: u8, signal_name: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementMatcher {
    #[serde(default)]
    pub cluster_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub namespaces: BTreeSet<String>,
    #[serde(default)]
    pub workload_kinds: BTreeSet<String>,
    #[serde(default)]
    pub workload_names: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement<'a> {
    pub cluster_id: Uuid,
    pub namespace: &'a str,
    pub workload_kind: &'a str,
    pub workload_name: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Expected,
    RequiresReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Unclassified,
    Expected,
    RequiresReview,
    PolicyConflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationState {
    Current,
    Pending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationReason {
    NoMatchingPolicy,
    InsidePlacement,
    OutsidePlacement,
    EqualSpecificityConflict,
    EvaluationPending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionState {
    Active,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecomputeState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedUnavailableReason {
    UnsupportedIdentityVersion,
    UnsupportedInventoryKind,
    InvalidSemanticIdentity,
    InvalidIdentityDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BehaviorIdentity {
    pub identity_version: i16,
    pub identity_digest: [u8; 32],
    pub matcher: BehaviorMatcher,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicySeed {
    pub behavior: BehaviorIdentity,
    pub placement: PlacementMatcher,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_inventory_item_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_runtime_group_id: Option<Uuid>,
    pub inside_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outside_effect: Option<PolicyEffect>,
}

impl PolicySeed {
    pub fn from_inventory_item(item_id: Uuid, behavior: BehaviorIdentity) -> Self {
        Self {
            behavior,
            placement: PlacementMatcher::default(),
            source_inventory_item_id: Some(item_id),
            source_runtime_group_id: None,
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        }
    }

    pub fn from_runtime_group(
        item_id: Uuid,
        group_id: Uuid,
        behavior: BehaviorIdentity,
        placement: &Placement<'_>,
    ) -> Self {
        Self {
            behavior,
            placement: PlacementMatcher {
                cluster_ids: [placement.cluster_id].into_iter().collect(),
                namespaces: [placement.namespace.to_owned()].into_iter().collect(),
                workload_kinds: [placement.workload_kind.to_owned()].into_iter().collect(),
                workload_names: [placement.workload_name.to_owned()].into_iter().collect(),
            },
            source_inventory_item_id: Some(item_id),
            source_runtime_group_id: Some(group_id),
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        }
    }
}

impl BehaviorIdentity {
    pub fn from_inventory(
        inventory_kind: &str,
        identity_version: i16,
        identity_digest: &[u8],
        summary: &serde_json::Value,
    ) -> Result<Self, SeedUnavailableReason> {
        if identity_version != crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION.get() {
            return Err(SeedUnavailableReason::UnsupportedIdentityVersion);
        }
        let identity_digest = identity_digest
            .try_into()
            .map_err(|_| SeedUnavailableReason::InvalidIdentityDigest)?;
        let matcher = matcher_from_summary(inventory_kind, summary)?;
        Ok(Self {
            identity_version,
            identity_digest,
            matcher,
        })
    }
}

fn matcher_from_summary(
    kind: &str,
    summary: &serde_json::Value,
) -> Result<BehaviorMatcher, SeedUnavailableReason> {
    fn string(summary: &serde_json::Value, field: &str) -> Result<String, SeedUnavailableReason> {
        summary
            .get(field)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .ok_or(SeedUnavailableReason::InvalidSemanticIdentity)
    }
    fn number<T: TryFrom<u64>>(
        summary: &serde_json::Value,
        field: &str,
    ) -> Result<T, SeedUnavailableReason> {
        summary
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| T::try_from(value).ok())
            .ok_or(SeedUnavailableReason::InvalidSemanticIdentity)
    }
    fn address_family(summary: &serde_json::Value) -> Result<AddressFamily, SeedUnavailableReason> {
        match summary
            .get("address_family")
            .and_then(serde_json::Value::as_str)
        {
            Some("ipv4") => Ok(AddressFamily::Ipv4),
            Some("ipv6") => Ok(AddressFamily::Ipv6),
            _ => Err(SeedUnavailableReason::InvalidSemanticIdentity),
        }
    }
    fn ip(summary: &serde_json::Value, field: &str) -> Result<IpAddr, SeedUnavailableReason> {
        string(summary, field)?
            .parse()
            .map_err(|_| SeedUnavailableReason::InvalidSemanticIdentity)
    }

    match kind {
        "process" => Ok(BehaviorMatcher::Process {
            executable: string(summary, "executable")?,
        }),
        "destination" => Ok(BehaviorMatcher::Destination {
            process_command: string(summary, "process_command")?,
            address_family: address_family(summary)?,
            destination_address: ip(summary, "destination_address")?,
            destination_port: number(summary, "destination_port")?,
        }),
        "domain" => Ok(BehaviorMatcher::Domain {
            process_command: string(summary, "process_command")?,
            name: string(summary, "name")?,
            query_type: string(summary, "query_type")?,
        }),
        "syscall" => Ok(BehaviorMatcher::Syscall {
            process_command: string(summary, "process_command")?,
            syscall: string(summary, "syscall")?,
        }),
        "inbound_endpoint" => Ok(BehaviorMatcher::InboundEndpoint {
            transport: string(summary, "transport")?,
            address_family: address_family(summary)?,
            local_address: ip(summary, "local_address")?,
            local_port: number(summary, "local_port")?,
        }),
        "file_activity" => Ok(BehaviorMatcher::FileActivity {
            process_command: string(summary, "process_command")?,
            operation: string(summary, "operation")?,
            path: string(summary, "path")?,
            new_path: summary
                .get("new_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            replaced: summary.get("replaced").and_then(serde_json::Value::as_bool),
        }),
        "lifecycle" => match summary
            .get("event_kind")
            .and_then(serde_json::Value::as_str)
        {
            Some("process.exit") => Ok(BehaviorMatcher::LifecycleProcessExit {
                identity: string(summary, "identity")?,
                termination: serde_json::from_value(
                    summary
                        .get("termination")
                        .cloned()
                        .ok_or(SeedUnavailableReason::InvalidSemanticIdentity)?,
                )
                .map_err(|_| SeedUnavailableReason::InvalidSemanticIdentity)?,
            }),
            Some("container.terminated") => Ok(BehaviorMatcher::LifecycleContainerTermination {
                container_name: string(summary, "container_name")?,
                reason: string(summary, "reason")?,
                exit_code: number(summary, "exit_code")?,
            }),
            Some("container.restart") => Ok(BehaviorMatcher::LifecycleContainerRestart {
                container_name: string(summary, "container_name")?,
            }),
            _ => Err(SeedUnavailableReason::InvalidSemanticIdentity),
        },
        _ => Err(SeedUnavailableReason::UnsupportedInventoryKind),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCandidate {
    pub revision_id: Uuid,
    pub placement: PlacementMatcher,
    pub inside_effect: PolicyEffect,
    pub outside_effect: Option<PolicyEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedPolicyCandidate {
    pub scope: PolicyScope,
    pub identity_version: i16,
    pub identity_digest: [u8; 32],
    pub candidate: PolicyCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationInput<'a> {
    pub scope: PolicyScope,
    pub identity_version: i16,
    pub identity_digest: [u8; 32],
    pub placement: Placement<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Evaluation {
    pub verdict: PolicyVerdict,
    pub reason: EvaluationReason,
    pub specificity: Option<Specificity>,
    pub winning_revision_id: Option<Uuid>,
    pub related_revision_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuppressionCandidate {
    pub id: Uuid,
    pub scope: PolicyScope,
    pub identity_version: i16,
    pub identity_digest: [u8; 32],
    pub placement: PlacementMatcher,
    pub expires_at: DateTime<Utc>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveSuppression {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Specificity {
    pub constrained_dimensions: u8,
    pub workload_name: u8,
    pub workload_kind: u8,
    pub namespace: u8,
    pub cluster: u8,
}

impl PlacementMatcher {
    pub fn matches(&self, placement: &Placement<'_>) -> bool {
        (self.cluster_ids.is_empty() || self.cluster_ids.contains(&placement.cluster_id))
            && (self.namespaces.is_empty() || self.namespaces.contains(placement.namespace))
            && (self.workload_kinds.is_empty()
                || self.workload_kinds.contains(placement.workload_kind))
            && (self.workload_names.is_empty()
                || self.workload_names.contains(placement.workload_name))
    }

    pub fn specificity(&self) -> Specificity {
        let cluster = !self.cluster_ids.is_empty();
        let namespace = !self.namespaces.is_empty();
        let workload_kind = !self.workload_kinds.is_empty();
        let workload_name = !self.workload_names.is_empty();
        Specificity {
            constrained_dimensions: u8::from(cluster)
                + u8::from(namespace)
                + u8::from(workload_kind)
                + u8::from(workload_name),
            workload_name: u8::from(workload_name),
            workload_kind: u8::from(workload_kind),
            namespace: u8::from(namespace),
            cluster: u8::from(cluster),
        }
    }

    pub fn normalize(&mut self) -> Result<(), &'static str> {
        if self.cluster_ids.len() > 50
            || self.namespaces.len() > 50
            || self.workload_kinds.len() > 50
            || self.workload_names.len() > 50
        {
            return Err("each placement dimension must contain at most 50 values");
        }
        self.namespaces = normalize_values(&self.namespaces, "namespace")?;
        self.workload_kinds = normalize_values(&self.workload_kinds, "workload_kind")?;
        self.workload_names = normalize_values(&self.workload_names, "workload_name")?;
        Ok(())
    }
}

fn normalize_values(
    values: &BTreeSet<String>,
    field: &'static str,
) -> Result<BTreeSet<String>, &'static str> {
    values
        .iter()
        .map(|value| {
            let value = value.trim();
            if value.is_empty() || value.len() > 253 {
                Err(field)
            } else {
                Ok(value.to_owned())
            }
        })
        .collect()
}

pub fn evaluate(placement: &Placement<'_>, candidates: &[PolicyCandidate]) -> Evaluation {
    let mut applicable = candidates
        .iter()
        .filter_map(|candidate| {
            let inside = candidate.placement.matches(placement);
            let effect = if inside {
                Some(candidate.inside_effect)
            } else {
                candidate.outside_effect
            }?;
            Some((
                candidate.placement.specificity(),
                candidate.revision_id,
                effect,
                inside,
            ))
        })
        .collect::<Vec<_>>();
    let Some(best_specificity) = applicable.iter().map(|entry| entry.0).max() else {
        return Evaluation {
            verdict: PolicyVerdict::Unclassified,
            reason: EvaluationReason::NoMatchingPolicy,
            specificity: None,
            winning_revision_id: None,
            related_revision_ids: Vec::new(),
        };
    };
    applicable.retain(|entry| entry.0 == best_specificity);
    applicable.sort_unstable_by_key(|entry| entry.1);
    let first_effect = applicable[0].2;
    let conflict = applicable.iter().any(|entry| entry.2 != first_effect);
    let related_revision_ids = applicable
        .iter()
        .take(MAX_POLICY_EXPLANATION_REVISIONS)
        .map(|entry| entry.1)
        .collect::<Vec<_>>();
    if conflict {
        return Evaluation {
            verdict: PolicyVerdict::PolicyConflict,
            reason: EvaluationReason::EqualSpecificityConflict,
            specificity: Some(best_specificity),
            winning_revision_id: None,
            related_revision_ids,
        };
    }
    Evaluation {
        verdict: match first_effect {
            PolicyEffect::Expected => PolicyVerdict::Expected,
            PolicyEffect::RequiresReview => PolicyVerdict::RequiresReview,
        },
        reason: if applicable.iter().all(|entry| entry.3) {
            EvaluationReason::InsidePlacement
        } else {
            EvaluationReason::OutsidePlacement
        },
        specificity: Some(best_specificity),
        winning_revision_id: (applicable.len() == 1).then_some(applicable[0].1),
        related_revision_ids,
    }
}

pub fn evaluate_scoped(
    input: &EvaluationInput<'_>,
    candidates: &[ScopedPolicyCandidate],
) -> Evaluation {
    let applicable = candidates
        .iter()
        .filter(|candidate| {
            candidate.scope == input.scope
                && candidate.identity_version == input.identity_version
                && candidate.identity_digest == input.identity_digest
        })
        .map(|candidate| candidate.candidate.clone())
        .collect::<Vec<_>>();
    evaluate(&input.placement, &applicable)
}

pub fn active_suppression(
    input: &EvaluationInput<'_>,
    snapshot_at: DateTime<Utc>,
    candidates: &[SuppressionCandidate],
) -> Option<ActiveSuppression> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.scope == input.scope
                && candidate.identity_version == input.identity_version
                && candidate.identity_digest == input.identity_digest
                && candidate.cancelled_at.is_none()
                && candidate.expires_at > snapshot_at
                && candidate.placement.matches(&input.placement)
        })
        .max_by_key(|candidate| {
            (
                candidate.placement.specificity(),
                candidate.expires_at,
                std::cmp::Reverse(candidate.id),
            )
        })
        .map(|candidate| ActiveSuppression {
            id: candidate.id,
            expires_at: candidate.expires_at,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_dimensions_are_conjunctive_and_values_are_disjunctive() {
        let cluster_id = Uuid::new_v4();
        let matcher = PlacementMatcher {
            cluster_ids: [cluster_id].into_iter().collect(),
            namespaces: ["production".to_owned(), "staging".to_owned()]
                .into_iter()
                .collect(),
            workload_kinds: ["Deployment".to_owned()].into_iter().collect(),
            workload_names: BTreeSet::new(),
        };
        assert!(matcher.matches(&Placement {
            cluster_id,
            namespace: "production",
            workload_kind: "Deployment",
            workload_name: "payments",
        }));
        assert!(!matcher.matches(&Placement {
            cluster_id,
            namespace: "maintenance",
            workload_kind: "Deployment",
            workload_name: "payments",
        }));
    }

    #[test]
    fn specificity_prefers_narrow_workload_scope() {
        let broad = PlacementMatcher::default().specificity();
        let narrow = PlacementMatcher {
            workload_names: ["payments".to_owned()].into_iter().collect(),
            ..PlacementMatcher::default()
        }
        .specificity();
        assert!(narrow > broad);
    }

    #[test]
    fn behavior_matchers_reject_unknown_fields() {
        let value = serde_json::json!({
            "kind": "process",
            "executable": "/app",
            "regex": ".*"
        });
        assert!(serde_json::from_value::<BehaviorMatcher>(value).is_err());
    }

    #[test]
    fn inventory_seed_keeps_only_identity_fields() {
        let seed = BehaviorIdentity::from_inventory(
            "inbound_endpoint",
            1,
            &[7; 32],
            &serde_json::json!({
                "transport": "tcp",
                "address_family": "ipv4",
                "local_address": "0.0.0.0",
                "local_port": 8080,
                "listener_observed": true,
                "accept_observed": false
            }),
        )
        .unwrap();
        assert!(matches!(
            seed.matcher,
            BehaviorMatcher::InboundEndpoint {
                local_port: 8080,
                ..
            }
        ));
    }

    #[test]
    fn inventory_seed_rejects_version_and_digest_mismatch() {
        assert_eq!(
            BehaviorIdentity::from_inventory(
                "process",
                2,
                &[0; 32],
                &serde_json::json!({"executable":"/app"})
            ),
            Err(SeedUnavailableReason::UnsupportedIdentityVersion)
        );
        assert_eq!(
            BehaviorIdentity::from_inventory(
                "process",
                1,
                &[0; 3],
                &serde_json::json!({"executable":"/app"})
            ),
            Err(SeedUnavailableReason::InvalidIdentityDigest)
        );
    }

    #[test]
    fn group_seed_defaults_to_exact_placement_without_outside_effect() {
        let cluster_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let behavior = BehaviorIdentity::from_inventory(
            "process",
            1,
            &[1; 32],
            &serde_json::json!({"executable":"/app"}),
        )
        .unwrap();
        let seed =
            PolicySeed::from_runtime_group(item_id, group_id, behavior, &placement(cluster_id));
        assert!(seed.placement.cluster_ids.contains(&cluster_id));
        assert!(seed.placement.namespaces.contains("production"));
        assert_eq!(seed.inside_effect, PolicyEffect::Expected);
        assert_eq!(seed.outside_effect, None);
    }

    #[test]
    fn scoped_evaluation_rejects_foreign_tenant_and_identity_version() {
        let scope = PolicyScope {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
        };
        let input = EvaluationInput {
            scope,
            identity_version: 1,
            identity_digest: [1; 32],
            placement: placement(Uuid::new_v4()),
        };
        let base = PolicyCandidate {
            revision_id: Uuid::new_v4(),
            placement: PlacementMatcher::default(),
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        };
        let candidates = [
            ScopedPolicyCandidate {
                scope: PolicyScope {
                    organization_id: Uuid::new_v4(),
                    ..scope
                },
                identity_version: 1,
                identity_digest: [1; 32],
                candidate: base.clone(),
            },
            ScopedPolicyCandidate {
                scope,
                identity_version: 2,
                identity_digest: [1; 32],
                candidate: base,
            },
        ];
        assert_eq!(
            evaluate_scoped(&input, &candidates).verdict,
            PolicyVerdict::Unclassified
        );
    }

    #[test]
    fn suppression_is_snapshot_based_and_prefers_specific_scope() {
        let now = Utc::now();
        let scope = PolicyScope {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
        };
        let input = EvaluationInput {
            scope,
            identity_version: 1,
            identity_digest: [3; 32],
            placement: placement(Uuid::new_v4()),
        };
        let broad = SuppressionCandidate {
            id: Uuid::from_u128(1),
            scope,
            identity_version: 1,
            identity_digest: [3; 32],
            placement: PlacementMatcher::default(),
            expires_at: now + chrono::Duration::days(2),
            cancelled_at: None,
        };
        let narrow = SuppressionCandidate {
            id: Uuid::from_u128(2),
            placement: PlacementMatcher {
                namespaces: ["production".to_owned()].into_iter().collect(),
                ..PlacementMatcher::default()
            },
            expires_at: now + chrono::Duration::days(1),
            ..broad.clone()
        };
        assert_eq!(
            active_suppression(&input, now, &[broad, narrow])
                .unwrap()
                .id,
            Uuid::from_u128(2)
        );
    }

    #[test]
    fn cancelled_expired_and_foreign_suppressions_are_inactive() {
        let now = Utc::now();
        let scope = PolicyScope {
            organization_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
        };
        let input = EvaluationInput {
            scope,
            identity_version: 1,
            identity_digest: [3; 32],
            placement: placement(Uuid::new_v4()),
        };
        let base = SuppressionCandidate {
            id: Uuid::new_v4(),
            scope,
            identity_version: 1,
            identity_digest: [3; 32],
            placement: PlacementMatcher::default(),
            expires_at: now,
            cancelled_at: None,
        };
        let cancelled = SuppressionCandidate {
            expires_at: now + chrono::Duration::days(1),
            cancelled_at: Some(now),
            ..base.clone()
        };
        let foreign = SuppressionCandidate {
            scope: PolicyScope {
                organization_id: Uuid::new_v4(),
                ..scope
            },
            expires_at: now + chrono::Duration::days(1),
            ..base.clone()
        };
        assert_eq!(
            active_suppression(&input, now, &[base, cancelled, foreign]),
            None
        );
    }

    fn placement<'a>(cluster_id: Uuid) -> Placement<'a> {
        Placement {
            cluster_id,
            namespace: "production",
            workload_kind: "Deployment",
            workload_name: "payments",
        }
    }

    #[test]
    fn evaluation_is_order_independent_and_prefers_specific_policy() {
        let cluster_id = Uuid::new_v4();
        let broad = PolicyCandidate {
            revision_id: Uuid::from_u128(1),
            placement: PlacementMatcher::default(),
            inside_effect: PolicyEffect::RequiresReview,
            outside_effect: None,
        };
        let narrow = PolicyCandidate {
            revision_id: Uuid::from_u128(2),
            placement: PlacementMatcher {
                workload_names: ["payments".to_owned()].into_iter().collect(),
                ..PlacementMatcher::default()
            },
            inside_effect: PolicyEffect::Expected,
            outside_effect: None,
        };
        let expected = evaluate(&placement(cluster_id), &[broad.clone(), narrow.clone()]);
        assert_eq!(expected.verdict, PolicyVerdict::Expected);
        assert_eq!(expected.winning_revision_id, Some(narrow.revision_id));
        assert_eq!(expected, evaluate(&placement(cluster_id), &[narrow, broad]));
    }

    #[test]
    fn equal_specificity_contradiction_is_visible() {
        let candidates = [
            PolicyCandidate {
                revision_id: Uuid::from_u128(1),
                placement: PlacementMatcher::default(),
                inside_effect: PolicyEffect::Expected,
                outside_effect: None,
            },
            PolicyCandidate {
                revision_id: Uuid::from_u128(2),
                placement: PlacementMatcher::default(),
                inside_effect: PolicyEffect::RequiresReview,
                outside_effect: None,
            },
        ];
        let result = evaluate(&placement(Uuid::new_v4()), &candidates);
        assert_eq!(result.verdict, PolicyVerdict::PolicyConflict);
        assert_eq!(result.winning_revision_id, None);
    }

    #[test]
    fn outside_scope_review_and_unclassified_are_distinct() {
        let candidate = PolicyCandidate {
            revision_id: Uuid::from_u128(1),
            placement: PlacementMatcher {
                namespaces: ["maintenance".to_owned()].into_iter().collect(),
                ..PlacementMatcher::default()
            },
            inside_effect: PolicyEffect::Expected,
            outside_effect: Some(PolicyEffect::RequiresReview),
        };
        let result = evaluate(&placement(Uuid::new_v4()), &[candidate]);
        assert_eq!(result.verdict, PolicyVerdict::RequiresReview);
        assert_eq!(result.reason, EvaluationReason::OutsidePlacement);
        assert_eq!(
            evaluate(&placement(Uuid::new_v4()), &[]).verdict,
            PolicyVerdict::Unclassified
        );
    }
}
