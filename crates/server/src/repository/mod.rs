//! Persistence layer.
//!
//! Every SQL statement the server issues lives in a repository here: HTTP
//! handlers, background workers and domain modules call repository methods
//! and never build queries themselves. Repositories own the statement text, the
//! row types, and — critically — the tenant-scoping predicates, so that
//! `organization_id` isolation is written once and reviewed once instead of
//! being restated at each call site.
//!
//! Repository methods are generic over [`sqlx::PgExecutor`]. A caller passes
//! `&pool` for a standalone read or `&mut *tx` to enlist the statement in its
//! own transaction; the repository never opens or commits a transaction on the
//! caller's behalf. A method that issues several statements in a row takes
//! `&mut PgConnection` instead, so they all run on the caller's connection.
//!
//! Errors surface as [`sqlx::Error`]. Mapping persistence failures onto an
//! API-facing error type stays the caller's responsibility, because the status
//! code and error envelope depend on the endpoint, not on the query.
//!
//! # Projections shaped by their endpoint
//!
//! Some statements exist for one endpoint and select exactly the columns its
//! response carries. Those still belong here, but their row type does not: a
//! method returning such a projection is generic over `T: FromRow`, and the
//! caller names the response type it decodes into. The repository owns the
//! statement and its tenant scoping; the endpoint owns the shape. Each such
//! method documents the columns it selects, because that list is the contract
//! between the two.

pub mod access_audit;
pub mod agent_health;
pub mod application_credentials;
pub mod applications;
pub mod attention;
pub mod clusters;
pub mod deployments;
pub mod dns_groups;
pub mod email_actions;
pub mod event_groups;
pub mod events;
pub mod installations;
pub mod inventory;
pub mod invitations;
pub mod memberships;
pub mod navigation;
pub mod notification_deliveries;
pub mod notification_recovery;
pub mod notification_retention;
pub mod organizations;
pub mod outbox;
pub mod policies;
pub mod projects;
pub mod provisioning;
pub mod releases;
pub mod resources;
pub mod runtime_retention;
pub mod schema;
pub mod sessions;
pub mod terminations;
pub mod transaction;
pub mod transactional_mail;
pub mod users;
pub mod webhook_destinations;

#[cfg(test)]
pub(crate) mod test_support;

pub use applications::ApplicationRepository;
pub use event_groups::{EventGroupRepository, GroupKey};
pub use events::{EventRepository, StoredEvent};
pub use memberships::MembershipRepository;
pub use organizations::{OrganizationRepository, OrganizationStatus, StoredOrganization};
pub use projects::{LockedProject, ProjectRepository, StoredProject};
pub use releases::{ApplicationScope, ReleaseRepository};
pub use sessions::SessionRepository;
pub use users::UserRepository;
