//! Persistence layer.
//!
//! Every SQL statement against a shared entity belongs in a repository here
//! rather than in an HTTP handler. Repositories own the statement text, the
//! row types, and — critically — the tenant-scoping predicates, so that
//! `organization_id` isolation is written once and reviewed once instead of
//! being restated at each call site.
//!
//! Repository methods are generic over [`sqlx::PgExecutor`]. A caller passes
//! `&pool` for a standalone read or `&mut *tx` to enlist the statement in its
//! own transaction; the repository never opens or commits a transaction on the
//! caller's behalf.
//!
//! Errors surface as [`sqlx::Error`]. Mapping persistence failures onto an
//! API-facing error type stays the caller's responsibility, because the status
//! code and error envelope depend on the endpoint, not on the query.

pub mod applications;
pub mod event_groups;
pub mod events;
pub mod organizations;
pub mod projects;
pub mod users;

pub use applications::ApplicationRepository;
pub use event_groups::{EventGroupRepository, GroupKey};
pub use events::{EventRepository, StoredEvent};
pub use organizations::OrganizationRepository;
pub use projects::ProjectRepository;
pub use users::UserRepository;
