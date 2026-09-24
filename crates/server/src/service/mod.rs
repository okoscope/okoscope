//! Service layer: the use cases of each area, between transport and
//! persistence.
//!
//! The server is split into three layers, each depending only on the one below
//! it:
//!
//! - **Transport** (the axum handlers and the agent gRPC service) authenticates
//!   the caller, parses the request (path, query, body), calls one service
//!   method, and turns its result into a response: status code, JSON body,
//!   error envelope, request metrics.
//! - **Services** (this module) carry the use case itself: who may do it
//!   (authorization against the authenticated principal), which inputs are
//!   valid, which repository calls happen in which order, and which of them
//!   share a transaction. A service method returns the use case's result or a
//!   service error; it knows nothing about HTTP.
//! - **Repositories** ([`crate::repository`]) own every SQL statement.
//!
//! # Conventions
//!
//! A service is a cheap-to-clone struct holding its dependencies (usually the
//! pool). Its methods take the authenticated principal first, then the scope
//! the request names, then the parsed inputs.
//!
//! Each service has its own error enum. Its variants name what went wrong for
//! the caller (`NotFound`, `Invalid`, `Conflict`, ...) plus `Database` for
//! persistence failures. The transport maps each variant onto a status, an
//! error code and a message; the service never chooses those.
//!
//! The order of checks in a service method is part of its behaviour, because
//! it decides which error a request that is wrong in several ways gets. When a
//! use case moves here from a handler, its checks keep their order.
//!
//! The types a use case returns live with the service. Where the response body
//! is exactly that result, they also derive `Serialize`, so the transport can
//! send them as they are.

pub mod access;
pub mod accounts;
pub mod identity;
pub mod invitations;
pub mod onboarding;
pub mod provisioning;
pub mod releases;
