//! Rules shared by the account use cases: the shape of slugs and display
//! names, and issuing a browser session.

use chrono::{Duration, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::auth::SessionToken;
use crate::repository::SessionRepository;

/// A slug: 1 to 63 lowercase ASCII letters, digits and single inner hyphens.
pub fn valid_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
}

/// A display name: 1 to 120 characters without surrounding whitespace.
pub fn valid_name(value: &str) -> bool {
    value.trim() == value && (1..=120).contains(&value.chars().count())
}

/// Opens a session that has no active organization yet.
pub async fn insert_identity_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    privileged_until: Option<chrono::DateTime<Utc>>,
    lifetime: std::time::Duration,
) -> Result<(Uuid, SessionToken), sqlx::Error> {
    insert_session_with_context(tx, user_id, None, privileged_until, lifetime).await
}

/// Opens a session for the user and returns its id and the token that is
/// shown to the browser once. A lifetime that does not fit a duration falls
/// back to twelve hours.
pub async fn insert_session_with_context(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    organization_id: Option<Uuid>,
    privileged_until: Option<chrono::DateTime<Utc>>,
    lifetime: std::time::Duration,
) -> Result<(Uuid, SessionToken), sqlx::Error> {
    let session_id = Uuid::new_v4();
    let token = SessionToken::generate();
    let expires_at =
        Utc::now() + Duration::from_std(lifetime).unwrap_or_else(|_| Duration::hours(12));
    SessionRepository::insert(
        &mut **tx,
        session_id,
        user_id,
        organization_id,
        token.digest().as_slice(),
        expires_at,
        privileged_until,
    )
    .await?;
    Ok((session_id, token))
}
