//! The closed set of machine-readable error codes the API emits.
//!
//! Every error body carries an `error` field that clients switch on. The codes
//! used to be `&'static str` literals spread across eighteen modules, and the
//! `OpenAPI` document listed its own copy of the set. Nothing compared the two,
//! and they had drifted: twenty-one codes reached clients that the published
//! contract did not list.
//!
//! Naming a code now means naming a constant here, so a typo is a compile
//! error rather than an undocumented code on the wire, and
//! `error_codes_match_the_openapi_contract` pins [`ErrorCode::ALL`] against the
//! document in both directions.
//!
//! Adding a code means adding it here and to the `Error` schema's enum in
//! `openapi/okoscope-v1.yaml`. The test fails until both sides agree.

use serde::{Serialize, Serializer};

/// A machine-readable error code from the published contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    pub const VALIDATION_FAILED: Self = Self("validation_failed");
    pub const UNAUTHORIZED: Self = Self("unauthorized");
    pub const INVALID_CREDENTIALS: Self = Self("invalid_credentials");
    pub const EMAIL_VERIFICATION_REQUIRED: Self = Self("email_verification_required");
    pub const REGISTRATION_DISABLED: Self = Self("registration_disabled");
    pub const REGISTRATION_CONFLICT: Self = Self("registration_conflict");
    pub const UNTRUSTED_ORIGIN: Self = Self("untrusted_origin");
    pub const FORBIDDEN: Self = Self("forbidden");
    pub const NOT_FOUND: Self = Self("not_found");
    pub const ORGANIZATION_NOT_FOUND: Self = Self("organization_not_found");
    pub const PROJECT_NOT_FOUND: Self = Self("project_not_found");
    pub const APPLICATION_NOT_FOUND: Self = Self("application_not_found");
    pub const USER_NOT_FOUND: Self = Self("user_not_found");
    pub const USER_NOT_ELIGIBLE: Self = Self("user_not_eligible");
    pub const SETUP_ALREADY_COMPLETED: Self = Self("setup_already_completed");
    pub const INVALID_SETUP_TOKEN: Self = Self("invalid_setup_token");
    pub const SETUP_RATE_LIMITED: Self = Self("setup_rate_limited");
    pub const PRIVILEGE_CONFIRMATION_REQUIRED: Self = Self("privilege_confirmation_required");
    pub const CURRENT_PASSWORD_INVALID: Self = Self("current_password_invalid");
    pub const SELF_PROMOTION_FORBIDDEN: Self = Self("self_promotion_forbidden");
    pub const LAST_SUPER_ADMIN_REQUIRED: Self = Self("last_super_admin_required");
    pub const LAST_ORGANIZATION_OWNER_REQUIRED: Self = Self("last_organization_owner_required");
    pub const ORGANIZATION_LIMIT_REACHED: Self = Self("organization_limit_reached");
    pub const INVITATION_UNUSABLE: Self = Self("invitation_unusable");
    pub const INVITATION_ACCOUNT_MISMATCH: Self = Self("invitation_account_mismatch");
    pub const INVITATION_EXISTS: Self = Self("invitation_exists");
    pub const RATE_LIMITED: Self = Self("rate_limited");
    pub const MAIL_UNAVAILABLE: Self = Self("mail_unavailable");
    pub const IDEMPOTENCY_KEY_REUSED: Self = Self("idempotency_key_reused");
    pub const OPERATION_ALREADY_COMPLETED: Self = Self("operation_already_completed");
    pub const INTERNAL_ERROR: Self = Self("internal_error");
    pub const INVALID_REQUEST: Self = Self("invalid_request");
    pub const LABEL_CONFLICT: Self = Self("label_conflict");
    pub const REVISION_CONFLICT: Self = Self("revision_conflict");
    pub const RELEASE_EXISTS: Self = Self("release_exists");
    pub const ACTION_TOKEN_INVALID: Self = Self("action_token_invalid");
    pub const APPLICATION_SLUG_CONFLICT: Self = Self("application_slug_conflict");
    pub const CONFLICT: Self = Self("conflict");
    pub const CREDENTIAL_CONFLICT: Self = Self("credential_conflict");
    pub const CREDENTIAL_NAME_CONFLICT: Self = Self("credential_name_conflict");
    pub const CREDENTIAL_NOT_FOUND: Self = Self("credential_not_found");
    pub const INSTALLATION_METADATA_UNAVAILABLE: Self = Self("installation_metadata_unavailable");
    pub const INVITATION_IDENTITY_CONFLICT: Self = Self("invitation_identity_conflict");
    pub const INVITATION_NOT_FOUND: Self = Self("invitation_not_found");
    pub const INVITATION_NOT_PENDING: Self = Self("invitation_not_pending");
    pub const INVITATION_REQUIRES_SIGN_IN: Self = Self("invitation_requires_sign_in");
    pub const INVITATION_SCOPE_NOT_FOUND: Self = Self("invitation_scope_not_found");
    pub const MEMBERSHIP_EXISTS: Self = Self("membership_exists");
    pub const ORGANIZATION_NOT_DELETABLE: Self = Self("organization_not_deletable");
    pub const ORGANIZATION_SLUG_CONFLICT: Self = Self("organization_slug_conflict");
    pub const PROJECT_SLUG_CONFLICT: Self = Self("project_slug_conflict");
    pub const BULK_LIMIT_EXCEEDED: Self = Self("bulk_limit_exceeded");
    pub const DELIVERY_ACTIVE_LEASE: Self = Self("delivery_active_lease");
    pub const DELIVERY_INVALID_STATE: Self = Self("delivery_invalid_state");
    pub const DESTINATION_DISABLED: Self = Self("destination_disabled");
    pub const DESTINATION_NAME_CONFLICT: Self = Self("destination_name_conflict");
    pub const INVALID_IDENTITY_TOKEN: Self = Self("invalid_identity_token");
    pub const EXPIRED_IDENTITY_TOKEN: Self = Self("expired_identity_token");
    pub const IDENTITY_TOKEN_SCOPE_MISMATCH: Self = Self("identity_token_scope_mismatch");

    /// Every code, in the order the `OpenAPI` enum lists them. The contract test
    /// compares this against the document, so a code added on one side only
    /// fails the build.
    pub const ALL: &'static [Self] = &[
        Self::VALIDATION_FAILED,
        Self::UNAUTHORIZED,
        Self::INVALID_CREDENTIALS,
        Self::EMAIL_VERIFICATION_REQUIRED,
        Self::REGISTRATION_DISABLED,
        Self::REGISTRATION_CONFLICT,
        Self::UNTRUSTED_ORIGIN,
        Self::FORBIDDEN,
        Self::NOT_FOUND,
        Self::ORGANIZATION_NOT_FOUND,
        Self::PROJECT_NOT_FOUND,
        Self::APPLICATION_NOT_FOUND,
        Self::USER_NOT_FOUND,
        Self::USER_NOT_ELIGIBLE,
        Self::SETUP_ALREADY_COMPLETED,
        Self::INVALID_SETUP_TOKEN,
        Self::SETUP_RATE_LIMITED,
        Self::PRIVILEGE_CONFIRMATION_REQUIRED,
        Self::CURRENT_PASSWORD_INVALID,
        Self::SELF_PROMOTION_FORBIDDEN,
        Self::LAST_SUPER_ADMIN_REQUIRED,
        Self::LAST_ORGANIZATION_OWNER_REQUIRED,
        Self::ORGANIZATION_LIMIT_REACHED,
        Self::INVITATION_UNUSABLE,
        Self::INVITATION_ACCOUNT_MISMATCH,
        Self::INVITATION_EXISTS,
        Self::RATE_LIMITED,
        Self::MAIL_UNAVAILABLE,
        Self::IDEMPOTENCY_KEY_REUSED,
        Self::OPERATION_ALREADY_COMPLETED,
        Self::INTERNAL_ERROR,
        Self::INVALID_REQUEST,
        Self::LABEL_CONFLICT,
        Self::REVISION_CONFLICT,
        Self::RELEASE_EXISTS,
        Self::ACTION_TOKEN_INVALID,
        Self::APPLICATION_SLUG_CONFLICT,
        Self::CONFLICT,
        Self::CREDENTIAL_CONFLICT,
        Self::CREDENTIAL_NAME_CONFLICT,
        Self::CREDENTIAL_NOT_FOUND,
        Self::INSTALLATION_METADATA_UNAVAILABLE,
        Self::INVITATION_IDENTITY_CONFLICT,
        Self::INVITATION_NOT_FOUND,
        Self::INVITATION_NOT_PENDING,
        Self::INVITATION_REQUIRES_SIGN_IN,
        Self::INVITATION_SCOPE_NOT_FOUND,
        Self::MEMBERSHIP_EXISTS,
        Self::ORGANIZATION_NOT_DELETABLE,
        Self::ORGANIZATION_SLUG_CONFLICT,
        Self::PROJECT_SLUG_CONFLICT,
        Self::BULK_LIMIT_EXCEEDED,
        Self::DELIVERY_ACTIVE_LEASE,
        Self::DELIVERY_INVALID_STATE,
        Self::DESTINATION_DISABLED,
        Self::DESTINATION_NAME_CONFLICT,
        Self::INVALID_IDENTITY_TOKEN,
        Self::EXPIRED_IDENTITY_TOKEN,
        Self::IDENTITY_TOKEN_SCOPE_MISMATCH,
    ];

    /// The wire representation, as it appears in the `error` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}
