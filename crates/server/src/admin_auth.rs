use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Clone)]
pub struct AdminAuthenticator {
    digest: [u8; 32],
}

impl AdminAuthenticator {
    pub fn new(credential: &str) -> Result<Self, AdminCredentialError> {
        if credential.trim() != credential || !(32..=512).contains(&credential.len()) {
            return Err(AdminCredentialError::InvalidFormat);
        }
        Ok(Self {
            digest: Sha256::digest(credential.as_bytes()).into(),
        })
    }

    pub fn authenticate(&self, credential: &str) -> bool {
        let candidate: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        self.digest.ct_eq(&candidate).into()
    }
}

impl fmt::Debug for AdminAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminAuthenticator")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AdminCredentialError {
    #[error("admin credential must contain between 32 and 512 non-whitespace-surrounded bytes")]
    InvalidFormat,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_redacts_admin_credentials() {
        let plaintext = "a-valid-admin-credential-with-32-bytes";
        let authenticator = AdminAuthenticator::new(plaintext).unwrap();
        assert!(authenticator.authenticate(plaintext));
        assert!(!authenticator.authenticate("another-valid-admin-credential-value"));
        assert!(!format!("{authenticator:?}").contains(plaintext));
    }

    #[test]
    fn rejects_unsafe_admin_credentials() {
        for credential in ["", "short", " surrounded-by-whitespace-and-long-enough "] {
            assert_eq!(
                AdminAuthenticator::new(credential).unwrap_err(),
                AdminCredentialError::InvalidFormat
            );
        }
    }
}
