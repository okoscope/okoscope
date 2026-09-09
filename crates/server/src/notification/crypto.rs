use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SecretVault {
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretVault")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretVaultError {
    #[error("webhook secret encryption failed")]
    Encryption,
    #[error("webhook secret decryption failed")]
    Decryption,
}

impl SecretVault {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }

    #[must_use]
    pub fn generate_secret() -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(bytes.as_mut());
        Zeroizing::new(hex::encode(bytes.as_ref()))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedSecret, SecretVaultError> {
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| SecretVaultError::Encryption)?;
        Ok(EncryptedSecret { ciphertext, nonce })
    }

    pub fn decrypt(
        &self,
        encrypted: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecretVaultError> {
        if nonce.len() != 24 {
            return Err(SecretVaultError::Decryption);
        }
        self.cipher
            .decrypt(XNonce::from_slice(nonce), encrypted)
            .map(Zeroizing::new)
            .map_err(|_| SecretVaultError::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_decrypts_and_rotates_secrets() {
        let vault = SecretVault::new(&[7; 32]);
        let first = SecretVault::generate_secret();
        let encrypted = vault.encrypt(first.as_bytes()).unwrap();
        assert_ne!(encrypted.ciphertext, first.as_bytes());
        assert_eq!(
            vault
                .decrypt(&encrypted.ciphertext, &encrypted.nonce)
                .unwrap()
                .as_slice(),
            first.as_bytes()
        );

        let second = SecretVault::generate_secret();
        assert_ne!(*first, *second);
        let rotated = vault.encrypt(second.as_bytes()).unwrap();
        assert_eq!(
            vault
                .decrypt(&rotated.ciphertext, &rotated.nonce)
                .unwrap()
                .as_slice(),
            second.as_bytes()
        );
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let encrypted = SecretVault::new(&[1; 32]).encrypt(b"secret").unwrap();
        assert_eq!(
            SecretVault::new(&[2; 32]).decrypt(&encrypted.ciphertext, &encrypted.nonce),
            Err(SecretVaultError::Decryption)
        );
    }
}
