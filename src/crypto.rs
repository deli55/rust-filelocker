use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroizing;

/// Magic bytes that identify a valid RFLK vault header.
pub const RFLK_MAGIC: &[u8; 4] = b"RFLK";

/// Current file format version.
pub const RFLK_VERSION: u8 = 1;

/// Salt size in bytes (256-bit / 32 bytes).
pub const SALT_SIZE: usize = 32;

/// Nonce size in bytes (96-bit / 12 bytes) for AES-GCM.
pub const NONCE_SIZE: usize = 12;

/// Key size in bytes (256-bit / 32 bytes) for AES-256.
pub const KEY_SIZE: usize = 32;

/// Header layout in the binary payload:
/// - Magic (4 bytes)
/// - Version (1 byte)
/// - Salt (32 bytes)
/// - Nonce (12 bytes)
///
/// Total header size: 49 bytes.
pub const HEADER_SIZE: usize = 4 + 1 + 32 + 12;

/// Represents the header of a RFLK encrypted vault.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Magic bytes identifying the format.
    pub magic: [u8; 4],
    /// Format version.
    pub version: u8,
    /// Salt used for key derivation.
    pub salt: [u8; 32],
    /// Nonce used for AES-256-GCM encryption.
    pub nonce: [u8; 12],
}

impl VaultHeader {
    /// Generate a new header with random salt and nonce.
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut rng = OsRng;

        rng.fill(&mut salt);
        rng.fill(&mut nonce);

        Self {
            magic: *RFLK_MAGIC,
            version: RFLK_VERSION,
            salt,
            nonce,
        }
    }

    /// Serialize this header into a byte buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Parse a header from raw bytes.
    /// Returns an error if the magic bytes do not match or the version is unsupported.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < HEADER_SIZE {
            return Err(CryptoError::HeaderTooShort);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != *RFLK_MAGIC {
            return Err(CryptoError::InvalidMagic(magic));
        }

        let version = data[4];
        if version != RFLK_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[5..37]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[37..49]);

        Ok(Self {
            magic,
            version,
            salt,
            nonce,
        })
    }
}

impl Default for VaultHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a 256-bit key from a password and salt using Argon2id.
///
/// Uses Argon2id with the default recommended parameters:
/// - memory: 64 MiB
/// - iterations: 3
/// - parallelism: 4
pub fn derive_key(password: &str, salt: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let argon2 = Argon2::default();

    // Argon2id produces a 32-byte (256-bit) key.
    let mut key = Zeroizing::new(vec![0u8; KEY_SIZE]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

/// Encrypt plaintext bytes using the given password.
///
/// Generates a new random salt and nonce, derives a key via Argon2id,
/// encrypts the payload with AES-256-GCM, and returns a binary payload
/// consisting of the serialized header followed by the ciphertext.
pub fn encrypt_payload(plaintext: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    // Generate header with random salt and nonce.
    let header = VaultHeader::new();

    // Derive the encryption key.
    let key = derive_key(password, &header.salt)?;

    // Initialize AES-256-GCM from the derived key bytes.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));

    // Prepare the nonce (exactly 12 bytes for AES-GCM).
    let nonce = Nonce::from_exact_iter(header.nonce.iter().copied())
        .ok_or_else(|| CryptoError::NonceError("Invalid nonce length".to_string()))?;

    // Encrypt the payload.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    // Serialize: header + ciphertext.
    let mut payload = header.to_bytes();
    payload.extend_from_slice(&ciphertext);

    Ok(payload)
}

/// Decrypt a binary payload using the given password.
///
/// Parses the header (validating magic bytes and version), extracts the
/// salt and nonce, derives the key via Argon2id, and decrypts/authenticates
/// the ciphertext using AES-256-GCM. Returns the decrypted plaintext or an error.
pub fn decrypt_payload(payload: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    // Parse the header.
    let header = VaultHeader::from_bytes(payload)?;

    // Derive the key using the salt from the header.
    let key = derive_key(password, &header.salt)?;

    // Initialize AES-256-GCM from the derived key bytes.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));

    // Prepare the nonce (exactly 12 bytes for AES-GCM).
    let nonce = Nonce::from_exact_iter(header.nonce.iter().copied())
        .ok_or_else(|| CryptoError::NonceError("Invalid nonce length".to_string()))?;

    // The ciphertext starts after the header.
    let ciphertext = &payload[HEADER_SIZE..];

    // Decrypt and authenticate.
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;

    Ok(plaintext)
}

/// Errors that can occur during cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Header too short: expected at least {HEADER_SIZE} bytes")]
    HeaderTooShort,

    #[error("Invalid magic bytes: expected RFLK, got {:?}", _0)]
    InvalidMagic([u8; 4]),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Nonce error: {0}")]
    NonceError(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed (wrong password or corrupted data): {0}")]
    Decryption(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, secure world! This is a secret message.";
        let password = "super_secret_password_123";

        // Encrypt.
        let payload = encrypt_payload(plaintext, password).expect("Encryption should succeed");

        // Verify header is present.
        assert!(
            payload.len() > HEADER_SIZE,
            "Payload should contain header + ciphertext"
        );

        // Verify magic bytes.
        assert_eq!(&payload[0..4], RFLK_MAGIC);

        // Decrypt.
        let decrypted = decrypt_payload(&payload, password).expect("Decryption should succeed");

        // Verify round-trip.
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_payload() {
        let plaintext: &[u8] = b"";
        let password = "test_password";

        let payload = encrypt_payload(plaintext, password).expect("Encryption should succeed");

        let decrypted = decrypt_payload(&payload, password).expect("Decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let plaintext = vec![0xAB; 1_000_000]; // 1 MB of data
        let password = "password_for_large_file";

        let payload = encrypt_payload(&plaintext, password).expect("Encryption should succeed");

        let decrypted = decrypt_payload(&payload, password).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = b"Secret data that should not be revealed.";
        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        let payload =
            encrypt_payload(plaintext, correct_password).expect("Encryption should succeed");

        // Decryption with wrong password should fail.
        let result = decrypt_payload(&payload, wrong_password);
        assert!(
            result.is_err(),
            "Decryption with wrong password should return an error"
        );
    }

    #[test]
    fn test_invalid_magic_bytes() {
        // Create a payload with invalid magic bytes.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"FAKE"); // Invalid magic.
        payload.push(RFLK_VERSION);
        payload.extend_from_slice(&[0u8; 32]); // Salt.
        payload.extend_from_slice(&[0u8; 12]); // Nonce.

        let result = decrypt_payload(&payload, "any_password");
        assert!(
            result.is_err(),
            "Decryption with invalid magic bytes should return an error"
        );
    }

    #[test]
    fn test_corrupted_header_fails() {
        // Payload shorter than header size.
        let payload = vec![0u8; 20];

        let result = decrypt_payload(&payload, "any_password");
        assert!(
            result.is_err(),
            "Decryption with header too short should return an error"
        );
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let plaintext = b"Sensitive data.";
        let password = "test_password";

        let mut payload = encrypt_payload(plaintext, password).expect("Encryption should succeed");

        // Flip a byte in the ciphertext portion.
        let ciphertext_start = HEADER_SIZE;
        payload[ciphertext_start] ^= 0xFF;

        let result = decrypt_payload(&payload, password);
        assert!(
            result.is_err(),
            "Decryption with corrupted ciphertext should return an error"
        );
    }

    #[test]
    fn test_vault_header_serialization() {
        let header = VaultHeader::new();
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(&bytes[0..4], RFLK_MAGIC);
        assert_eq!(bytes[4], RFLK_VERSION);

        // Round-trip serialization.
        let parsed = VaultHeader::from_bytes(&bytes).expect("Header parsing should succeed");
        assert_eq!(header.magic, parsed.magic);
        assert_eq!(header.version, parsed.version);
        assert_eq!(header.salt, parsed.salt);
        assert_eq!(header.nonce, parsed.nonce);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = "test_password";
        let salt = [0x42u8; 32];

        let key1 = derive_key(password, &salt).expect("Key derivation should succeed");
        let key2 = derive_key(password, &salt).expect("Key derivation should succeed");

        // Same password + salt should produce the same key.
        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn test_different_salt_different_keys() {
        let password = "test_password";
        let salt1 = [0x42u8; 32];
        let salt2 = [0x43u8; 32];

        let key1 = derive_key(password, &salt1).expect("Key derivation should succeed");
        let key2 = derive_key(password, &salt2).expect("Key derivation should succeed");

        // Different salts should produce different keys.
        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn test_unsupported_version() {
        let mut data = Vec::new();
        data.extend_from_slice(RFLK_MAGIC);
        data.push(99); // Unsupported version.
        data.extend_from_slice(&[0u8; 32]); // Salt.
        data.extend_from_slice(&[0u8; 12]); // Nonce.

        let result = VaultHeader::from_bytes(&data);
        assert!(result.is_err());
    }
}
