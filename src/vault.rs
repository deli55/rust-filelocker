use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

use crate::crypto;

/// Errors that can occur during vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Failed to read/write file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Password mismatch: passwords do not match")]
    PasswordMismatch,
}

impl From<crypto::CryptoError> for VaultError {
    fn from(e: crypto::CryptoError) -> Self {
        match e {
            crypto::CryptoError::Encryption(msg) => VaultError::Encryption(msg),
            crypto::CryptoError::Decryption(msg) => VaultError::Decryption(msg),
            crypto::CryptoError::KeyDerivation(msg) => VaultError::Decryption(msg),
            _ => VaultError::Decryption(e.to_string()),
        }
    }
}

/// A vault payload that can hold either an arbitrary file or a set of secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultPayload {
    /// An arbitrary file with its original filename and raw bytes.
    File {
        /// The original filename (basename) of the encrypted file.
        filename: String,
        /// The raw file data.
        data: Vec<u8>,
    },
    /// A collection of key-value secrets (e.g. API keys, environment variables).
    Secrets {
        /// A sorted map of secret names to their values.
        items: BTreeMap<String, String>,
    },
}

impl VaultPayload {
    /// Serialize this payload to bytes using JSON.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    /// Deserialize a payload from bytes using JSON.
    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        serde_json::from_slice(data).map_err(|e| VaultError::Serialization(e.to_string()))
    }
}

/// Prompt for a password with confirmation validation.
/// Returns the validated password or an error if the passwords don't match.
/// Prompt for a password with confirmation validation.
pub fn prompt_password_with_confirmation() -> Result<String, VaultError> {
    loop {
        print!("Enter password: ");
        std::io::Write::flush(&mut std::io::stdout()).map_err(VaultError::Io)?;
        let password1 = rpassword::read_password().map_err(VaultError::Io)?;

        print!("Confirm password: ");
        std::io::Write::flush(&mut std::io::stdout()).map_err(VaultError::Io)?;
        let password2 = rpassword::read_password().map_err(VaultError::Io)?;

        if password1 == password2 {
            return Ok(password1);
        }
        eprintln!("Error: Passwords do not match. Please try again.");
    }
}

/// Prompt for a single password (no confirmation).
pub fn prompt_password() -> Result<String, VaultError> {
    print!("Enter password: ");
    std::io::Write::flush(&mut std::io::stdout()).map_err(VaultError::Io)?;
    let password = rpassword::read_password().map_err(VaultError::Io)?;
    Ok(password)
}

/// Lock an arbitrary file into a `.lock` container.
///
/// Reads the file at `input_path`, constructs a `VaultPayload::File`,
/// serializes it to JSON, encrypts via `crypto::encrypt_payload`,
/// and writes the resulting binary payload to `output_path`.
pub fn lock_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), VaultError> {
    // Read the target file bytes.
    let data = std::fs::read(input_path)?;

    // Extract the filename (basename) from the input path.
    let filename = input_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| {
            VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid input path: no filename component",
            ))
        })?;

    // Construct the vault payload.
    let payload = VaultPayload::File { filename, data };

    // Serialize the payload to JSON bytes.
    let serialized = payload.to_bytes()?;

    // Encrypt the serialized payload.
    let encrypted = crypto::encrypt_payload(&serialized, password)?;

    // Write the encrypted payload to the output file.
    std::fs::write(output_path, &encrypted)?;

    println!("Successfully locked file: {}", input_path.display());
    println!("Output written to: {}", output_path.display());
    Ok(())
}

/// Unlock a `.lock` container and restore the file to disk.
///
/// Reads the `.lock` file at `input_path`, decrypts via
/// `crypto::decrypt_payload`, deserializes the `VaultPayload`,
/// and writes the restored file back to `output_dir/filename`.
pub fn unlock_file(input_path: &Path, output_dir: &Path, password: &str) -> Result<(), VaultError> {
    // Read the encrypted payload.
    let encrypted = std::fs::read(input_path)?;

    // Decrypt the payload.
    let decrypted = crypto::decrypt_payload(&encrypted, password)?;

    // Deserialize the vault payload from JSON.
    let payload = VaultPayload::from_bytes(&decrypted)?;

    // Ensure the output directory exists.
    std::fs::create_dir_all(output_dir)?;

    match payload {
        VaultPayload::File { filename, data } => {
            let output_path = output_dir.join(filename);
            std::fs::write(&output_path, data)?;
            println!("Successfully unlocked file: {}", output_path.display());
        }
        VaultPayload::Secrets { items } => {
            // For secrets, write a JSON file with the decrypted data.
            let output_path = output_dir.join("secrets.json");
            let json_data = serde_json::to_string_pretty(&items)
                .map_err(|e| VaultError::Serialization(e.to_string()))?;
            std::fs::write(&output_path, json_data)?;
            println!(
                "Successfully unlocked secrets: {} items written to {}",
                items.len(),
                output_path.display()
            );
        }
    }

    Ok(())
}

/// List the contents of a `.lock` container without fully restoring it.
///
/// Decrypts the payload and displays entry metadata:
/// - For files: filename and size in bytes.
/// - For secrets: key names (without values).
pub fn list_contents(input_path: &Path, password: &str) -> Result<(), VaultError> {
    // Read the encrypted payload.
    let encrypted = std::fs::read(input_path)?;

    // Decrypt the payload.
    let decrypted = crypto::decrypt_payload(&encrypted, password)?;

    // Deserialize the vault payload from JSON.
    let payload = VaultPayload::from_bytes(&decrypted)?;

    match payload {
        VaultPayload::File { filename, data } => {
            println!("Type: File");
            println!("Filename: {}", filename);
            println!("Size: {} bytes", data.len());
        }
        VaultPayload::Secrets { items } => {
            println!("Type: Secrets ({} items)", items.len());
            for key in items.keys() {
                println!("  - {}", key);
            }
        }
    }

    Ok(())
}

/// Load an existing vault file or create a new empty secrets payload.
/// Returns the decrypted payload.
fn load_or_create_secrets_vault(
    vault_path: &Path,
    password: &str,
) -> Result<VaultPayload, VaultError> {
    if vault_path.exists() {
        let encrypted = std::fs::read(vault_path)?;
        let decrypted = crypto::decrypt_payload(&encrypted, password)?;
        let payload = VaultPayload::from_bytes(&decrypted)?;
        match payload {
            VaultPayload::Secrets { .. } => Ok(payload),
            VaultPayload::File { .. } => {
                Err(VaultError::Decryption("Vault file contains a file payload, not secrets. Cannot modify secrets in a file vault.".to_string()))
            }
        }
    } else {
        let items = BTreeMap::new();
        Ok(VaultPayload::Secrets { items })
    }
}

/// Encrypt and save a secrets vault to disk.
fn save_secrets_vault(
    vault_path: &Path,
    payload: &VaultPayload,
    password: &str,
) -> Result<(), VaultError> {
    let serialized = payload.to_bytes()?;
    let encrypted = crypto::encrypt_payload(&serialized, password)?;
    std::fs::write(vault_path, &encrypted)?;
    Ok(())
}

/// Set a secret in a secrets vault.
///
/// Reads and decrypts the existing `.lock` file (or creates a new `VaultPayload::Secrets`
/// if the file does not exist). Ensures the payload is `VaultPayload::Secrets`
/// (returns an error if trying to modify a file vault). Inserts or updates the
/// `key` -> `value` in the `BTreeMap`, then encrypts and writes back to disk.
pub fn set_secret(
    vault_path: &Path,
    key: &str,
    value: &str,
    password: &str,
) -> Result<(), VaultError> {
    let payload = load_or_create_secrets_vault(vault_path, password)?;

    match payload {
        VaultPayload::Secrets { items } => {
            let mut items = items;
            items.insert(key.to_string(), value.to_string());
            let new_payload = VaultPayload::Secrets { items };
            save_secrets_vault(vault_path, &new_payload, password)?;
            println!("Successfully set secret: {}", key);
        }
        VaultPayload::File { filename, data: _ } => {
            return Err(VaultError::Decryption(format!(
                "Vault file '{}' contains a file payload (\"{}\"), not secrets. Cannot set secret in a file vault.",
                vault_path.display(),
                filename
            )));
        }
    }

    Ok(())
}

/// Get a secret from a secrets vault.
///
/// Decrypts the vault payload and retrieves the value for the given key from
/// `VaultPayload::Secrets`. Returns `Some(value)` if the key exists, or `None`
/// if the key does not exist.
pub fn get_secret(
    vault_path: &Path,
    key: &str,
    password: &str,
) -> Result<Option<String>, VaultError> {
    let encrypted = std::fs::read(vault_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => VaultError::Decryption(format!(
            "Vault file '{}' does not exist.",
            vault_path.display()
        )),
        _ => VaultError::Io(e),
    })?;

    let decrypted = crypto::decrypt_payload(&encrypted, password)?;
    let payload = VaultPayload::from_bytes(&decrypted)?;

    match payload {
        VaultPayload::Secrets { items } => Ok(items.get(key).cloned()),
        VaultPayload::File { filename, data: _ } => Err(VaultError::Decryption(format!(
            "Vault file '{}' contains a file payload (\"{}\"), not secrets.",
            vault_path.display(),
            filename
        ))),
    }
}

/// Get a secret from a secrets vault with zeroizing memory safety.
///
/// Like `get_secret` but returns `Zeroizing<String>` so the secret value is
/// automatically zeroed in memory when dropped. This is the recommended way
/// to retrieve sensitive credentials.
pub fn get_secret_zeroizing(
    vault_path: &Path,
    key: &str,
    password: &str,
) -> Result<Option<Zeroizing<String>>, VaultError> {
    let encrypted = std::fs::read(vault_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => VaultError::Decryption(format!(
            "Vault file '{}' does not exist.",
            vault_path.display()
        )),
        _ => VaultError::Io(e),
    })?;

    let decrypted = crypto::decrypt_payload(&encrypted, password)?;
    let payload = VaultPayload::from_bytes(&decrypted)?;

    match payload {
        VaultPayload::Secrets { items } => Ok(items.get(key).cloned().map(Zeroizing::new)),
        VaultPayload::File { filename, data: _ } => Err(VaultError::Decryption(format!(
            "Vault file '{}' contains a file payload (\"{}\"), not secrets.",
            vault_path.display(),
            filename
        ))),
    }
}

/// Remove a secret from a secrets vault.
///
/// Decrypts the vault, removes the key from `VaultPayload::Secrets` map,
/// and saves the vault back to disk. Returns `true` if the key was found and removed.
pub fn remove_secret(vault_path: &Path, key: &str, password: &str) -> Result<bool, VaultError> {
    let payload = load_or_create_secrets_vault(vault_path, password)?;

    match payload {
        VaultPayload::Secrets { mut items } => match items.remove(key) {
            Some(_) => {
                let new_payload = VaultPayload::Secrets { items };
                save_secrets_vault(vault_path, &new_payload, password)?;
                println!("Successfully removed secret: {}", key);
                Ok(true)
            }
            None => {
                println!("Secret not found: {}", key);
                Ok(false)
            }
        },
        VaultPayload::File { filename, data: _ } => Err(VaultError::Decryption(format!(
            "Vault file '{}' contains a file payload (\"{}\"), not secrets.",
            vault_path.display(),
            filename
        ))),
    }
}

/// Import secrets from a `.env` file into a secrets vault.
///
/// Parses `.env` lines (`KEY=VALUE`) into `VaultPayload::Secrets` and encrypts
/// the result to the vault file. Skips empty lines and lines starting with `#`.
pub fn import_env(env_path: &Path, vault_path: &Path, password: &str) -> Result<(), VaultError> {
    let contents = std::fs::read_to_string(env_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Environment file '{}' not found.", env_path.display()),
        )),
        _ => VaultError::Io(e),
    })?;

    let payload = load_or_create_secrets_vault(vault_path, password)?;

    match payload {
        VaultPayload::Secrets { mut items } => {
            for line in contents.lines() {
                let line = line.trim();
                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Parse KEY=VALUE format
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim();
                    let value = line[eq_pos + 1..].trim();

                    // Handle quoted values (remove surrounding quotes)
                    let value = value.trim_matches(|c| c == '"' || c == '\'');

                    if !key.is_empty() {
                        items.insert(key.to_string(), value.to_string());
                    }
                }
            }

            let new_payload = VaultPayload::Secrets { items };
            save_secrets_vault(vault_path, &new_payload, password)?;
            println!("Successfully imported secrets from: {}", env_path.display());
            Ok(())
        }
        VaultPayload::File { filename, data: _ } => Err(VaultError::Decryption(format!(
            "Vault file '{}' contains a file payload (\"{}\"), not secrets.",
            vault_path.display(),
            filename
        ))),
    }
}

/// Export secrets from a secrets vault to a `.env` file.
///
/// Decrypts the vault and writes out formatted `.env` lines (`KEY=VALUE`)
/// to the specified output path.
pub fn export_env(vault_path: &Path, env_path: &Path, password: &str) -> Result<(), VaultError> {
    let encrypted = std::fs::read(vault_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => VaultError::Decryption(format!(
            "Vault file '{}' does not exist.",
            vault_path.display()
        )),
        _ => VaultError::Io(e),
    })?;

    let decrypted = crypto::decrypt_payload(&encrypted, password)?;
    let payload = VaultPayload::from_bytes(&decrypted)?;

    match payload {
        VaultPayload::Secrets { items } => {
            // Ensure the output directory exists
            if let Some(parent) = env_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut env_content = String::new();
            for (key, value) in &items {
                // Use quotes to handle values that may contain special characters
                env_content.push_str(&format!("{}=\"{}\"\n", key, value));
            }

            std::fs::write(env_path, &env_content)?;
            println!(
                "Successfully exported {} secrets to: {}",
                items.len(),
                env_path.display()
            );
            Ok(())
        }
        VaultPayload::File { filename, data: _ } => Err(VaultError::Decryption(format!(
            "Vault file '{}' contains a file payload (\"{}\"), not secrets.",
            vault_path.display(),
            filename
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_payload_file_serialization() {
        let payload = VaultPayload::File {
            filename: "test.txt".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };
        let bytes = payload.to_bytes().unwrap();
        let restored = VaultPayload::from_bytes(&bytes).unwrap();

        match (payload, restored) {
            (
                VaultPayload::File {
                    filename: f1,
                    data: d1,
                },
                VaultPayload::File {
                    filename: f2,
                    data: d2,
                },
            ) => {
                assert_eq!(f1, f2);
                assert_eq!(d1, d2);
            }
            _ => panic!("Expected File variant"),
        }
    }

    #[test]
    fn test_vault_payload_secrets_serialization() {
        let mut items = BTreeMap::new();
        items.insert("API_KEY".to_string(), "secret123".to_string());
        items.insert("DB_PASSWORD".to_string(), "password456".to_string());

        let payload = VaultPayload::Secrets { items };
        let bytes = payload.to_bytes().unwrap();
        let restored = VaultPayload::from_bytes(&bytes).unwrap();

        match (payload, restored) {
            (VaultPayload::Secrets { items: i1 }, VaultPayload::Secrets { items: i2 }) => {
                assert_eq!(i1, i2);
            }
            _ => panic!("Expected Secrets variant"),
        }
    }

    #[test]
    fn test_lock_unlock_roundtrip() {
        // Create a temporary test file.
        let temp_dir = std::env::temp_dir().join("rust_filelocker_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let input_path = temp_dir.join("testfile.txt");
        let output_path = temp_dir.join("testfile.lock");
        let unlock_dir = temp_dir.join("unlocked");

        let original_content = b"Hello, secure world!";
        std::fs::write(&input_path, original_content).unwrap();

        let password = "test_password_123";

        // Lock the file.
        lock_file(&input_path, &output_path, password).unwrap();

        // Verify .lock file exists and has content.
        let encrypted_data = std::fs::read(&output_path).unwrap();
        assert!(encrypted_data.len() > crate::crypto::HEADER_SIZE);

        // Unlock the file.
        unlock_file(&output_path, &unlock_dir, password).unwrap();

        // Verify the restored file matches the original.
        let restored_path = unlock_dir.join("testfile.txt");
        let restored_content = std::fs::read(&restored_path).unwrap();
        assert_eq!(restored_content, original_content);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_list_contents_file() {
        let temp_dir = std::env::temp_dir().join("rust_filelocker_test_list");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let input_path = temp_dir.join("testfile.txt");
        let output_path = temp_dir.join("testfile.lock");

        let original_content = b"Hello, secure world!";
        std::fs::write(&input_path, original_content).unwrap();

        let password = "test_password_123";

        // Lock the file.
        lock_file(&input_path, &output_path, password).unwrap();

        // List contents.
        let result = std::panic::catch_unwind(|| list_contents(&output_path, password));
        assert!(result.is_ok());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wrong_password_fails() {
        let temp_dir = std::env::temp_dir().join("rust_filelocker_test_wrong");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let input_path = temp_dir.join("testfile.txt");
        let output_path = temp_dir.join("testfile.lock");

        let original_content = b"Secret data";
        std::fs::write(&input_path, original_content).unwrap();

        let correct_password = "correct_password";
        let wrong_password = "wrong_password";

        // Lock with correct password.
        lock_file(&input_path, &output_path, correct_password).unwrap();

        // Unlock with wrong password should fail.
        let unlock_dir = temp_dir.join("unlocked");
        let result = unlock_file(&output_path, &unlock_dir, wrong_password);
        assert!(result.is_err());

        // List with wrong password should fail.
        let list_result = list_contents(&output_path, wrong_password);
        assert!(list_result.is_err());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
