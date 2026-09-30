use rust_filelocker::vault::{self, VaultPayload};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

/// Helper to create a temp directory with a test file inside.
/// Returns (temp_dir_path, input_file_path).
fn setup_test_file(content: &[u8]) -> (PathBuf, PathBuf) {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let file_path = temp_dir.join("test_input.txt");
    let mut file = std::fs::File::create(&file_path).unwrap();
    file.write_all(content).unwrap();
    (temp_dir, file_path)
}

#[test]
fn test_lock_unlock_file_roundtrip() {
    let original_content = b"Hello, secure world! This is a test file for encryption.".to_vec();
    let (temp_dir, input_path) = setup_test_file(&original_content);

    let lock_path = temp_dir.join("test_input.txt.lock");
    let password = "test_password_123";

    // Lock the file.
    vault::lock_file(&input_path, &lock_path, password).unwrap();

    // Verify the .lock file exists and has content.
    let encrypted_data = std::fs::read(&lock_path).unwrap();
    assert!(
        encrypted_data.len() > rust_filelocker::crypto::HEADER_SIZE,
        "Encrypted payload should be at least header size ({} bytes)",
        rust_filelocker::crypto::HEADER_SIZE
    );

    // Unlock to a new directory.
    let unlock_dir = temp_dir.join("unlocked");
    vault::unlock_file(&lock_path, &unlock_dir, password).unwrap();

    // Verify the restored file matches the original exactly.
    // The restored filename comes from the original file's basename.
    let restored_path = unlock_dir.join("test_input.txt");
    let restored_content = std::fs::read(&restored_path).unwrap();
    assert_eq!(
        restored_content, original_content,
        "Restored file content must match the original exactly"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_lock_unlock_binary_file() {
    // Create a binary file with various byte values (0-255).
    let original_content: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let (temp_dir, input_path) = setup_test_file(&original_content);

    let lock_path = temp_dir.join("binary_test.bin.lock");
    let password = "binary_test_password";

    // Lock the binary file.
    vault::lock_file(&input_path, &lock_path, password).unwrap();

    // Unlock to a new directory.
    let unlock_dir = temp_dir.join("unlocked_binary");
    vault::unlock_file(&lock_path, &unlock_dir, password).unwrap();

    // Verify the restored binary file matches the original exactly.
    // The restored filename comes from the original file's basename (test_input.txt).
    let restored_path = unlock_dir.join("test_input.txt");
    let restored_content = std::fs::read(&restored_path).unwrap();
    assert_eq!(
        restored_content, original_content,
        "Restored binary file content must match the original exactly"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wrong_password_fails_lock() {
    let original_content = b"Secret data".to_vec();
    let (temp_dir, input_path) = setup_test_file(&original_content);

    let lock_path = temp_dir.join("test.lock");
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    // Lock with correct password.
    vault::lock_file(&input_path, &lock_path, correct_password).unwrap();

    // Unlock with wrong password should fail.
    let unlock_dir = temp_dir.join("unlocked_wrong");
    let result = vault::unlock_file(&lock_path, &unlock_dir, wrong_password);
    assert!(
        result.is_err(),
        "Unlocking with wrong password should return an error"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_vault_payload_serialization() {
    // Test File variant serialization.
    let file_payload = VaultPayload::File {
        filename: "document.pdf".to_string(),
        data: vec![0x00, 0x01, 0x02, 0x03],
    };
    let serialized = file_payload.to_bytes().unwrap();
    let deserialized = VaultPayload::from_bytes(&serialized).unwrap();

    match (file_payload, deserialized) {
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

    // Test Secrets variant serialization.
    let mut secrets = BTreeMap::new();
    secrets.insert("API_KEY".to_string(), "sk-1234567890".to_string());
    secrets.insert("DB_PASSWORD".to_string(), "super_secret".to_string());
    secrets.insert(
        "ENDPOINT".to_string(),
        "https://api.example.com".to_string(),
    );

    let secrets_payload = VaultPayload::Secrets { items: secrets };
    let serialized = secrets_payload.to_bytes().unwrap();
    let deserialized = VaultPayload::from_bytes(&serialized).unwrap();

    match (secrets_payload, deserialized) {
        (VaultPayload::Secrets { items: i1 }, VaultPayload::Secrets { items: i2 }) => {
            assert_eq!(i1, i2);
        }
        _ => panic!("Expected Secrets variant"),
    }
}

#[test]
fn test_empty_file_lock_unlock() {
    // Test with an empty file.
    let original_content: Vec<u8> = vec![];
    let (temp_dir, input_path) = setup_test_file(&original_content);

    let lock_path = temp_dir.join("empty.lock");
    let password = "empty_file_password";

    // Lock the empty file.
    vault::lock_file(&input_path, &lock_path, password).unwrap();

    // Unlock to a new directory.
    let unlock_dir = temp_dir.join("unlocked_empty");
    vault::unlock_file(&lock_path, &unlock_dir, password).unwrap();

    // Verify the restored file is also empty.
    let restored_path = unlock_dir.join("test_input.txt");
    let restored_content = std::fs::read(&restored_path).unwrap();
    assert_eq!(
        restored_content, original_content,
        "Restored empty file should be empty"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ====== Secret Management Integration Tests ======

#[test]
fn test_set_and_get_secret() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_secret_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let password = "secret_vault_password";

    // Set a secret
    vault::set_secret(&vault_path, "API_KEY", "sk-1234567890", password).unwrap();
    assert!(
        vault_path.exists(),
        "Vault file should exist after setting secret"
    );

    // Get the secret back
    let result = vault::get_secret(&vault_path, "API_KEY", password).unwrap();
    assert_eq!(
        result,
        Some("sk-1234567890".to_string()),
        "Retrieved secret should match the set value"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_set_multiple_secrets() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_secrets_multi_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let password = "multi_secret_password";

    // Set multiple secrets
    vault::set_secret(&vault_path, "DB_PASSWORD", "db_pass_123", password).unwrap();
    vault::set_secret(&vault_path, "API_KEY", "sk-abc123", password).unwrap();
    vault::set_secret(&vault_path, "ENDPOINT", "https://api.example.com", password).unwrap();

    // Verify each secret
    assert_eq!(
        vault::get_secret(&vault_path, "DB_PASSWORD", password).unwrap(),
        Some("db_pass_123".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "API_KEY", password).unwrap(),
        Some("sk-abc123".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "ENDPOINT", password).unwrap(),
        Some("https://api.example.com".to_string())
    );

    // Verify non-existent key returns None
    let result = vault::get_secret(&vault_path, "NONEXISTENT", password).unwrap();
    assert_eq!(result, None);

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_update_secret() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_secret_update_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let password = "update_secret_password";

    // Set initial secret
    vault::set_secret(&vault_path, "API_KEY", "original_key", password).unwrap();
    assert_eq!(
        vault::get_secret(&vault_path, "API_KEY", password).unwrap(),
        Some("original_key".to_string())
    );

    // Update the secret
    vault::set_secret(&vault_path, "API_KEY", "new_key", password).unwrap();
    assert_eq!(
        vault::get_secret(&vault_path, "API_KEY", password).unwrap(),
        Some("new_key".to_string())
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_remove_secret() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_secret_remove_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let password = "remove_secret_password";

    // Set secrets
    vault::set_secret(&vault_path, "KEY_ONE", "value_one", password).unwrap();
    vault::set_secret(&vault_path, "KEY_TWO", "value_two", password).unwrap();

    // Verify both exist
    assert!(vault::get_secret(&vault_path, "KEY_ONE", password)
        .unwrap()
        .is_some());
    assert!(vault::get_secret(&vault_path, "KEY_TWO", password)
        .unwrap()
        .is_some());

    // Remove one
    let removed = vault::remove_secret(&vault_path, "KEY_ONE", password).unwrap();
    assert!(removed, "remove_secret should return true for existing key");

    // Verify it's removed
    assert_eq!(
        vault::get_secret(&vault_path, "KEY_ONE", password).unwrap(),
        None,
        "Removed key should return None"
    );

    // Verify the other still exists
    assert_eq!(
        vault::get_secret(&vault_path, "KEY_TWO", password).unwrap(),
        Some("value_two".to_string())
    );

    // Try to remove non-existent key
    let removed_again = vault::remove_secret(&vault_path, "KEY_ONE", password).unwrap();
    assert!(
        !removed_again,
        "remove_secret should return false for non-existent key"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_import_env_file() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_env_import_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let env_path = temp_dir.join("test.env");
    let vault_path = temp_dir.join("secrets.lock");
    let password = "env_import_password";

    // Create a .env file
    let env_content = r#"# Database configuration
DB_HOST="localhost"
DB_PORT=5432
DB_USER=admin
DB_PASSWORD="super_secret"

# API Key
API_KEY=sk-test-12345
"#
    .to_string();
    std::fs::write(&env_path, env_content).unwrap();

    // Import the .env file into the vault
    vault::import_env(&env_path, &vault_path, password).unwrap();
    assert!(vault_path.exists(), "Vault file should exist after import");

    // Verify all secrets were imported
    assert_eq!(
        vault::get_secret(&vault_path, "DB_HOST", password).unwrap(),
        Some("localhost".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "DB_PORT", password).unwrap(),
        Some("5432".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "DB_USER", password).unwrap(),
        Some("admin".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "DB_PASSWORD", password).unwrap(),
        Some("super_secret".to_string())
    );
    assert_eq!(
        vault::get_secret(&vault_path, "API_KEY", password).unwrap(),
        Some("sk-test-12345".to_string())
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_export_env_file() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_env_export_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let env_path = temp_dir.join("exported.env");
    let password = "env_export_password";

    // Create a vault with secrets
    vault::set_secret(&vault_path, "DB_HOST", "production.example.com", password).unwrap();
    vault::set_secret(&vault_path, "DB_PORT", "5432", password).unwrap();
    vault::set_secret(&vault_path, "API_KEY", "sk-exported-key", password).unwrap();

    // Export to .env file
    vault::export_env(&vault_path, &env_path, password).unwrap();
    assert!(env_path.exists(), "Exported .env file should exist");

    // Verify the exported .env file content
    let exported_content = std::fs::read_to_string(&env_path).unwrap();
    assert!(
        exported_content.contains("DB_HOST"),
        "Exported file should contain DB_HOST"
    );
    assert!(
        exported_content.contains("production.example.com"),
        "Exported file should contain DB_HOST value"
    );
    assert!(
        exported_content.contains("DB_PORT"),
        "Exported file should contain DB_PORT"
    );
    assert!(
        exported_content.contains("API_KEY"),
        "Exported file should contain API_KEY"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_import_export_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_env_roundtrip_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let original_env_path = temp_dir.join("original.env");
    let vault_path = temp_dir.join("secrets.lock");
    let exported_env_path = temp_dir.join("exported.env");
    let password = "roundtrip_password";

    // Create original .env file
    let env_content = r#"# Original environment file
SECRET_KEY=my_secret_value
ANOTHER_KEY=another_value
"#
    .to_string();
    std::fs::write(&original_env_path, env_content).unwrap();

    // Import into vault
    vault::import_env(&original_env_path, &vault_path, password).unwrap();

    // Export from vault
    vault::export_env(&vault_path, &exported_env_path, password).unwrap();

    // Import the exported file into vault again
    let vault_path_2 = temp_dir.join("secrets2.lock");
    vault::import_env(&exported_env_path, &vault_path_2, password).unwrap();

    // Verify secrets match
    assert_eq!(
        vault::get_secret(&vault_path, "SECRET_KEY", password).unwrap(),
        vault::get_secret(&vault_path_2, "SECRET_KEY", password).unwrap()
    );
    assert_eq!(
        vault::get_secret(&vault_path, "ANOTHER_KEY", password).unwrap(),
        vault::get_secret(&vault_path_2, "ANOTHER_KEY", password).unwrap()
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_secret_wrong_password_fails() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_secret_wrong_pass_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let vault_path = temp_dir.join("secrets.lock");
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    // Set a secret
    vault::set_secret(&vault_path, "MY_KEY", "my_value", correct_password).unwrap();

    // Get with wrong password should fail
    let result = vault::get_secret(&vault_path, "MY_KEY", wrong_password);
    assert!(
        result.is_err(),
        "Getting secret with wrong password should fail"
    );

    // Remove with wrong password should fail
    let remove_result = vault::remove_secret(&vault_path, "MY_KEY", wrong_password);
    assert!(
        remove_result.is_err(),
        "Removing secret with wrong password should fail"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cannot_modify_secrets_in_file_vault() {
    let temp_dir = std::env::temp_dir().join(format!(
        "rust_filelocker_file_vault_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let input_path = temp_dir.join("testfile.txt");
    let vault_path = temp_dir.join("file.lock");
    let password = "file_vault_password";

    // Create a test file and lock it as a file vault
    std::fs::write(&input_path, b"test file content").unwrap();
    vault::lock_file(&input_path, &vault_path, password).unwrap();

    // Try to set a secret in the file vault
    let result = vault::set_secret(&vault_path, "MY_KEY", "my_value", password);
    assert!(result.is_err(), "Setting secret in file vault should fail");

    // Try to get a secret from the file vault
    let get_result = vault::get_secret(&vault_path, "MY_KEY", password);
    assert!(
        get_result.is_err(),
        "Getting secret from file vault should fail"
    );

    // Try to remove a secret from the file vault
    let remove_result = vault::remove_secret(&vault_path, "MY_KEY", password);
    assert!(
        remove_result.is_err(),
        "Removing secret from file vault should fail"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_large_file_lock_unlock() {
    // Test with a larger file (1 MB).
    let original_content = vec![0xAB; 1_000_000];
    let (temp_dir, input_path) = setup_test_file(&original_content);

    let lock_path = temp_dir.join("large_file.lock");
    let password = "large_file_password";

    // Lock the large file.
    vault::lock_file(&input_path, &lock_path, password).unwrap();

    // Unlock to a new directory.
    let unlock_dir = temp_dir.join("unlocked_large");
    vault::unlock_file(&lock_path, &unlock_dir, password).unwrap();

    // Verify the restored file matches the original exactly.
    let restored_path = unlock_dir.join("test_input.txt");
    let restored_content = std::fs::read(&restored_path).unwrap();
    assert_eq!(
        restored_content, original_content,
        "Restored large file content must match the original exactly"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}
