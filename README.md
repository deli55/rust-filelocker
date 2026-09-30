# rust-filelocker

A high-security hybrid file locker and zero-trust credential vault built in Rust. Encrypt arbitrary files, manage secrets, and import/export environment variables — all protected by military-grade cryptography.

## Overview

`rust-filelocker` provides two unified capabilities in a single tool:

1. **File Locking** — Encrypt any file into a `.lock` container with a password. Unlock restores the original file with byte-perfect fidelity.
2. **Credential Vault** — Store, retrieve, and manage named secrets (API keys, passwords, environment variables) in an encrypted vault file with fine-grained access.

### Key Features

- **Argon2id** key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- **AES-256-GCM** authenticated encryption (AEAD)
- **Zeroize** memory safety — all sensitive buffers (passwords, derived keys, decrypted payloads, secret values) are automatically zeroed on drop
- Deterministic key derivation — same password + salt always produces the same key
- Binary-safe encryption — handles arbitrary file types including executables and images
- `.env` import/export — migrate environment variables into the vault seamlessly
- Clipboard support — copy secrets to clipboard with automatic memory zeroing

## Security Architecture

### Key Derivation: Argon2id

Passwords are hashed using **Argon2id** (the recommended variant of Argon2) with parameters tuned for memory-hardness:

| Parameter    | Value |
|-------------|-------|
| Memory      | 64 MiB |
| Iterations  | 3     |
| Parallelism | 4     |
| Output      | 32 bytes (256-bit) |

Each vault receives a **cryptographically random 256-bit salt**, ensuring unique keys even for identical passwords.

### Encryption: AES-256-GCM

Payloads are encrypted using **AES-256-GCM** in authenticated mode (AEAD):

- **Key size**: 256 bits (derived from Argon2id output)
- **Nonce size**: 96 bits (random per encryption)
- **Authentication tag**: 128 bits (prevents tampering)

The binary vault format:

```
+--------+---------+--------+---------+-----------+
| MAGIC  | VERSION | SALT   | NONCE   | ciphertext|
| 4 bytes| 1 byte  | 32 bytes| 12 bytes| variable  |
+--------+---------+--------+---------+-----------+
```

### Memory Safety: Zeroize

All sensitive in-memory buffers use [`zeroize::Zeroizing`](https://docs.rs/zeroize/latest/zeroize/), a RAII wrapper that:

1. Overwrites the buffer with zeros via [`zeroize()`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html) when dropped
2. Prevents password/key leakage in memory dumps
3. Clears clipboard buffers after use

**Covered types:**
- Passwords entered via `rpassword`
- Argon2id-derived encryption keys
- Decrypted payload bytes
- Secret values retrieved via `get --clip`

## CLI Usage Reference

### Build

```bash
cargo build --release
```

The binary is produced at `target/release/rust-filelocker.exe` (Windows) or `target/release/rust-filelocker` (Linux/macOS).

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Increase verbosity (can be repeated) |

### `lock` — Encrypt a File

```bash
rust-filelocker lock -i input.txt -o input.txt.lock
```

Prompts for password confirmation, reads `input.txt`, encrypts it, and writes the `.lock` container to `input.txt.lock`.

### `unlock` — Decrypt a File

```bash
rust-filelocker unlock -i input.txt.lock -o ./output_dir/
```

Prompts for the password, decrypts the `.lock` file, and restores the original file(s) to the output directory.

### `list` — Inspect a Vault

```bash
rust-filelocker list -i input.txt.lock
```

Shows the vault type (File/Secrets), filename, size, or secret key names without revealing values.

### `set` — Store a Secret

```bash
# Set with inline value
rust-filelocker set -v vault.lock -k API_KEY -v sk-1234567890

# Set with interactive prompt
rust-filelocker set -v vault.lock -k DB_PASSWORD
Enter secret value:
```

Creates a new secrets vault or appends to an existing one.

### `get` — Retrieve a Secret

```bash
# Print to stdout
rust-filelocker get -v vault.lock -k API_KEY
sk-1234567890

# Copy to clipboard (zeroized after use)
rust-filelocker get -v vault.lock -k DB_PASSWORD --clip
Secret 'DB_PASSWORD' copied to clipboard.
```

### `remove` — Delete a Secret

```bash
rust-filelocker remove -v vault.lock -k OLD_KEY
```

Removes the named secret from the vault and re-encrypts.

### `import-env` — Import from .env File

```bash
rust-filelocker import-env -e .env -v vault.lock
```

Parses `KEY=VALUE` lines from a `.env` file into the vault. Skips comments (`#`) and empty lines. Prompts for password confirmation.

### `export-env` — Export to .env File

```bash
rust-filelocker export-env -v vault.lock -e exported.env
```

Writes all secrets as quoted `.env`-formatted lines to the output file.

## Build & Test Commands

### Compile

```bash
# Development build (faster, debug symbols)
cargo build

# Release build (optimized, smaller binary)
cargo build --release
```

### Test

```bash
# Run all unit and integration tests
cargo test

# Run a specific test
cargo test test_encrypt_decrypt_roundtrip

# Run integration tests only
cargo test --test integration_test
```

### Static Analysis

```bash
# Format check
cargo fmt -- --check

# Linter (clippy)
cargo clippy -- -D warnings

# All checks combined
cargo fmt -- --check && cargo clippy -- -D warnings && cargo test
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `argon2` 0.5 | Argon2id password hashing |
| `aes-gem` 0.10 | AES-256-GCM encryption |
| `zeroize` 1 | Memory zeroing for sensitive data |
| `rand` 0.8 | Cryptographic random number generation |
| `rpassword` 7 | Secure password input (hidden) |
| `arboard` 3 | Cross-platform clipboard access |
| `clap` 4 | Command-line argument parsing |
| `serde` + `serde_json` | JSON serialization for vault payloads |
| `thiserror` | Error derive macro |

## License

MIT
