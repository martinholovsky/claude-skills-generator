# SQLCipher Security Examples

## Key Derivation Implementations

### Argon2id Key Derivation (Recommended)

```rust
use argon2::{Argon2, Algorithm, Version, Params};
use argon2::password_hash::SaltString;
use zeroize::{Zeroize, Zeroizing};
use rand::rngs::OsRng;

pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive database encryption key from user password
    pub fn from_password(
        password: &str,
        stored_salt: Option<&str>
    ) -> Result<(Zeroizing<String>, String), KeyDerivationError> {
        // Use stored salt or generate new one
        let salt = match stored_salt {
            Some(s) => SaltString::from_b64(s)
                .map_err(|_| KeyDerivationError::InvalidSalt)?,
            None => SaltString::generate(&mut OsRng),
        };

        // Configure Argon2id with secure parameters
        let argon2 = Argon2::new(
            Algorithm::Argon2id,  // Hybrid - resistant to side-channel and GPU attacks
            Version::V0x13,
            Params::new(
                65536,   // 64 MB memory cost
                3,       // 3 iterations
                4,       // 4 parallel lanes
                Some(32) // 32 byte (256 bit) output
            ).map_err(|_| KeyDerivationError::InvalidParams)?
        );

        // Derive key bytes
        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key_bytes
        ).map_err(|_| KeyDerivationError::HashFailed)?;

        // Format for SQLCipher (hex blob)
        let key_hex = Zeroizing::new(format!("x'{}'", hex::encode(key_bytes)));

        // Securely zero the raw key bytes
        key_bytes.zeroize();

        Ok((key_hex, salt.as_str().to_string()))
    }

    /// Derive key from hardware token or secure enclave
    pub fn from_hardware_key(
        hardware_key: &[u8],
        context: &str
    ) -> Result<Zeroizing<String>, KeyDerivationError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, hardware_key);
        let mut key_bytes = [0u8; 32];

        hkdf.expand(context.as_bytes(), &mut key_bytes)
            .map_err(|_| KeyDerivationError::HkdfFailed)?;

        let key_hex = Zeroizing::new(format!("x'{}'", hex::encode(key_bytes)));
        key_bytes.zeroize();

        Ok(key_hex)
    }
}

#[derive(Debug)]
pub enum KeyDerivationError {
    InvalidSalt,
    InvalidParams,
    HashFailed,
    HkdfFailed,
}
```

### PBKDF2 Configuration (SQLCipher Native)

```rust
/// Configure SQLCipher's built-in PBKDF2
pub fn configure_pbkdf2(conn: &Connection) -> Result<()> {
    // Set high iteration count for PBKDF2
    // CRITICAL: Default is 256000 in SQLCipher 4, but verify
    conn.pragma_update(None, "kdf_iter", 256000)?;

    // Use PBKDF2-HMAC-SHA512 (default in SQLCipher 4)
    conn.pragma_update(None, "kdf_algorithm", "PBKDF2_HMAC_SHA512")?;

    // Verify settings
    let iter: i32 = conn.pragma_query_value(None, "kdf_iter", |row| row.get(0))?;
    assert!(iter >= 256000, "KDF iterations too low!");

    Ok(())
}
```

---

## Secure Key Storage

### OS Keychain Integration

```rust
use keyring::Entry;
use zeroize::Zeroizing;

pub struct SecureKeyStore {
    service_name: String,
}

impl SecureKeyStore {
    pub fn new(app_name: &str) -> Self {
        Self {
            service_name: format!("{}-encryption", app_name),
        }
    }

    /// Store encryption key in OS keychain
    pub fn store(&self, identifier: &str, key: &Zeroizing<String>) -> Result<(), KeyStoreError> {
        let entry = Entry::new(&self.service_name, identifier)
            .map_err(KeyStoreError::Keyring)?;

        entry.set_password(key.as_str())
            .map_err(KeyStoreError::Keyring)
    }

    /// Retrieve encryption key from OS keychain
    pub fn retrieve(&self, identifier: &str) -> Result<Zeroizing<String>, KeyStoreError> {
        let entry = Entry::new(&self.service_name, identifier)
            .map_err(KeyStoreError::Keyring)?;

        let password = entry.get_password()
            .map_err(KeyStoreError::Keyring)?;

        Ok(Zeroizing::new(password))
    }

    /// Delete key from OS keychain
    pub fn delete(&self, identifier: &str) -> Result<(), KeyStoreError> {
        let entry = Entry::new(&self.service_name, identifier)
            .map_err(KeyStoreError::Keyring)?;

        entry.delete_credential()
            .map_err(KeyStoreError::Keyring)
    }

    /// Check if key exists
    pub fn exists(&self, identifier: &str) -> bool {
        Entry::new(&self.service_name, identifier)
            .and_then(|e| e.get_password())
            .is_ok()
    }
}

#[derive(Debug)]
pub enum KeyStoreError {
    Keyring(keyring::Error),
    NotFound,
}
```

### Key Caching with Secure Memory

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Cached key with automatic expiration and secure cleanup
#[derive(ZeroizeOnDrop)]
struct CachedKey {
    #[zeroize(skip)]
    created_at: Instant,
    key: String,
}

pub struct SecureKeyCache {
    cache: RwLock<Option<CachedKey>>,
    ttl: Duration,
}

impl SecureKeyCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: RwLock::new(None),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub fn set(&self, key: Zeroizing<String>) {
        let mut cache = self.cache.write().unwrap();
        *cache = Some(CachedKey {
            created_at: Instant::now(),
            key: key.to_string(),
        });
    }

    pub fn get(&self) -> Option<Zeroizing<String>> {
        let cache = self.cache.read().unwrap();
        cache.as_ref().and_then(|cached| {
            if cached.created_at.elapsed() < self.ttl {
                Some(Zeroizing::new(cached.key.clone()))
            } else {
                None
            }
        })
    }

    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        if let Some(mut cached) = cache.take() {
            cached.key.zeroize();
        }
    }
}

impl Drop for SecureKeyCache {
    fn drop(&mut self) {
        self.clear();
    }
}
```

---

## Key Rotation

### Complete Key Rotation Procedure

```rust
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct KeyRotationManager {
    db_path: PathBuf,
    backup_dir: PathBuf,
    key_store: SecureKeyStore,
}

impl KeyRotationManager {
    /// Rotate database encryption key with full safety measures
    pub fn rotate_key(
        &self,
        current_key: &Zeroizing<String>,
        new_key: &Zeroizing<String>,
        user_id: &str
    ) -> Result<(), RotationError> {
        // Step 1: Create timestamped backup
        let backup_path = self.create_backup(current_key)?;

        // Step 2: Open database with current key
        let conn = Connection::open(&self.db_path)
            .map_err(RotationError::Database)?;
        conn.pragma_update(None, "key", current_key.as_str())
            .map_err(RotationError::Database)?;

        // Step 3: Verify current key works
        self.verify_encryption(&conn)?;

        // Step 4: Re-encrypt with new key
        conn.pragma_update(None, "rekey", new_key.as_str())
            .map_err(RotationError::Database)?;

        // Step 5: Verify new key works
        drop(conn);
        let conn = Connection::open(&self.db_path)
            .map_err(RotationError::Database)?;
        conn.pragma_update(None, "key", new_key.as_str())
            .map_err(RotationError::Database)?;
        self.verify_encryption(&conn)?;

        // Step 6: Update stored key
        self.key_store.store(user_id, new_key)
            .map_err(|_| RotationError::KeyStorage)?;

        // Step 7: Log rotation event
        self.log_rotation_event(user_id);

        // Step 8: Schedule backup deletion (keep for 7 days)
        self.schedule_backup_cleanup(backup_path, 7);

        Ok(())
    }

    fn create_backup(&self, key: &Zeroizing<String>) -> Result<PathBuf, RotationError> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = self.backup_dir.join(format!("backup_{}.db", timestamp));

        let conn = Connection::open(&self.db_path)
            .map_err(RotationError::Database)?;
        conn.pragma_update(None, "key", key.as_str())
            .map_err(RotationError::Database)?;

        // Create encrypted backup
        let backup_key = self.generate_backup_key()?;
        let attach_sql = format!(
            "ATTACH DATABASE '{}' AS backup KEY {}",
            backup_path.display(),
            backup_key.as_str()
        );

        conn.execute_batch(&format!("
            {};
            SELECT sqlcipher_export('backup');
            DETACH DATABASE backup;
        ", attach_sql)).map_err(RotationError::Database)?;

        // Store backup key
        let backup_id = format!("backup_{}", timestamp);
        self.key_store.store(&backup_id, &backup_key)
            .map_err(|_| RotationError::KeyStorage)?;

        Ok(backup_path)
    }

    fn verify_encryption(&self, conn: &Connection) -> Result<(), RotationError> {
        let page_size: i32 = conn.pragma_query_value(None, "cipher_page_size", |row| row.get(0))
            .map_err(RotationError::Database)?;

        if page_size == 0 {
            return Err(RotationError::EncryptionNotActive);
        }

        // Try to read data
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(RotationError::Database)?;

        Ok(())
    }

    fn generate_backup_key(&self) -> Result<Zeroizing<String>, RotationError> {
        use rand::Rng;
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        Ok(Zeroizing::new(format!("x'{}'", hex::encode(key_bytes))))
    }

    fn log_rotation_event(&self, user_id: &str) {
        log::info!(
            target: "security_audit",
            "key_rotation completed for user={} at={}",
            user_id,
            chrono::Utc::now().to_rfc3339()
        );
    }

    fn schedule_backup_cleanup(&self, path: PathBuf, days: u64) {
        // In production, use a proper scheduler
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(days * 24 * 60 * 60));
            if path.exists() {
                // Secure delete
                let _ = std::fs::remove_file(path);
            }
        });
    }
}

#[derive(Debug)]
pub enum RotationError {
    Database(rusqlite::Error),
    KeyStorage,
    EncryptionNotActive,
    BackupFailed,
}
```

---

## OpenSSL Security Monitoring

### Dependency Version Checking

```rust
/// Check SQLCipher and OpenSSL versions for known vulnerabilities
pub fn check_security_versions(conn: &Connection) -> SecurityReport {
    let mut report = SecurityReport::default();

    // Get SQLCipher version
    let cipher_version: String = conn
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .unwrap_or_default();

    // Get OpenSSL version (if available)
    let openssl_version = openssl::version::version();

    // Check for known vulnerable versions
    report.sqlcipher_version = cipher_version.clone();
    report.openssl_version = openssl_version.to_string();

    // CVE checks
    if cipher_version.starts_with("4.4.0") || cipher_version.starts_with("4.3") {
        report.warnings.push(
            "SQLCipher version may be affected by CVE-2020-27207. Update to 4.4.1+".into()
        );
    }

    if openssl_version.contains("1.1.1") && !openssl_version.contains("1.1.1w") {
        report.warnings.push(
            "OpenSSL version may be affected by multiple CVEs. Update to 1.1.1w+ or 3.0+".into()
        );
    }

    report
}

#[derive(Default)]
pub struct SecurityReport {
    pub sqlcipher_version: String,
    pub openssl_version: String,
    pub warnings: Vec<String>,
}
```

---

## Secure Memory Handling

### Memory Locking and Protection

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::ops::{Deref, DerefMut};

/// A buffer that is locked in memory and zeroed on drop
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self, std::io::Error> {
        let mut data = vec![0u8; size];

        // Lock memory to prevent swapping (Unix)
        #[cfg(unix)]
        unsafe {
            libc::mlock(data.as_ptr() as *const libc::c_void, size);
        }

        Ok(Self { data })
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Unlock memory before zeroing
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.data.as_ptr() as *const libc::c_void, self.data.len());
        }
        // ZeroizeOnDrop handles zeroing
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
```

---

## Migration from Unencrypted SQLite

### Encrypting Existing Database

```rust
/// Migrate unencrypted SQLite database to encrypted SQLCipher
pub fn encrypt_existing_database(
    source_path: &Path,
    encrypted_path: &Path,
    key: &Zeroizing<String>
) -> Result<(), MigrationError> {
    // Step 1: Open unencrypted database
    let source = Connection::open(source_path)
        .map_err(MigrationError::Source)?;

    // Step 2: Attach encrypted database
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS encrypted KEY {}",
        encrypted_path.display(),
        key.as_str()
    );

    source.execute_batch(&attach_sql)
        .map_err(MigrationError::Attach)?;

    // Step 3: Configure encryption settings on new database
    source.execute_batch("
        -- Set SQLCipher 4 compatibility on attached database
        PRAGMA encrypted.cipher_compatibility = 4;
        PRAGMA encrypted.cipher_memory_security = ON;
    ").map_err(MigrationError::Config)?;

    // Step 4: Export all data
    source.execute_batch("SELECT sqlcipher_export('encrypted')")
        .map_err(MigrationError::Export)?;

    // Step 5: Detach
    source.execute_batch("DETACH DATABASE encrypted")
        .map_err(MigrationError::Detach)?;

    // Step 6: Verify encrypted database
    let encrypted = Connection::open(encrypted_path)
        .map_err(MigrationError::Verify)?;
    encrypted.pragma_update(None, "key", key.as_str())
        .map_err(MigrationError::Verify)?;

    let page_size: i32 = encrypted
        .pragma_query_value(None, "cipher_page_size", |row| row.get(0))
        .map_err(MigrationError::Verify)?;

    if page_size == 0 {
        return Err(MigrationError::EncryptionFailed);
    }

    // Step 7: Securely delete original (optional)
    // secure_delete_file(source_path)?;

    Ok(())
}

#[derive(Debug)]
pub enum MigrationError {
    Source(rusqlite::Error),
    Attach(rusqlite::Error),
    Config(rusqlite::Error),
    Export(rusqlite::Error),
    Detach(rusqlite::Error),
    Verify(rusqlite::Error),
    EncryptionFailed,
}
```
