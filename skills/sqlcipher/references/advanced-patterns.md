# SQLCipher Advanced Patterns

## Performance Optimization

### Optimal PRAGMA Configuration

```rust
pub fn configure_for_performance(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        -- Cache size: negative = KB, positive = pages
        PRAGMA cache_size = -64000;  -- 64 MB cache

        -- WAL mode for concurrent reads
        PRAGMA journal_mode = WAL;

        -- Synchronous: NORMAL is good balance
        PRAGMA synchronous = NORMAL;

        -- Memory-mapped I/O
        PRAGMA mmap_size = 268435456;  -- 256 MB

        -- Temporary storage in memory
        PRAGMA temp_store = MEMORY;

        -- Page size (must match cipher_page_size)
        PRAGMA page_size = 4096;

        -- SQLCipher specific
        PRAGMA cipher_page_size = 4096;
        PRAGMA cipher_memory_security = ON;
    ")?;

    Ok(())
}

// For high-throughput writes
pub fn configure_for_writes(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA wal_autocheckpoint = 1000;  -- Checkpoint every 1000 pages
    ")?;

    Ok(())
}

// For read-heavy workloads
pub fn configure_for_reads(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        PRAGMA cache_size = -128000;  -- 128 MB cache
        PRAGMA mmap_size = 1073741824;  -- 1 GB mmap
        PRAGMA query_only = ON;  -- Read-only optimization
    ")?;

    Ok(())
}
```

### Benchmarking Encryption Overhead

```rust
pub fn benchmark_encryption_overhead(
    plaintext_db: &Path,
    encrypted_db: &Path,
    key: &Zeroizing<String>
) -> BenchmarkResults {
    use std::time::Instant;

    let mut results = BenchmarkResults::default();

    // Benchmark plaintext
    let plain_conn = Connection::open(plaintext_db).unwrap();
    let start = Instant::now();
    for _ in 0..1000 {
        plain_conn.execute("INSERT INTO test (data) VALUES (?1)", ["test"]).unwrap();
    }
    results.plaintext_write_ms = start.elapsed().as_millis();

    // Benchmark encrypted
    let enc_conn = Connection::open(encrypted_db).unwrap();
    enc_conn.pragma_update(None, "key", key.as_str()).unwrap();
    let start = Instant::now();
    for _ in 0..1000 {
        enc_conn.execute("INSERT INTO test (data) VALUES (?1)", ["test"]).unwrap();
    }
    results.encrypted_write_ms = start.elapsed().as_millis();

    results.overhead_percent =
        ((results.encrypted_write_ms as f64 / results.plaintext_write_ms as f64) - 1.0) * 100.0;

    results
}

#[derive(Default)]
pub struct BenchmarkResults {
    pub plaintext_write_ms: u128,
    pub encrypted_write_ms: u128,
    pub overhead_percent: f64,
}
```

---

## Backup Strategies

### Encrypted Backup with Different Key

```rust
pub fn create_encrypted_backup(
    conn: &Connection,
    backup_path: &Path,
    backup_key: &Zeroizing<String>
) -> Result<()> {
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS backup KEY {}",
        backup_path.display(),
        backup_key.as_str()
    );

    conn.execute_batch(&format!("
        {};

        -- Configure backup database
        PRAGMA backup.cipher_compatibility = 4;
        PRAGMA backup.kdf_iter = 256000;

        -- Export
        SELECT sqlcipher_export('backup');

        -- Detach
        DETACH DATABASE backup;
    ", attach_sql))?;

    Ok(())
}
```

### Incremental Backup with WAL

```rust
pub fn backup_wal_checkpoint(
    conn: &Connection,
    backup_dir: &Path
) -> Result<()> {
    // Force a checkpoint to ensure all WAL data is in main database
    conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")?;

    // Now the main .db file contains all data
    // Copy the main file (already encrypted)
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_path = backup_dir.join(format!("backup_{}.db", timestamp));

    std::fs::copy(
        conn.path().unwrap(),
        &backup_path
    )?;

    Ok(())
}
```

---

## Multi-Database Patterns

### Attached Encrypted Databases

```rust
pub struct MultiDatabaseManager {
    main_conn: Connection,
}

impl MultiDatabaseManager {
    pub fn new(main_path: &Path, main_key: &Zeroizing<String>) -> Result<Self> {
        let conn = Connection::open(main_path)?;
        conn.pragma_update(None, "key", main_key.as_str())?;

        Ok(Self { main_conn: conn })
    }

    /// Attach another encrypted database
    pub fn attach(
        &self,
        path: &Path,
        alias: &str,
        key: &Zeroizing<String>
    ) -> Result<()> {
        // Validate alias (prevent SQL injection)
        if !alias.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(rusqlite::Error::InvalidParameterName("Invalid alias".into()));
        }

        let sql = format!(
            "ATTACH DATABASE '{}' AS {} KEY {}",
            path.display(),
            alias,
            key.as_str()
        );

        self.main_conn.execute_batch(&sql)?;
        Ok(())
    }

    /// Query across databases
    pub fn query_cross_db(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<Row>> {
        let mut stmt = self.main_conn.prepare(sql)?;
        // Execute query that can reference main.table and alias.table
        stmt.query_map(params, |row| {
            // Map results
            Ok(row)
        })?.collect()
    }

    pub fn detach(&self, alias: &str) -> Result<()> {
        if !alias.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(rusqlite::Error::InvalidParameterName("Invalid alias".into()));
        }

        self.main_conn.execute(&format!("DETACH DATABASE {}", alias), [])?;
        Ok(())
    }
}
```

---

## Connection Pooling for Encrypted Databases

### R2D2 Pool with Encryption

```rust
use r2d2::{Pool, PooledConnection, CustomizeConnection};
use r2d2_sqlite::SqliteConnectionManager;
use zeroize::Zeroizing;

struct EncryptionInitializer {
    key: Zeroizing<String>,
}

impl CustomizeConnection<Connection, rusqlite::Error> for EncryptionInitializer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // Set encryption key for each connection
        conn.pragma_update(None, "key", self.key.as_str())?;

        // Configure settings
        conn.execute_batch("
            PRAGMA cipher_memory_security = ON;
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
        ")?;

        Ok(())
    }
}

pub fn create_encrypted_pool(
    path: &std::path::Path,
    key: Zeroizing<String>,
    pool_size: u32
) -> Result<Pool<SqliteConnectionManager>, r2d2::Error> {
    let manager = SqliteConnectionManager::file(path);

    Pool::builder()
        .max_size(pool_size)
        .connection_customizer(Box::new(EncryptionInitializer { key }))
        .build(manager)
}
```

---

## Cipher Settings Reference

### SQLCipher 4 Defaults

```rust
/// Apply SQLCipher 4 default settings explicitly
pub fn apply_sqlcipher4_defaults(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        -- Encryption algorithm
        PRAGMA cipher = 'aes-256-cbc';

        -- Key derivation
        PRAGMA kdf_algorithm = 'PBKDF2_HMAC_SHA512';
        PRAGMA kdf_iter = 256000;

        -- HMAC for page integrity
        PRAGMA hmac_algorithm = 'HMAC_SHA512';
        PRAGMA hmac_use = ON;

        -- Page size
        PRAGMA cipher_page_size = 4096;

        -- Plaintext header (for compatibility - usually 0)
        PRAGMA cipher_plaintext_header_size = 0;
    ")?;

    Ok(())
}
```

### Custom Cipher Configuration

```rust
/// Configure for maximum security (slower)
pub fn apply_maximum_security(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        PRAGMA kdf_iter = 1000000;  -- 1 million iterations
        PRAGMA cipher_memory_security = ON;
        PRAGMA cipher_plaintext_header_size = 0;
    ")?;

    Ok(())
}

/// Configure for better performance (still secure)
pub fn apply_performance_settings(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        PRAGMA kdf_iter = 256000;  -- Standard
        PRAGMA cipher_memory_security = OFF;  -- Slight risk, better performance
        PRAGMA cache_size = -64000;
    ")?;

    Ok(())
}
```

---

## Database Verification

### Verify Encryption Status

```rust
pub struct EncryptionStatus {
    pub is_encrypted: bool,
    pub cipher: String,
    pub page_size: i32,
    pub kdf_iter: i32,
    pub hmac_enabled: bool,
}

pub fn get_encryption_status(conn: &Connection) -> Result<EncryptionStatus> {
    let cipher_page_size: i32 = conn
        .pragma_query_value(None, "cipher_page_size", |row| row.get(0))
        .unwrap_or(0);

    if cipher_page_size == 0 {
        return Ok(EncryptionStatus {
            is_encrypted: false,
            cipher: String::new(),
            page_size: 0,
            kdf_iter: 0,
            hmac_enabled: false,
        });
    }

    let cipher: String = conn
        .pragma_query_value(None, "cipher", |row| row.get(0))?;
    let kdf_iter: i32 = conn
        .pragma_query_value(None, "kdf_iter", |row| row.get(0))?;
    let hmac_use: i32 = conn
        .pragma_query_value(None, "hmac_use", |row| row.get(0))?;

    Ok(EncryptionStatus {
        is_encrypted: true,
        cipher,
        page_size: cipher_page_size,
        kdf_iter,
        hmac_enabled: hmac_use == 1,
    })
}
```

### Integrity Check

```rust
pub fn verify_database_integrity(conn: &Connection) -> Result<bool> {
    let result: String = conn.query_row(
        "SELECT integrity_check FROM pragma_integrity_check LIMIT 1",
        [],
        |row| row.get(0)
    )?;

    Ok(result == "ok")
}

pub fn verify_can_read_data(conn: &Connection) -> Result<bool> {
    // Try to read from sqlite_master
    let count: i32 = conn.query_row(
        "SELECT count(*) FROM sqlite_master",
        [],
        |row| row.get(0)
    )?;

    Ok(count >= 0)
}
```

---

## Error Recovery

### Recovering from Key Issues

```rust
pub enum RecoveryStrategy {
    RetryWithCachedKey,
    PromptForPassword,
    RestoreFromBackup,
    FailGracefully,
}

pub fn handle_key_error(
    error: &rusqlite::Error,
    backup_available: bool
) -> RecoveryStrategy {
    match error {
        rusqlite::Error::SqliteFailure(err, _) => {
            match err.code {
                // SQLITE_NOTADB - wrong key or not encrypted
                rusqlite::ErrorCode::NotADatabase => {
                    if backup_available {
                        RecoveryStrategy::RestoreFromBackup
                    } else {
                        RecoveryStrategy::PromptForPassword
                    }
                }
                // SQLITE_AUTH - authentication failed
                rusqlite::ErrorCode::AuthorizationForStatementDenied => {
                    RecoveryStrategy::PromptForPassword
                }
                _ => RecoveryStrategy::FailGracefully,
            }
        }
        _ => RecoveryStrategy::FailGracefully,
    }
}
```
