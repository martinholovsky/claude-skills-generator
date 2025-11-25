# Rust Security Examples Reference

## CVE Details and Mitigations

### CVE-2024-24576: Command Injection via Batch Files (Windows)

**Severity**: CRITICAL (CVSS 10.0)
**Affected**: Rust < 1.77.2 on Windows
**CWE**: CWE-78 (OS Command Injection)

**Description**: The Rust standard library did not properly escape arguments when invoking batch files (.bat, .cmd) on Windows using `std::process::Command`. Attackers could execute arbitrary shell commands.

**Vulnerable Code**:
```rust
// VULNERABLE: Arguments not properly escaped
use std::process::Command;

fn run_batch(user_arg: &str) {
    Command::new("script.bat")
        .arg(user_arg)  // If user_arg = "foo & malicious.exe", injection occurs
        .spawn();
}
```

**Mitigation**:
```rust
// FIXED: Upgrade Rust and validate input
use std::process::Command;

fn run_batch(user_arg: &str) -> Result<(), String> {
    // Input validation - reject shell metacharacters
    if user_arg.chars().any(|c| matches!(c, '&' | '|' | ';' | '$' | '`' | '(' | ')')) {
        return Err("Invalid characters in argument".into());
    }

    // Use allowlist approach
    if !user_arg.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Argument contains disallowed characters".into());
    }

    Command::new("script.bat")
        .arg(user_arg)
        .spawn()
        .map_err(|e| e.to_string())?;

    Ok(())
}

// BEST: Avoid batch files entirely - use direct execution
fn safe_alternative() {
    Command::new("program.exe")
        .args(["--option", "value"])
        .spawn();
}
```

---

### CVE-2024-43402: Incomplete Fix for Command Injection

**Severity**: HIGH
**Affected**: Rust 1.77.2 to < 1.81.0 on Windows
**CWE**: CWE-78 (OS Command Injection)

**Description**: The fix for CVE-2024-24576 was incomplete. Batch files with trailing whitespace or periods could bypass escaping.

**Mitigation**:
```rust
// Upgrade to Rust 1.81.0+

// Additional defense: normalize filenames
fn safe_batch_call(batch_name: &str, args: &[&str]) -> Result<(), String> {
    // Strip trailing whitespace/periods that Windows ignores
    let normalized = batch_name.trim_end_matches(|c| c == ' ' || c == '.');

    // Validate batch file exists with exact name
    if !std::path::Path::new(&format!("{}.bat", normalized)).exists() {
        return Err("Batch file not found".into());
    }

    Command::new(format!("{}.bat", normalized))
        .args(args)
        .spawn()
        .map_err(|e| e.to_string())?;

    Ok(())
}
```

---

### CVE-2021-28032: Multiple Mutable References

**Severity**: HIGH
**Affected**: Various crates using unsafe incorrectly
**CWE**: CWE-119 (Buffer Errors), CWE-416 (Use After Free)

**Description**: Unsafe code created multiple mutable references to the same memory, violating Rust's aliasing rules and potentially causing undefined behavior.

**Vulnerable Pattern**:
```rust
// VULNERABLE: Creates multiple mutable references
unsafe fn bad_split(slice: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let ptr = slice.as_mut_ptr();
    let len = slice.len();
    // Both slices can modify the same memory!
    (
        std::slice::from_raw_parts_mut(ptr, len),
        std::slice::from_raw_parts_mut(ptr, len),
    )
}
```

**Safe Implementation**:
```rust
// SAFE: Use split_at_mut which enforces non-overlapping
fn safe_split(slice: &mut [u8], mid: usize) -> (&mut [u8], &mut [u8]) {
    slice.split_at_mut(mid)
}

// If unsafe is required, document invariants
unsafe fn documented_unsafe(slice: &mut [u8], mid: usize) -> (&mut [u8], &mut [u8]) {
    let ptr = slice.as_mut_ptr();
    let len = slice.len();

    assert!(mid <= len, "mid out of bounds");

    // SAFETY: The two slices are non-overlapping:
    // - First slice: [0, mid)
    // - Second slice: [mid, len)
    // Both are within the original allocation and properly aligned.
    (
        std::slice::from_raw_parts_mut(ptr, mid),
        std::slice::from_raw_parts_mut(ptr.add(mid), len - mid),
    )
}
```

---

## OWASP Top 10 2025 Complete Examples

### A01: Broken Access Control

```rust
// VULNERABLE: No authorization check
#[tauri::command]
async fn delete_user(user_id: String) -> Result<(), String> {
    db.delete_user(&user_id).await?;
    Ok(())
}

// SECURE: Verify permissions
#[tauri::command]
async fn delete_user(
    user_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let current_user = state.get_current_user()?;

    // Check authorization
    if current_user.id != user_id && !current_user.is_admin {
        return Err("Not authorized to delete this user".into());
    }

    db.delete_user(&user_id).await?;

    // Audit log
    tracing::info!(
        action = "delete_user",
        target_user = %user_id,
        performed_by = %current_user.id,
        "User deleted"
    );

    Ok(())
}
```

### A03: Injection

```rust
// VULNERABLE: SQL injection
async fn get_user(name: &str) -> Result<User, Error> {
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_one(&pool)
        .await
}

// SECURE: Parameterized query
async fn get_user(name: &str) -> Result<User, Error> {
    sqlx::query_as!(
        User,
        "SELECT id, name, email FROM users WHERE name = $1",
        name
    )
    .fetch_one(&pool)
    .await
}

// VULNERABLE: Command injection
fn ping(host: &str) {
    Command::new("sh")
        .args(["-c", &format!("ping -c 1 {}", host)])
        .spawn();
}

// SECURE: Direct execution with validation
fn ping(host: &str) -> Result<(), String> {
    // Validate IP/hostname format
    let ip_regex = regex::Regex::new(r"^[\d\.]+$|^[\w\-\.]+$").unwrap();
    if !ip_regex.is_match(host) {
        return Err("Invalid host format".into());
    }

    Command::new("ping")
        .args(["-c", "1", host])
        .spawn()
        .map_err(|e| e.to_string())?;

    Ok(())
}
```

### A04: Insecure Design

```rust
// VULNERABLE: Password reset token predictable
fn generate_reset_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{:x}", secs)  // Predictable!
}

// SECURE: Cryptographically random token
fn generate_reset_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: [u8; 32] = rng.gen();
    hex::encode(token)
}
```

### A05: Security Misconfiguration

```toml
# tauri.conf.json - Restrict capabilities
{
  "tauri": {
    "security": {
      "csp": "default-src 'self'; script-src 'self'",
      "dangerousDisableAssetCspModification": false
    },
    "allowlist": {
      "all": false,  // NEVER enable all
      "fs": {
        "scope": ["$APPDATA/*"],  // Restrict to app directory
        "readFile": true,
        "writeFile": true
      },
      "shell": {
        "open": false,  // Disable if not needed
        "execute": false
      }
    }
  }
}
```

### A06: Vulnerable and Outdated Components

```bash
# Regular dependency auditing
cargo audit

# In CI/CD pipeline
cargo audit --deny warnings

# Keep dependencies updated
cargo update

# Check for outdated dependencies
cargo outdated
```

---

## Additional Security Patterns

### Safe FFI Wrapper

```rust
// External C library
extern "C" {
    fn unsafe_c_function(ptr: *const u8, len: usize) -> i32;
}

// Safe Rust wrapper
pub fn safe_wrapper(data: &[u8]) -> Result<i32, Error> {
    // Validate input
    if data.is_empty() {
        return Err(Error::InvalidInput("Empty data"));
    }

    if data.len() > MAX_SIZE {
        return Err(Error::InvalidInput("Data too large"));
    }

    // SAFETY: We verified data is not empty and within size limits.
    // The C function only reads from the pointer for len bytes.
    let result = unsafe {
        unsafe_c_function(data.as_ptr(), data.len())
    };

    if result < 0 {
        Err(Error::CFunction(result))
    } else {
        Ok(result)
    }
}
```

### Secure Deserialization

```rust
use serde::Deserialize;

// Limit deserialization depth/size to prevent DoS
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]  // Reject unexpected fields
pub struct Config {
    #[serde(deserialize_with = "validate_size")]
    pub buffer_size: usize,

    pub timeout_seconds: u64,
}

fn validate_size<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let size = usize::deserialize(deserializer)?;

    if size > 1024 * 1024 {  // 1MB limit
        return Err(serde::de::Error::custom("buffer_size too large"));
    }

    Ok(size)
}
```
