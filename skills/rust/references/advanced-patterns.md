# Rust Advanced Patterns Reference

## Tauri Integration Patterns

### State Management

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::State;

pub struct AppState {
    pub db: Arc<DatabasePool>,
    pub config: Arc<RwLock<Config>>,
    pub cache: Arc<Cache>,
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    let config = state.config.read().await;
    Ok(config.clone())
}

#[tauri::command]
async fn update_config(
    new_config: Config,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Validate before updating
    new_config.validate()?;

    let mut config = state.config.write().await;
    *config = new_config;

    Ok(())
}
```

### Event System

```rust
use tauri::{AppHandle, Manager};

// Emit events to frontend
pub fn emit_progress(app: &AppHandle, progress: f64) -> Result<(), tauri::Error> {
    app.emit_all("progress", progress)
}

// Listen for events from frontend
#[tauri::command]
async fn start_task(app: AppHandle) -> Result<(), String> {
    tokio::spawn(async move {
        for i in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let _ = emit_progress(&app, i as f64 / 100.0);
        }
    });

    Ok(())
}
```

### Plugin Development

```rust
use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("my-plugin")
        .invoke_handler(tauri::generate_handler![
            plugin_command_1,
            plugin_command_2,
        ])
        .setup(|app| {
            // Initialize plugin state
            app.manage(PluginState::default());
            Ok(())
        })
        .build()
}
```

---

## Performance Optimization

### Zero-Copy Parsing

```rust
use std::borrow::Cow;

// Avoid unnecessary allocations
pub fn process_data(input: &str) -> Cow<'_, str> {
    if input.contains("replace_me") {
        // Only allocate when needed
        Cow::Owned(input.replace("replace_me", "replaced"))
    } else {
        // Zero-copy when no changes needed
        Cow::Borrowed(input)
    }
}
```

### Async Streaming

```rust
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

// Stream large files without loading into memory
pub async fn process_large_file(path: &str) -> Result<(), Error> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        process_line(&line).await?;
    }

    Ok(())
}
```

### Connection Pooling

```rust
use sqlx::postgres::PgPoolOptions;

pub async fn create_pool(database_url: &str) -> Result<PgPool, Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .connect(database_url)
        .await
}
```

---

## Type-Safe Patterns

### Newtype Pattern

```rust
// Prevent mixing up IDs
pub struct UserId(pub i64);
pub struct OrderId(pub i64);

impl UserId {
    pub fn new(id: i64) -> Result<Self, ValidationError> {
        if id <= 0 {
            return Err(ValidationError::InvalidId);
        }
        Ok(Self(id))
    }
}

// Compiler prevents: get_user(order_id) - wrong type!
async fn get_user(user_id: UserId) -> Result<User, Error> {
    // ...
}
```

### Builder Pattern

```rust
#[derive(Default)]
pub struct RequestBuilder {
    url: Option<String>,
    timeout: Option<Duration>,
    headers: HashMap<String, String>,
}

impl RequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<Request, BuildError> {
        let url = self.url.ok_or(BuildError::MissingUrl)?;

        Ok(Request {
            url,
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
            headers: self.headers,
        })
    }
}
```

### Typestate Pattern

```rust
// Compile-time state machine
pub struct Connection<S> {
    state: S,
    // ...
}

pub struct Disconnected;
pub struct Connected;
pub struct Authenticated;

impl Connection<Disconnected> {
    pub fn new() -> Self {
        Connection { state: Disconnected }
    }

    pub async fn connect(self, addr: &str) -> Result<Connection<Connected>, Error> {
        // Connect logic...
        Ok(Connection { state: Connected })
    }
}

impl Connection<Connected> {
    pub async fn authenticate(self, token: &str) -> Result<Connection<Authenticated>, Error> {
        // Auth logic...
        Ok(Connection { state: Authenticated })
    }
}

impl Connection<Authenticated> {
    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        // Only authenticated connections can send
        Ok(())
    }
}

// Usage:
// Connection::new()
//     .connect("localhost:8080").await?
//     .authenticate("token").await?
//     .send(b"data").await?;
```

---

## Async Patterns

### Graceful Shutdown

```rust
use tokio::signal;
use tokio::sync::broadcast;

pub async fn run_with_shutdown(app: App) -> Result<(), Error> {
    let (shutdown_tx, _) = broadcast::channel(1);

    let server = tokio::spawn({
        let mut shutdown_rx = shutdown_tx.subscribe();
        async move {
            tokio::select! {
                result = app.run() => result,
                _ = shutdown_rx.recv() => Ok(()),
            }
        }
    });

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    tracing::info!("Shutdown signal received");

    // Notify all tasks
    let _ = shutdown_tx.send(());

    // Wait for graceful shutdown with timeout
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        server
    ).await??
}
```

### Rate Limiting

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
}

impl RateLimiter {
    pub fn new(permits_per_second: usize) -> Self {
        let semaphore = Arc::new(Semaphore::new(permits_per_second));

        // Replenish permits every second
        let sem = semaphore.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let to_add = permits_per_second.saturating_sub(sem.available_permits());
                sem.add_permits(to_add);
            }
        });

        Self { semaphore }
    }

    pub async fn acquire(&self) -> Result<(), Error> {
        self.semaphore
            .acquire()
            .await
            .map_err(|_| Error::RateLimited)?;
        Ok(())
    }
}
```

---

## Testing Patterns

### Property-Based Testing

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_path_join_never_escapes(
            base in "[a-z]{1,10}",
            input in "[a-z0-9_\\-]{1,20}"
        ) {
            let base_path = std::path::Path::new(&base);
            if let Ok(result) = safe_path_join(base_path, &input) {
                // Result must always start with base
                prop_assert!(result.starts_with(base_path));
            }
        }

        #[test]
        fn test_serialization_roundtrip(config: Config) {
            let json = serde_json::to_string(&config).unwrap();
            let parsed: Config = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(config, parsed);
        }
    }
}
```

### Async Test Fixtures

```rust
#[cfg(test)]
mod tests {
    use sqlx::PgPool;
    use once_cell::sync::Lazy;

    static TEST_DB: Lazy<PgPool> = Lazy::new(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                create_test_pool().await.unwrap()
            })
    });

    #[tokio::test]
    async fn test_user_creation() {
        let pool = &*TEST_DB;

        // Test with real database
        let user = create_user(pool, "test@example.com").await.unwrap();
        assert_eq!(user.email, "test@example.com");

        // Cleanup
        delete_user(pool, user.id).await.unwrap();
    }
}
```
