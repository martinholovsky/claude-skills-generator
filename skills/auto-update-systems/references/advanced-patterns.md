# Auto-Update Systems Advanced Patterns

## Staged Rollouts

### Percentage-Based Rollout

```rust
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct StagedRollout {
    stages: Vec<RolloutStage>,
}

#[derive(Clone)]
struct RolloutStage {
    percentage: u8,
    start_time: chrono::DateTime<chrono::Utc>,
}

impl StagedRollout {
    pub fn new() -> Self {
        Self {
            stages: vec![
                RolloutStage { percentage: 1, start_time: chrono::Utc::now() },
                RolloutStage { percentage: 10, start_time: chrono::Utc::now() + chrono::Duration::hours(24) },
                RolloutStage { percentage: 50, start_time: chrono::Utc::now() + chrono::Duration::hours(48) },
                RolloutStage { percentage: 100, start_time: chrono::Utc::now() + chrono::Duration::hours(72) },
            ],
        }
    }

    pub fn should_update(&self, device_id: &str) -> bool {
        let current_percentage = self.get_current_percentage();
        let device_bucket = self.device_to_bucket(device_id);
        device_bucket <= current_percentage
    }

    fn get_current_percentage(&self) -> u8 {
        let now = chrono::Utc::now();
        self.stages
            .iter()
            .filter(|stage| stage.start_time <= now)
            .map(|stage| stage.percentage)
            .max()
            .unwrap_or(0)
    }

    fn device_to_bucket(&self, device_id: &str) -> u8 {
        let mut hasher = DefaultHasher::new();
        device_id.hash(&mut hasher);
        (hasher.finish() % 100) as u8 + 1
    }
}
```

### Server-Side Rollout Control

```rust
// Update server endpoint
async fn check_update(
    device_id: web::Query<DeviceQuery>,
    rollout: web::Data<RolloutConfig>,
) -> HttpResponse {
    let version = "1.2.0";

    // Check if device is in rollout
    if !rollout.is_device_eligible(&device_id.id, version) {
        return HttpResponse::NoContent().finish();
    }

    // Return update manifest
    let manifest = get_manifest(version);
    HttpResponse::Ok().json(manifest)
}

#[derive(Clone)]
struct RolloutConfig {
    versions: HashMap<String, VersionRollout>,
}

#[derive(Clone)]
struct VersionRollout {
    percentage: u8,
    excluded_devices: HashSet<String>,
    included_devices: HashSet<String>, // For beta testers
}

impl RolloutConfig {
    fn is_device_eligible(&self, device_id: &str, version: &str) -> bool {
        let rollout = match self.versions.get(version) {
            Some(r) => r,
            None => return false,
        };

        // Always include beta testers
        if rollout.included_devices.contains(device_id) {
            return true;
        }

        // Exclude blocked devices
        if rollout.excluded_devices.contains(device_id) {
            return false;
        }

        // Check percentage
        let bucket = device_to_bucket(device_id);
        bucket <= rollout.percentage
    }
}
```

---

## Update Channels

### Channel Configuration

```json
// tauri.conf.json for different channels
{
  "tauri": {
    "updater": {
      "endpoints": [
        "https://releases.myapp.com/{{channel}}/{{target}}/{{arch}}/{{current_version}}"
      ]
    }
  }
}
```

### Channel Selection

```rust
use std::fs;
use directories::ProjectDirs;

pub fn get_update_channel() -> String {
    let dirs = ProjectDirs::from("com", "company", "app").unwrap();
    let config_path = dirs.config_dir().join("channel.txt");

    fs::read_to_string(config_path)
        .unwrap_or_else(|_| "stable".to_string())
        .trim()
        .to_string()
}

#[tauri::command]
pub fn set_update_channel(channel: String) -> Result<(), String> {
    let valid_channels = ["stable", "beta", "nightly"];
    if !valid_channels.contains(&channel.as_str()) {
        return Err("Invalid channel".to_string());
    }

    let dirs = ProjectDirs::from("com", "company", "app").unwrap();
    let config_path = dirs.config_dir().join("channel.txt");

    fs::write(config_path, &channel)
        .map_err(|e| e.to_string())
}
```

### Channel-Specific Manifests

```yaml
# Directory structure
releases/
├── stable/
│   ├── darwin-x86_64/
│   │   └── latest.json
│   ├── darwin-aarch64/
│   ├── linux-x86_64/
│   └── windows-x86_64/
├── beta/
│   └── ...
└── nightly/
    └── ...
```

---

## Rollback Mechanisms

### Automatic Rollback on Failure

```rust
use std::path::PathBuf;
use std::fs;

pub struct RollbackManager {
    backup_dir: PathBuf,
    current_version: String,
}

impl RollbackManager {
    pub fn new(backup_dir: PathBuf, current_version: String) -> Self {
        Self { backup_dir, current_version }
    }

    pub async fn perform_update_with_rollback<F, Fut>(
        &self,
        update_fn: F,
    ) -> Result<(), UpdateError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), UpdateError>>,
    {
        // Create backup
        let backup_path = self.create_backup()?;

        // Attempt update
        match update_fn().await {
            Ok(()) => {
                // Verify update
                if self.verify_update() {
                    // Cleanup old backup after grace period
                    self.schedule_backup_cleanup(backup_path);
                    Ok(())
                } else {
                    // Rollback if verification fails
                    self.restore_backup(&backup_path)?;
                    Err(UpdateError::VerificationFailed)
                }
            }
            Err(e) => {
                // Rollback on error
                self.restore_backup(&backup_path)?;
                Err(e)
            }
        }
    }

    fn create_backup(&self) -> Result<PathBuf, UpdateError> {
        let backup_path = self.backup_dir.join(format!(
            "backup_{}_{}",
            self.current_version,
            chrono::Utc::now().timestamp()
        ));

        // Copy current installation to backup
        let app_path = std::env::current_exe()?;
        let app_dir = app_path.parent().unwrap();

        copy_dir_all(app_dir, &backup_path)?;

        Ok(backup_path)
    }

    fn restore_backup(&self, backup_path: &PathBuf) -> Result<(), UpdateError> {
        let app_path = std::env::current_exe()?;
        let app_dir = app_path.parent().unwrap();

        // Restore from backup
        copy_dir_all(backup_path, app_dir)?;

        Ok(())
    }

    fn verify_update(&self) -> bool {
        // Run basic health checks
        // - Check binary exists and runs
        // - Verify critical files
        // - Test basic functionality
        true
    }

    fn schedule_backup_cleanup(&self, backup_path: PathBuf) {
        // Keep backup for 7 days before cleanup
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(7 * 24 * 60 * 60));
            let _ = fs::remove_dir_all(backup_path);
        });
    }
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
```

---

## Differential Updates

### Delta Update Implementation

```rust
// Use bidiff/bsdiff for creating patches
use bidiff::{diff, patch};
use std::io::{Read, Write};

pub fn create_delta(old_file: &[u8], new_file: &[u8]) -> Vec<u8> {
    let mut patch = Vec::new();
    diff(old_file, new_file, &mut patch).unwrap();
    patch
}

pub fn apply_delta(old_file: &[u8], patch: &[u8]) -> Vec<u8> {
    let mut new_file = Vec::new();
    bidiff::patch(old_file, patch, &mut new_file).unwrap();
    new_file
}

// CI job to generate deltas
// For each release:
// 1. Get previous release artifact
// 2. Generate delta patch
// 3. Sign the patch
// 4. Upload patch alongside full artifact
```

### Delta-Aware Manifest

```json
{
  "version": "1.2.0",
  "platforms": {
    "darwin-x86_64": {
      "signature": "...",
      "url": "https://releases.myapp.com/MyApp_1.2.0.tar.gz",
      "size": 50000000,
      "deltas": [
        {
          "from_version": "1.1.0",
          "url": "https://releases.myapp.com/MyApp_1.1.0_to_1.2.0.delta",
          "size": 5000000,
          "signature": "..."
        },
        {
          "from_version": "1.0.0",
          "url": "https://releases.myapp.com/MyApp_1.0.0_to_1.2.0.delta",
          "size": 15000000,
          "signature": "..."
        }
      ]
    }
  }
}
```

---

## Update Analytics

### Telemetry Collection

```rust
use serde::Serialize;

#[derive(Serialize)]
pub struct UpdateEvent {
    event_type: UpdateEventType,
    device_id: String,
    from_version: String,
    to_version: String,
    platform: String,
    timestamp: String,
    duration_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Serialize)]
pub enum UpdateEventType {
    CheckStarted,
    UpdateAvailable,
    DownloadStarted,
    DownloadComplete,
    InstallStarted,
    InstallComplete,
    InstallFailed,
    Rollback,
}

pub async fn report_update_event(event: UpdateEvent) {
    // Send to analytics endpoint
    let client = reqwest::Client::new();
    let _ = client
        .post("https://analytics.myapp.com/updates")
        .json(&event)
        .send()
        .await;
}
```

### Health Monitoring

```rust
pub async fn check_update_health(version: &str) -> UpdateHealth {
    // Query analytics for this version
    let stats = get_version_stats(version).await;

    UpdateHealth {
        version: version.to_string(),
        total_attempts: stats.total,
        successful: stats.successful,
        failed: stats.failed,
        rollbacks: stats.rollbacks,
        success_rate: stats.successful as f64 / stats.total as f64,
        // Halt rollout if success rate drops
        should_continue: stats.successful as f64 / stats.total as f64 > 0.95,
    }
}
```

---

## Background Updates

### Silent Background Check

```rust
use std::time::Duration;
use tokio::time::interval;

pub async fn start_background_update_checker(app: tauri::AppHandle) {
    let mut interval = interval(Duration::from_secs(3600)); // Check every hour

    loop {
        interval.tick().await;

        match app.updater().check().await {
            Ok(update) if update.is_update_available() => {
                // Notify frontend about available update
                let _ = app.emit_all("update-available", UpdateInfo {
                    version: update.latest_version().to_string(),
                    notes: update.body().map(|s| s.to_string()),
                });

                // Optionally download in background
                if should_auto_download() {
                    let _ = update.download().await;
                    let _ = app.emit_all("update-downloaded", ());
                }
            }
            Err(e) => {
                log::warn!("Background update check failed: {}", e);
            }
            _ => {}
        }
    }
}
```

### User Preferences

```rust
#[derive(serde::Deserialize, serde::Serialize)]
pub struct UpdatePreferences {
    pub auto_check: bool,
    pub auto_download: bool,
    pub auto_install: bool,
    pub check_interval_hours: u32,
    pub channel: String,
}

impl Default for UpdatePreferences {
    fn default() -> Self {
        Self {
            auto_check: true,
            auto_download: true,
            auto_install: false, // Require user confirmation to install
            check_interval_hours: 24,
            channel: "stable".to_string(),
        }
    }
}
```

---

## Update UI Patterns

### Progress Reporting

```rust
#[tauri::command]
async fn download_update(
    app: AppHandle,
    window: Window,
) -> Result<(), String> {
    let update = app.updater().check().await.map_err(|e| e.to_string())?;

    if !update.is_update_available() {
        return Ok(());
    }

    // Download with progress
    update
        .download(|downloaded, total| {
            let progress = if total > 0 {
                (downloaded as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let _ = window.emit("update-progress", progress);
        })
        .await
        .map_err(|e| e.to_string())?;

    let _ = window.emit("update-ready", ());

    Ok(())
}
```

### Frontend Component

```typescript
// React component for update UI
function UpdateNotification() {
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<'idle' | 'downloading' | 'ready'>('idle');

  useEffect(() => {
    const unlisten = listen('update-available', (event) => {
      setUpdateAvailable(true);
    });

    const unlistenProgress = listen('update-progress', (event) => {
      setProgress(event.payload as number);
      setStatus('downloading');
    });

    const unlistenReady = listen('update-ready', () => {
      setStatus('ready');
    });

    return () => {
      unlisten.then(fn => fn());
      unlistenProgress.then(fn => fn());
      unlistenReady.then(fn => fn());
    };
  }, []);

  if (!updateAvailable) return null;

  return (
    <div className="update-notification">
      {status === 'idle' && (
        <button onClick={() => invoke('download_update')}>
          Download Update
        </button>
      )}
      {status === 'downloading' && (
        <progress value={progress} max={100} />
      )}
      {status === 'ready' && (
        <button onClick={() => invoke('install_update')}>
          Restart to Update
        </button>
      )}
    </div>
  );
}
```
