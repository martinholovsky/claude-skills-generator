# Cross-Platform Builds Advanced Patterns

## Build Matrix Configurations

### Complete Tauri Build Matrix

```yaml
name: Build Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          # Windows
          - platform: windows-latest
            target: x86_64-pc-windows-msvc
            bundle: msi
            artifact_ext: '.msi'

          # macOS Intel
          - platform: macos-latest
            target: x86_64-apple-darwin
            bundle: dmg
            artifact_ext: '.dmg'

          # macOS Apple Silicon
          - platform: macos-latest
            target: aarch64-apple-darwin
            bundle: dmg
            artifact_ext: '.dmg'

          # Linux
          - platform: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            bundle: deb
            artifact_ext: '.deb'

          - platform: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            bundle: appimage
            artifact_ext: '.AppImage'

    runs-on: ${{ matrix.platform }}
    env:
      TAURI_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
      TAURI_KEY_PASSWORD: ${{ secrets.TAURI_KEY_PASSWORD }}

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install Linux Dependencies
        if: matrix.platform == 'ubuntu-22.04'
        run: |
          sudo apt-get update
          sudo apt-get install -y \
            libgtk-3-dev \
            libwebkit2gtk-4.0-dev \
            libappindicator3-dev \
            librsvg2-dev \
            patchelf

      - name: Install Dependencies
        run: npm ci

      - name: Build
        run: npm run tauri build -- --target ${{ matrix.target }} --bundles ${{ matrix.bundle }}

      - name: Upload Artifact
        uses: actions/upload-artifact@v3
        with:
          name: ${{ matrix.target }}-${{ matrix.bundle }}
          path: src-tauri/target/${{ matrix.target }}/release/bundle/**/*${{ matrix.artifact_ext }}
```

---

## Conditional Compilation

### Platform-Specific Features

```rust
// Cargo.toml
[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.48", features = ["Win32_Foundation", "Win32_UI_Shell"] }

[target.'cfg(target_os = "macos")'.dependencies]
objc = "0.2"
cocoa = "0.25"

[target.'cfg(target_os = "linux")'.dependencies]
dbus = "0.9"
```

### Platform-Specific Code

```rust
// System tray implementation
#[cfg(target_os = "macos")]
pub fn create_tray(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::SystemTray;
    // macOS uses template images
    let tray = SystemTray::new()
        .with_icon(tauri::Icon::Raw(include_bytes!("../icons/tray-Template.png").to_vec()));
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn create_tray(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::SystemTray;
    // Windows uses ICO
    let tray = SystemTray::new()
        .with_icon(tauri::Icon::Raw(include_bytes!("../icons/tray.ico").to_vec()));
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn create_tray(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::SystemTray;
    // Linux uses PNG
    let tray = SystemTray::new()
        .with_icon(tauri::Icon::Raw(include_bytes!("../icons/tray.png").to_vec()));
    Ok(())
}
```

### Feature Flags for Platforms

```rust
// Cargo.toml
[features]
default = []
windows-console = []  # Show console on Windows
macos-transparent = []  # Enable transparency on macOS

// main.rs
fn main() {
    #[cfg(all(target_os = "windows", not(feature = "windows-console")))]
    {
        // Hide console window
        use windows::Win32::System::Console::FreeConsole;
        unsafe { FreeConsole(); }
    }

    #[cfg(all(target_os = "macos", feature = "macos-transparent"))]
    {
        // Enable transparent window
    }

    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running application");
}
```

---

## Build Optimization

### Release Profile Configuration

```toml
# Cargo.toml
[profile.release]
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization, slower compile
panic = "abort"      # Smaller binary
strip = true         # Strip symbols
opt-level = "z"      # Optimize for size

# For better debugging in release
[profile.release-with-debug]
inherits = "release"
debug = true
strip = false
```

### Bundle Size Optimization

```json
// tauri.conf.json
{
  "tauri": {
    "bundle": {
      "resources": [
        // Only include necessary resources
        "assets/icons/*",
        "assets/fonts/*.woff2"
      ],
      "linux": {
        "appimage": {
          "bundleMediaFramework": false  // Reduces size significantly
        }
      }
    }
  }
}
```

### Dependency Optimization

```toml
# Cargo.toml - Use minimal features
[dependencies]
serde = { version = "1.0", default-features = false, features = ["derive"] }
tokio = { version = "1", default-features = false, features = ["rt", "macros"] }

# Check dependency sizes
# cargo install cargo-bloat
# cargo bloat --release --crates
```

---

## Platform-Specific Installers

### Windows NSIS Configuration

```json
// tauri.conf.json
{
  "tauri": {
    "bundle": {
      "windows": {
        "nsis": {
          "license": "./LICENSE.txt",
          "installerIcon": "./icons/icon.ico",
          "headerImage": "./icons/nsis-header.bmp",
          "sidebarImage": "./icons/nsis-sidebar.bmp",
          "installMode": "currentUser",
          "languages": ["English", "German", "French"],
          "displayLanguageSelector": true
        }
      }
    }
  }
}
```

### macOS DMG Configuration

```json
// tauri.conf.json
{
  "tauri": {
    "bundle": {
      "macOS": {
        "dmg": {
          "appPosition": { "x": 180, "y": 170 },
          "applicationFolderPosition": { "x": 480, "y": 170 },
          "windowSize": { "width": 660, "height": 400 }
        }
      }
    }
  }
}
```

### Linux Package Metadata

```json
// tauri.conf.json
{
  "tauri": {
    "bundle": {
      "linux": {
        "deb": {
          "depends": [
            "libgtk-3-0",
            "libwebkit2gtk-4.0-37",
            "libappindicator3-1"
          ],
          "section": "utils",
          "priority": "optional"
        }
      },
      "category": "Utility"
    }
  }
}
```

---

## Universal Binaries

### macOS Universal Binary

```yaml
jobs:
  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-apple-darwin,aarch64-apple-darwin

      - name: Build Intel
        run: npm run tauri build -- --target x86_64-apple-darwin

      - name: Build ARM
        run: npm run tauri build -- --target aarch64-apple-darwin

      - name: Create Universal Binary
        run: |
          mkdir -p target/universal-apple-darwin/release/bundle/macos

          # Combine binaries
          lipo -create \
            target/x86_64-apple-darwin/release/bundle/macos/MyApp.app/Contents/MacOS/MyApp \
            target/aarch64-apple-darwin/release/bundle/macos/MyApp.app/Contents/MacOS/MyApp \
            -output MyApp-universal

          # Copy app bundle from one architecture
          cp -r target/x86_64-apple-darwin/release/bundle/macos/MyApp.app \
            target/universal-apple-darwin/release/bundle/macos/

          # Replace binary with universal
          cp MyApp-universal \
            target/universal-apple-darwin/release/bundle/macos/MyApp.app/Contents/MacOS/MyApp

      - name: Sign Universal App
        env:
          SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
        run: |
          codesign --force --options runtime --sign "$SIGNING_IDENTITY" \
            --deep target/universal-apple-darwin/release/bundle/macos/MyApp.app
```

---

## Resource Handling

### Platform-Specific Resources

```rust
// Load platform-specific assets
fn get_icon_path() -> &'static str {
    #[cfg(target_os = "windows")]
    { "icons/icon.ico" }

    #[cfg(target_os = "macos")]
    { "icons/icon.icns" }

    #[cfg(target_os = "linux")]
    { "icons/icon.png" }
}

// Platform-specific config locations
fn get_config_dir() -> std::path::PathBuf {
    use directories::ProjectDirs;

    let dirs = ProjectDirs::from("com", "company", "app").unwrap();

    #[cfg(target_os = "linux")]
    {
        // Follow XDG spec on Linux
        dirs.config_dir().to_path_buf()
    }

    #[cfg(target_os = "macos")]
    {
        // Use Application Support on macOS
        dirs.data_dir().to_path_buf()
    }

    #[cfg(target_os = "windows")]
    {
        // Use %APPDATA% on Windows
        dirs.config_dir().to_path_buf()
    }
}
```

### Embedded Resources

```rust
// Embed files at compile time
const LICENSE: &str = include_str!("../LICENSE");
const DEFAULT_CONFIG: &[u8] = include_bytes!("../assets/default-config.json");

// Platform-specific embedded resources
#[cfg(target_os = "windows")]
const ICON: &[u8] = include_bytes!("../icons/icon.ico");

#[cfg(target_os = "macos")]
const ICON: &[u8] = include_bytes!("../icons/icon.icns");

#[cfg(target_os = "linux")]
const ICON: &[u8] = include_bytes!("../icons/icon.png");
```

---

## Testing Cross-Platform

### Cross-Platform Test Matrix

```yaml
name: Test

on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-22.04, windows-latest, macos-latest]
        rust: [stable]

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}

      - name: Install Linux Dependencies
        if: matrix.os == 'ubuntu-22.04'
        run: |
          sudo apt-get update
          sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.0-dev

      - name: Run Tests
        run: cargo test --all-features

      - name: Run Platform-Specific Tests
        run: cargo test --all-features -- --ignored
        env:
          RUN_PLATFORM_TESTS: true
```

### Platform-Specific Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_registry() {
        // Windows-specific test
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_keychain() {
        // macOS-specific test
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_xdg() {
        // Linux-specific test
    }

    #[test]
    #[ignore]  // Run only with RUN_PLATFORM_TESTS=true
    fn test_platform_integration() {
        if std::env::var("RUN_PLATFORM_TESTS").is_err() {
            return;
        }
        // Integration test requiring platform setup
    }
}
```
