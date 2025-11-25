# Auto-Update Systems Security Examples

## Key Generation and Management

### Generating Update Signing Keys

```bash
# Generate Tauri signing key pair
npm run tauri signer generate -- -w ~/.tauri/myapp.key

# This creates:
# - ~/.tauri/myapp.key (private key - KEEP SECRET)
# - Public key output (embed in tauri.conf.json)

# Example output:
# Please enter a password to protect the secret key:
# Password: ********
#
# Your keypair was generated successfully
# Private: ~/.tauri/myapp.key
# Public: dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6...
#
# IMPORTANT: Store the private key securely!
```

### Storing Keys in CI/CD

```yaml
# GitHub Actions secrets required:
# TAURI_PRIVATE_KEY: contents of ~/.tauri/myapp.key
# TAURI_KEY_PASSWORD: password used during key generation

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TAURI_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
      TAURI_KEY_PASSWORD: ${{ secrets.TAURI_KEY_PASSWORD }}
    steps:
      - uses: actions/checkout@v4
      - run: npm run tauri build
      # Tauri automatically signs the update artifact
```

### Key Rotation Procedure

```rust
// 1. Generate new key pair
// npm run tauri signer generate -- -w ~/.tauri/myapp-new.key

// 2. Update tauri.conf.json with new public key
{
  "tauri": {
    "updater": {
      "pubkey": "NEW_PUBLIC_KEY_HERE"
    }
  }
}

// 3. Build and release new version with new key
// This version becomes the "transitional" version

// 4. Update CI secrets with new private key
// Update TAURI_PRIVATE_KEY secret

// 5. All subsequent releases use new key
// Old versions can still update to transitional version
// Transitional version and newer use new key

// 6. After sufficient time, deprecate old key
```

---

## Signature Verification

### How Tauri Verifies Signatures

```rust
// Tauri uses minisign format for signatures
// Verification happens automatically when:
// 1. pubkey is configured in tauri.conf.json
// 2. Update manifest contains signature field
// 3. Downloaded artifact is verified before installation

// The signature in the manifest is base64-encoded minisign signature
// Example signature format:
// untrusted comment: signature from tauri secret key
// RUTYyBCGAMv1234... (base64-encoded signature)
```

### Manual Signature Verification

```bash
# Verify signature manually using minisign
# Install minisign: brew install minisign / apt install minisign

# Create public key file from base64
echo "dW50cnVzdGVkIGNvbW1lbnQ6..." | base64 -d > myapp.pub

# Verify signature
minisign -Vm MyApp_1.0.0.tar.gz -p myapp.pub
# Should output: Signature and comment signature verified
```

### Testing Invalid Signatures

```rust
#[cfg(test)]
mod signature_tests {
    #[tokio::test]
    async fn test_invalid_signature_rejected() {
        let manifest = r#"{
            "version": "1.0.1",
            "platforms": {
                "darwin-x86_64": {
                    "url": "https://example.com/update.tar.gz",
                    "signature": "INVALID_SIGNATURE_HERE"
                }
            }
        }"#;

        let result = verify_and_install(manifest).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[tokio::test]
    async fn test_missing_signature_rejected() {
        let manifest = r#"{
            "version": "1.0.1",
            "platforms": {
                "darwin-x86_64": {
                    "url": "https://example.com/update.tar.gz"
                }
            }
        }"#;

        let result = verify_and_install(manifest).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tampered_artifact_rejected() {
        // Even with valid signature in manifest,
        // if artifact is tampered, verification fails
        let mock_server = MockServer::new();
        mock_server.serve_tampered_artifact();

        let result = download_and_verify(&mock_server.url()).await;
        assert!(result.is_err());
    }
}
```

---

## Secure Update Endpoints

### HTTPS Configuration

```json
// tauri.conf.json
{
  "tauri": {
    "updater": {
      "active": true,
      "pubkey": "YOUR_PUBLIC_KEY",
      "endpoints": [
        // Primary endpoint
        "https://releases.myapp.com/{{target}}/{{arch}}/{{current_version}}",
        // Fallback endpoint
        "https://cdn.myapp.com/releases/{{target}}/{{arch}}/{{current_version}}"
      ]
    }
  }
}
```

### CDN Configuration for Updates

```yaml
# Cloudflare Pages / AWS CloudFront configuration
# Serve update manifests with appropriate headers

# Example Cloudflare _headers file
/releases/*
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=300  # 5 minutes
  Content-Type: application/json

/*.tar.gz
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=86400  # 24 hours
```

### Update Server Implementation

```rust
// Simple update server with Actix-web
use actix_web::{web, App, HttpServer, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct UpdateManifest {
    version: String,
    notes: String,
    pub_date: String,
    platforms: std::collections::HashMap<String, PlatformUpdate>,
}

#[derive(Serialize)]
struct PlatformUpdate {
    signature: String,
    url: String,
}

async fn get_update(
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (target, arch, current_version) = path.into_inner();

    // Check if update is available
    let latest = get_latest_version();
    if semver::Version::parse(&current_version).unwrap()
        >= semver::Version::parse(&latest).unwrap()
    {
        return HttpResponse::NoContent().finish();
    }

    // Return update manifest
    let manifest = build_manifest(&target, &arch, &latest);
    HttpResponse::Ok().json(manifest)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/updates/{target}/{arch}/{version}", web::get().to(get_update))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

---

## Manifest Security

### Secure Manifest Structure

```json
{
  "version": "1.2.0",
  "notes": "Security update: fixes CVE-2024-XXXX",
  "pub_date": "2024-01-15T12:00:00Z",
  "platforms": {
    "darwin-x86_64": {
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVS...",
      "url": "https://releases.myapp.com/v1.2.0/MyApp_1.2.0_x64.app.tar.gz",
      "with_elevated_task": false
    },
    "darwin-aarch64": {
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVS...",
      "url": "https://releases.myapp.com/v1.2.0/MyApp_1.2.0_aarch64.app.tar.gz"
    },
    "linux-x86_64": {
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVS...",
      "url": "https://releases.myapp.com/v1.2.0/MyApp_1.2.0_amd64.AppImage.tar.gz"
    },
    "windows-x86_64": {
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVS...",
      "url": "https://releases.myapp.com/v1.2.0/MyApp_1.2.0_x64-setup.nsis.zip"
    }
  }
}
```

### Manifest Generation in CI

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download Build Artifacts
        uses: actions/download-artifact@v3

      - name: Generate Manifest
        run: |
          VERSION="${GITHUB_REF#refs/tags/v}"

          # Get signatures from .sig files
          DARWIN_X64_SIG=$(cat darwin-x86_64/*.sig)
          DARWIN_ARM_SIG=$(cat darwin-aarch64/*.sig)
          LINUX_SIG=$(cat linux-x86_64/*.sig)
          WINDOWS_SIG=$(cat windows-x86_64/*.sig)

          # Generate manifest
          cat > latest.json << EOF
          {
            "version": "$VERSION",
            "notes": "$(git log -1 --pretty=%B)",
            "pub_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "platforms": {
              "darwin-x86_64": {
                "signature": "$DARWIN_X64_SIG",
                "url": "https://releases.myapp.com/v$VERSION/MyApp_${VERSION}_x64.app.tar.gz"
              },
              "darwin-aarch64": {
                "signature": "$DARWIN_ARM_SIG",
                "url": "https://releases.myapp.com/v$VERSION/MyApp_${VERSION}_aarch64.app.tar.gz"
              },
              "linux-x86_64": {
                "signature": "$LINUX_SIG",
                "url": "https://releases.myapp.com/v$VERSION/MyApp_${VERSION}_amd64.AppImage.tar.gz"
              },
              "windows-x86_64": {
                "signature": "$WINDOWS_SIG",
                "url": "https://releases.myapp.com/v$VERSION/MyApp_${VERSION}_x64-setup.nsis.zip"
              }
            }
          }
          EOF

      - name: Upload Manifest
        run: |
          # Upload to your update server
          aws s3 cp latest.json s3://releases-bucket/latest.json
```

---

## Version Validation

### Preventing Downgrade Attacks

```rust
// Tauri prevents downgrades by default
// The updater only installs if new_version > current_version

// Custom version validation
fn is_valid_update(current: &str, new: &str) -> bool {
    let current = semver::Version::parse(current).unwrap();
    let new = semver::Version::parse(new).unwrap();

    // Must be newer version
    if new <= current {
        return false;
    }

    // Don't skip major versions (optional policy)
    if new.major > current.major + 1 {
        return false;
    }

    true
}
```

### Version Pinning for Testing

```json
// For testing specific versions
{
  "tauri": {
    "updater": {
      "endpoints": [
        "https://releases.myapp.com/test/1.2.0-beta.json"
      ]
    }
  }
}
```

---

## Emergency Update Procedures

### Force Update for Critical Security Issues

```rust
#[tauri::command]
async fn check_for_critical_updates(app: AppHandle) -> Result<bool, String> {
    // Check for critical security updates
    let response = reqwest::get("https://api.myapp.com/security/critical")
        .await
        .map_err(|e| e.to_string())?;

    let critical: CriticalUpdate = response.json().await.map_err(|e| e.to_string())?;

    if critical.affects_version(&app.package_info().version.to_string()) {
        // Show mandatory update dialog
        let _ = app.emit_all("critical-update", &critical);
        return Ok(true);
    }

    Ok(false)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct CriticalUpdate {
    min_version: String,
    message: String,
    cve: Option<String>,
}
```

### Disable Auto-Update in Emergency

```json
// Update manifest to disable updates temporarily
{
  "version": "0.0.0",
  "notes": "Updates temporarily disabled",
  "platforms": {}
}
```
