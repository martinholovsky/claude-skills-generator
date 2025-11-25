# Cross-Platform Builds Security Examples

## Windows Code Signing

### Certificate Setup in CI

```yaml
jobs:
  sign-windows:
    runs-on: windows-latest
    environment: code-signing
    steps:
      - uses: actions/checkout@v4

      - name: Import Code Signing Certificate
        env:
          CERTIFICATE_BASE64: ${{ secrets.WINDOWS_CERTIFICATE_BASE64 }}
          CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
        run: |
          # Decode certificate
          $certBytes = [Convert]::FromBase64String($env:CERTIFICATE_BASE64)
          $certPath = "$env:RUNNER_TEMP\certificate.pfx"
          [IO.File]::WriteAllBytes($certPath, $certBytes)

          # Import to Windows certificate store
          $securePassword = ConvertTo-SecureString $env:CERTIFICATE_PASSWORD -AsPlainText -Force
          Import-PfxCertificate `
            -FilePath $certPath `
            -CertStoreLocation Cert:\CurrentUser\My `
            -Password $securePassword

          # Cleanup
          Remove-Item $certPath -Force

      - name: Build and Sign with Tauri
        env:
          TAURI_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
        run: npm run tauri build

      - name: Verify Signature
        run: |
          $exePath = Get-ChildItem -Recurse -Filter "*.exe" | Where-Object { $_.Name -eq "MyApp.exe" } | Select-Object -First 1
          $signature = Get-AuthenticodeSignature $exePath.FullName
          if ($signature.Status -ne "Valid") {
            Write-Error "Signature validation failed: $($signature.StatusMessage)"
            exit 1
          }
          Write-Host "Signature valid: $($signature.SignerCertificate.Subject)"
```

### Manual Signing with SignTool

```powershell
# Sign an executable
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 "THUMBPRINT" MyApp.exe

# Sign multiple files
Get-ChildItem -Recurse -Include *.exe,*.dll | ForEach-Object {
    signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 "THUMBPRINT" $_.FullName
}

# Verify signature
signtool verify /pa /v MyApp.exe
```

---

## macOS Code Signing and Notarization

### Complete Signing Workflow

```yaml
jobs:
  sign-macos:
    runs-on: macos-latest
    environment: code-signing
    steps:
      - uses: actions/checkout@v4

      - name: Setup Keychain
        env:
          APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE_BASE64 }}
          APPLE_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
          KEYCHAIN_PASSWORD: ${{ secrets.KEYCHAIN_PASSWORD }}
        run: |
          # Create temporary keychain
          KEYCHAIN_PATH="$RUNNER_TEMP/build.keychain-db"
          security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
          security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
          security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

          # Import certificate
          CERT_PATH="$RUNNER_TEMP/certificate.p12"
          echo "$APPLE_CERTIFICATE" | base64 --decode > "$CERT_PATH"
          security import "$CERT_PATH" -P "$APPLE_CERTIFICATE_PASSWORD" -A -t cert -f pkcs12 -k "$KEYCHAIN_PATH"

          # Set keychain for codesigning
          security list-keychain -d user -s "$KEYCHAIN_PATH"
          security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

          # Cleanup
          rm "$CERT_PATH"

      - name: Build with Tauri
        env:
          APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
        run: |
          # Set signing identity for Tauri
          export APPLE_SIGNING_IDENTITY="$APPLE_SIGNING_IDENTITY"
          npm run tauri build

      - name: Notarize Application
        env:
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APPLE_APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
        run: |
          APP_PATH=$(find src-tauri/target -name "*.app" -type d | head -1)
          DMG_PATH=$(find src-tauri/target -name "*.dmg" | head -1)

          # Create ZIP for notarization
          ditto -c -k --keepParent "$APP_PATH" app.zip

          # Submit for notarization
          xcrun notarytool submit app.zip \
            --apple-id "$APPLE_ID" \
            --password "$APPLE_APP_PASSWORD" \
            --team-id "$APPLE_TEAM_ID" \
            --wait

          # Staple the app
          xcrun stapler staple "$APP_PATH"

          # Recreate DMG with stapled app
          # ... (rebuild DMG)

          rm app.zip

      - name: Verify Signing
        run: |
          APP_PATH=$(find src-tauri/target -name "*.app" -type d | head -1)

          # Verify codesign
          codesign --verify --deep --strict "$APP_PATH"

          # Verify notarization
          spctl --assess --type execute "$APP_PATH"
          xcrun stapler validate "$APP_PATH"

      - name: Cleanup Keychain
        if: always()
        run: security delete-keychain "$RUNNER_TEMP/build.keychain-db"
```

### Entitlements Configuration

```xml
<!-- entitlements.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Required for JIT compilation (WebView) -->
    <key>com.apple.security.cs.allow-jit</key>
    <true/>

    <!-- Required for WebView -->
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>

    <!-- Network access -->
    <key>com.apple.security.network.client</key>
    <true/>

    <!-- Hardened runtime -->
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
```

---

## Linux Package Signing

### GPG Signing for DEB Packages

```yaml
jobs:
  sign-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Import GPG Key
        env:
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
        run: |
          echo "$GPG_PRIVATE_KEY" | gpg --import
          echo "$GPG_PASSPHRASE" | gpg --passphrase-fd 0 --pinentry-mode loopback --sign --armor /dev/null

      - name: Build
        run: npm run tauri build

      - name: Sign DEB Package
        env:
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
        run: |
          DEB_FILE=$(find src-tauri/target -name "*.deb" | head -1)

          # Sign with dpkg-sig
          dpkg-sig --sign builder -g "--passphrase $GPG_PASSPHRASE --pinentry-mode loopback" "$DEB_FILE"

          # Verify signature
          dpkg-sig --verify "$DEB_FILE"

      - name: Generate Checksums
        run: |
          cd src-tauri/target/release/bundle/deb
          sha256sum *.deb > SHA256SUMS
          gpg --armor --detach-sign SHA256SUMS
```

### AppImage Signing

```bash
# Sign AppImage with GPG
gpg --armor --detach-sign MyApp.AppImage

# Users can verify with
gpg --verify MyApp.AppImage.asc MyApp.AppImage
```

---

## Secure Build Environment

### Environment Isolation

```yaml
jobs:
  secure-build:
    runs-on: ubuntu-latest
    container:
      image: rust:1.70
      options: --user root

    steps:
      - uses: actions/checkout@v4

      - name: Verify Environment
        run: |
          # Check no unexpected tools
          which curl wget || true

          # Check environment variables
          env | grep -v GITHUB | sort

      - name: Build in Clean Environment
        run: |
          # Install only required dependencies
          apt-get update
          apt-get install -y --no-install-recommends \
            libgtk-3-dev libwebkit2gtk-4.0-dev

          # Build
          cargo build --release
```

### Reproducible Builds

```toml
# Cargo.toml
[profile.release]
lto = true
codegen-units = 1
strip = "none"  # Keep for reproducibility verification

# Build with locked dependencies
# cargo build --release --locked
```

```yaml
- name: Verify Reproducible Build
  run: |
    # Build twice and compare
    cargo build --release --locked
    cp target/release/myapp myapp-build1

    cargo clean
    cargo build --release --locked
    cp target/release/myapp myapp-build2

    # Compare binaries
    sha256sum myapp-build1 myapp-build2
```

---

## Credential Management

### Storing Certificates

```bash
# Encode certificate for GitHub Secrets
base64 -i certificate.pfx | tr -d '\n' > certificate_base64.txt

# For macOS p12
base64 -i certificate.p12 | tr -d '\n' > certificate_base64.txt
```

### Tauri Update Keys

```bash
# Generate update key pair
npm run tauri signer generate -- -w ~/.tauri/myapp.key

# Store in GitHub Secrets:
# TAURI_PRIVATE_KEY: contents of ~/.tauri/myapp.key
# TAURI_KEY_PASSWORD: the password you used

# Public key goes in tauri.conf.json
```

### Key Rotation Procedure

1. **Generate new keys** before old ones expire
2. **Test signing** with new keys on staging
3. **Update CI secrets** with new keys
4. **Verify** builds work with new keys
5. **Revoke old keys** after transition period

---

## Artifact Verification

### Checksum Generation

```yaml
- name: Generate Checksums
  run: |
    cd dist

    # Generate multiple checksum types
    sha256sum * > SHA256SUMS
    sha512sum * > SHA512SUMS

    # Sign checksums
    gpg --armor --detach-sign SHA256SUMS

- name: Upload Checksums
  uses: actions/upload-artifact@v3
  with:
    name: checksums
    path: |
      dist/SHA256SUMS
      dist/SHA256SUMS.asc
      dist/SHA512SUMS
```

### Signature Verification Scripts

```bash
#!/bin/bash
# verify-release.sh - For users to verify downloads

# Verify GPG signature on checksums
gpg --verify SHA256SUMS.asc SHA256SUMS

# Verify file checksum
sha256sum -c SHA256SUMS --ignore-missing

# Verify code signature (Windows)
# signtool verify /pa MyApp.exe

# Verify code signature (macOS)
# codesign --verify --deep --strict MyApp.app
# spctl --assess --type execute MyApp.app
```
