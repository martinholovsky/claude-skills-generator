# CI/CD Security Examples

## Secret Management

### Environment-Scoped Secrets

```yaml
# Different secrets for different environments
jobs:
  deploy-staging:
    environment: staging
    steps:
      - name: Deploy
        env:
          DATABASE_URL: ${{ secrets.STAGING_DATABASE_URL }}
          API_KEY: ${{ secrets.STAGING_API_KEY }}
        run: ./deploy.sh

  deploy-production:
    environment: production
    needs: deploy-staging
    steps:
      - name: Deploy
        env:
          DATABASE_URL: ${{ secrets.PRODUCTION_DATABASE_URL }}
          API_KEY: ${{ secrets.PRODUCTION_API_KEY }}
        run: ./deploy.sh
```

### Secure Secret Usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # WRONG: Secret exposed in command
      - name: Bad Example
        run: echo "Token is ${{ secrets.API_TOKEN }}"  # DON'T DO THIS

      # CORRECT: Secret in environment variable
      - name: Good Example
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          # Token is automatically masked in logs
          curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com

      # CORRECT: Write to file securely
      - name: Create Config
        env:
          CONFIG_CONTENT: ${{ secrets.CONFIG_JSON }}
        run: |
          echo "$CONFIG_CONTENT" > config.json
          chmod 600 config.json
```

### OIDC for Cloud Authentication

```yaml
# AWS OIDC Configuration
jobs:
  deploy-aws:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1
          # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed!

      - name: Push to S3
        run: aws s3 sync ./dist s3://my-bucket/

# GCP OIDC Configuration
jobs:
  deploy-gcp:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: google-github-actions/auth@v1
        with:
          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/github/providers/my-repo
          service_account: github-actions@my-project.iam.gserviceaccount.com

      - name: Push to GCS
        run: gsutil cp ./dist/* gs://my-bucket/
```

---

## Code Signing

### Windows Code Signing

```yaml
jobs:
  sign-windows:
    runs-on: windows-latest
    environment: code-signing
    steps:
      - uses: actions/checkout@v4

      - name: Setup Certificate
        env:
          CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE_BASE64 }}
          PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
        run: |
          # Decode and import certificate
          $certBytes = [Convert]::FromBase64String($env:CERTIFICATE)
          $certPath = "$env:RUNNER_TEMP\cert.pfx"
          [IO.File]::WriteAllBytes($certPath, $certBytes)

          # Import to store
          $pwd = ConvertTo-SecureString $env:PASSWORD -AsPlainText -Force
          Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\CurrentUser\My -Password $pwd

          # Cleanup
          Remove-Item $certPath -Force

      - name: Sign Executable
        run: |
          $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
          Set-AuthenticodeSignature -FilePath ".\target\release\app.exe" -Certificate $cert -TimestampServer "http://timestamp.digicert.com"

      - name: Verify Signature
        run: |
          $sig = Get-AuthenticodeSignature ".\target\release\app.exe"
          if ($sig.Status -ne "Valid") {
            Write-Error "Signature verification failed: $($sig.StatusMessage)"
            exit 1
          }
```

### macOS Code Signing and Notarization

```yaml
jobs:
  sign-macos:
    runs-on: macos-latest
    environment: code-signing
    steps:
      - uses: actions/checkout@v4

      - name: Setup Keychain
        env:
          CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE_BASE64 }}
          CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
          KEYCHAIN_PASSWORD: ${{ secrets.KEYCHAIN_PASSWORD }}
        run: |
          # Create temporary keychain
          KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db
          security create-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
          security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
          security unlock-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH

          # Import certificate
          CERT_PATH=$RUNNER_TEMP/certificate.p12
          echo "$CERTIFICATE" | base64 --decode > $CERT_PATH
          security import $CERT_PATH -P "$CERTIFICATE_PASSWORD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
          security list-keychain -d user -s $KEYCHAIN_PATH

          # Allow codesign access
          security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH

          rm $CERT_PATH

      - name: Sign Application
        env:
          SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
        run: |
          codesign --force --options runtime --sign "$SIGNING_IDENTITY" \
            --timestamp --entitlements entitlements.plist \
            "./target/release/bundle/macos/MyApp.app"

      - name: Notarize Application
        env:
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
          TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
        run: |
          # Create ZIP for notarization
          ditto -c -k --keepParent "./target/release/bundle/macos/MyApp.app" app.zip

          # Submit for notarization
          xcrun notarytool submit app.zip \
            --apple-id "$APPLE_ID" \
            --password "$APP_PASSWORD" \
            --team-id "$TEAM_ID" \
            --wait

          # Staple the ticket
          xcrun stapler staple "./target/release/bundle/macos/MyApp.app"

      - name: Cleanup Keychain
        if: always()
        run: security delete-keychain $RUNNER_TEMP/app-signing.keychain-db
```

---

## Supply Chain Security

### Pin Actions by SHA

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Pin all actions by their full SHA
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608 # v4.1.0
      - uses: actions/setup-node@8f152de45cc393bb48ce5d89d36b731f54556e65 # v4.0.0
      - uses: actions/cache@704facf57e6136b1bc63b828d79edcd491f0ee84 # v3.3.2

      # For third-party actions, audit before using
      - uses: some-org/action@abc123def456789  # Audited on YYYY-MM-DD
```

### SBOM Generation

```yaml
jobs:
  generate-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          path: ./
          artifact-name: sbom.spdx.json
          output-file: sbom.spdx.json

      - name: Scan SBOM for vulnerabilities
        uses: anchore/scan-action@v3
        with:
          sbom: sbom.spdx.json
          fail-build: true
          severity-cutoff: high

      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.spdx.json
```

### Artifact Attestation

```yaml
jobs:
  build-with-attestation:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: npm run build

      - name: Generate artifact attestation
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: './dist/*'
```

### Dependency Review

```yaml
on:
  pull_request:

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v3
        with:
          fail-on-severity: moderate
          deny-licenses: GPL-3.0, AGPL-3.0
          allow-ghsas: GHSA-xxxx-yyyy-zzzz  # Known false positives
```

---

## Artifact Security

### Signed Releases

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: npm run build

      - name: Sign with Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign artifacts
        run: |
          cosign sign-blob --yes --output-signature dist/app.sig dist/app.tar.gz

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            dist/app.tar.gz
            dist/app.sig
```

### Checksum Generation

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Generate checksums
        run: |
          cd dist
          sha256sum * > SHA256SUMS
          sha512sum * > SHA512SUMS

      - name: Sign checksums
        env:
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
        run: |
          echo "$GPG_PRIVATE_KEY" | gpg --import
          gpg --batch --yes --passphrase "$GPG_PASSPHRASE" \
            --detach-sign --armor dist/SHA256SUMS
```

---

## Workflow Security

### Restrict Workflow Triggers

```yaml
# Only allow workflow dispatch from specific branches
on:
  workflow_dispatch:
    branches:
      - main
      - 'release/*'

# Restrict paths that can trigger
on:
  push:
    branches: [main]
    paths-ignore:
      - '**.md'
      - 'docs/**'
```

### Environment Protection Rules

```yaml
# In GitHub repository settings, configure:
# - Required reviewers for production
# - Wait timer before deployment
# - Restrict to specific branches

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://myapp.com
    steps:
      - name: Deploy
        run: ./deploy-production.sh
```

### Reusable Workflow Security

```yaml
# In called workflow (.github/workflows/build.yml)
on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
    secrets:
      DEPLOY_KEY:
        required: true

jobs:
  build:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    steps:
      - name: Deploy
        env:
          KEY: ${{ secrets.DEPLOY_KEY }}
        run: ./deploy.sh
```
