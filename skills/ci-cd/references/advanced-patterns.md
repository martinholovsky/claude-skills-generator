# CI/CD Advanced Patterns

## Multi-Platform Build Matrices

### Tauri Cross-Platform Build

```yaml
name: Build and Release

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
          - platform: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            artifact: app_linux_amd64
          - platform: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: app_windows_amd64
          - platform: macos-latest
            target: x86_64-apple-darwin
            artifact: app_macos_amd64
          - platform: macos-latest
            target: aarch64-apple-darwin
            artifact: app_macos_arm64

    runs-on: ${{ matrix.platform }}

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
          sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.0-dev libappindicator3-dev librsvg2-dev patchelf

      - name: Install Dependencies
        run: npm ci

      - name: Build
        run: npm run tauri build -- --target ${{ matrix.target }}

      - name: Upload Artifact
        uses: actions/upload-artifact@v3
        with:
          name: ${{ matrix.artifact }}
          path: |
            src-tauri/target/${{ matrix.target }}/release/bundle/
```

---

## Caching Strategies

### Comprehensive Caching

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Rust cache
      - name: Cache Cargo
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/bin/
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            target/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-

      # Node modules cache
      - name: Cache Node modules
        uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            ${{ runner.os }}-npm-

      # Turbo cache for monorepos
      - name: Cache Turbo
        uses: actions/cache@v3
        with:
          path: .turbo
          key: ${{ runner.os }}-turbo-${{ github.sha }}
          restore-keys: |
            ${{ runner.os }}-turbo-

      - name: Install Dependencies
        run: npm ci

      - name: Build
        run: npm run build
```

### Self-Hosted Runner Cache

```yaml
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4

      # Use local cache directory on self-hosted runner
      - name: Setup Cache Directory
        run: |
          mkdir -p /cache/cargo
          mkdir -p /cache/npm

      - name: Restore Cargo Cache
        run: |
          if [ -d "/cache/cargo/${{ hashFiles('**/Cargo.lock') }}" ]; then
            cp -r /cache/cargo/${{ hashFiles('**/Cargo.lock') }}/* ~/.cargo/ || true
          fi

      - name: Build
        run: npm run build

      - name: Save Cargo Cache
        run: |
          mkdir -p /cache/cargo/${{ hashFiles('**/Cargo.lock') }}
          cp -r ~/.cargo/registry /cache/cargo/${{ hashFiles('**/Cargo.lock') }}/ || true
```

---

## Release Automation

### Semantic Versioning Release

```yaml
name: Release

on:
  push:
    branches:
      - main

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Create Release
        uses: google-github-actions/release-please-action@v4
        id: release
        with:
          release-type: rust

      - name: Build if Released
        if: ${{ steps.release.outputs.release_created }}
        run: npm run build

      - name: Upload Release Assets
        if: ${{ steps.release.outputs.release_created }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release upload ${{ steps.release.outputs.tag_name }} \
            ./dist/*.tar.gz \
            ./dist/*.zip
```

### Changelog Generation

```yaml
jobs:
  changelog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Generate Changelog
        uses: orhun/git-cliff-action@v2
        with:
          config: cliff.toml
          args: --verbose
        env:
          OUTPUT: CHANGELOG.md

      - name: Commit Changelog
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: 'docs: update changelog'
          file_pattern: CHANGELOG.md
```

---

## Deployment Strategies

### Blue-Green Deployment

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Deploy to Green
        env:
          DEPLOY_ENV: green
        run: ./deploy.sh

      - name: Health Check Green
        run: |
          for i in {1..30}; do
            if curl -sf https://green.myapp.com/health; then
              echo "Green is healthy"
              exit 0
            fi
            sleep 10
          done
          echo "Green health check failed"
          exit 1

      - name: Switch Traffic to Green
        run: ./switch-traffic.sh green

      - name: Health Check Production
        run: |
          sleep 30
          curl -sf https://myapp.com/health

      - name: Cleanup Blue
        if: success()
        run: ./cleanup.sh blue
```

### Canary Deployment

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy Canary (10%)
        run: ./deploy.sh --weight 10

      - name: Monitor Canary
        run: |
          # Monitor for 10 minutes
          for i in {1..10}; do
            ERROR_RATE=$(curl -s https://metrics.myapp.com/error-rate)
            if (( $(echo "$ERROR_RATE > 1" | bc -l) )); then
              echo "Error rate too high: $ERROR_RATE%"
              ./rollback.sh
              exit 1
            fi
            sleep 60
          done

      - name: Increase to 50%
        run: ./deploy.sh --weight 50

      - name: Monitor 50%
        run: |
          for i in {1..10}; do
            ERROR_RATE=$(curl -s https://metrics.myapp.com/error-rate)
            if (( $(echo "$ERROR_RATE > 1" | bc -l) )); then
              ./rollback.sh
              exit 1
            fi
            sleep 60
          done

      - name: Full Deployment
        run: ./deploy.sh --weight 100
```

---

## Reusable Workflows

### Shared Build Workflow

```yaml
# .github/workflows/build-reusable.yml
name: Reusable Build

on:
  workflow_call:
    inputs:
      node-version:
        required: false
        type: string
        default: '20'
      rust-version:
        required: false
        type: string
        default: 'stable'
    secrets:
      NPM_TOKEN:
        required: false
    outputs:
      artifact-name:
        description: 'Name of the uploaded artifact'
        value: ${{ jobs.build.outputs.artifact-name }}

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      artifact-name: ${{ steps.upload.outputs.artifact-name }}
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ inputs.rust-version }}

      - uses: actions/setup-node@v4
        with:
          node-version: ${{ inputs.node-version }}

      - run: npm ci
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}

      - run: npm run build

      - id: upload
        uses: actions/upload-artifact@v3
        with:
          name: build-${{ github.sha }}
          path: dist/
```

### Using Reusable Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]

jobs:
  build:
    uses: ./.github/workflows/build-reusable.yml
    with:
      node-version: '20'
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}

  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
        with:
          name: build-${{ github.sha }}

      - run: npm test
```

---

## Conditional Workflows

### Path-Based Triggers

```yaml
on:
  push:
    branches: [main]
    paths:
      - 'src/**'
      - 'Cargo.toml'
      - 'package.json'

jobs:
  build:
    if: |
      !contains(github.event.head_commit.message, '[skip ci]') &&
      !contains(github.event.head_commit.message, '[ci skip]')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
```

### Monorepo Selective Builds

```yaml
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      frontend: ${{ steps.filter.outputs.frontend }}
      backend: ${{ steps.filter.outputs.backend }}
      shared: ${{ steps.filter.outputs.shared }}
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v2
        id: filter
        with:
          filters: |
            frontend:
              - 'packages/frontend/**'
            backend:
              - 'packages/backend/**'
            shared:
              - 'packages/shared/**'

  build-frontend:
    needs: changes
    if: needs.changes.outputs.frontend == 'true' || needs.changes.outputs.shared == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building frontend"

  build-backend:
    needs: changes
    if: needs.changes.outputs.backend == 'true' || needs.changes.outputs.shared == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building backend"
```

---

## Performance Optimization

### Parallel Jobs

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build

  # Only after all parallel jobs succeed
  deploy:
    needs: [lint, test, build]
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

### Matrix with Fail-Fast Disabled

```yaml
jobs:
  test:
    strategy:
      fail-fast: false  # Continue other matrix jobs if one fails
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18, 20]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm test
```
