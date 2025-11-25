# CI/CD Pipeline Examples

This file contains comprehensive pipeline examples for various platforms and use cases.

---

## Table of Contents

1. [GitLab CI Examples](#gitlab-ci-examples)
2. [Jenkins Pipeline Examples](#jenkins-pipeline-examples)
3. [Advanced Matrix Builds](#advanced-matrix-builds)
4. [Monorepo Strategies](#monorepo-strategies)
5. [Docker Build Optimization](#docker-build-optimization)
6. [GitOps with ArgoCD](#gitops-with-argocd)

---

## GitLab CI Examples

### Complete GitLab CI/CD Pipeline

```yaml
# .gitlab-ci.yml
variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

stages:
  - security
  - build
  - test
  - scan
  - deploy
  - verify

# Security stage
secret-scan:
  stage: security
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://. --json --fail
  allow_failure: false

sast:
  stage: security
  image: returntocorp/semgrep
  script:
    - semgrep --config=p/security-audit --config=p/owasp-top-ten --sarif -o semgrep.sarif .
  artifacts:
    reports:
      sast: semgrep.sarif
    expire_in: 1 week

dependency-scan:
  stage: security
  image: node:20
  script:
    - npm audit --audit-level=high
    - npm ci
    - npx snyk test --severity-threshold=high
  only:
    - merge_requests
    - main

# Build stage
build:
  stage: build
  image: node:20
  cache:
    key:
      files:
        - package-lock.json
    paths:
      - node_modules/
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
    expire_in: 1 day
  only:
    - merge_requests
    - main

# Test stage
unit-tests:
  stage: test
  image: node:20
  dependencies:
    - build
  cache:
    key:
      files:
        - package-lock.json
    paths:
      - node_modules/
  script:
    - npm ci
    - npm run test:unit -- --coverage
  coverage: '/Lines\s*:\s*(\d+\.\d+)%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml
    expire_in: 1 week

integration-tests:
  stage: test
  image: node:20
  services:
    - postgres:14
    - redis:7
  variables:
    POSTGRES_DB: testdb
    POSTGRES_USER: testuser
    POSTGRES_PASSWORD: testpass
    DATABASE_URL: postgresql://testuser:testpass@postgres:5432/testdb
    REDIS_URL: redis://redis:6379
  dependencies:
    - build
  script:
    - npm ci
    - npm run db:migrate
    - npm run test:integration
  only:
    - merge_requests
    - main

# Container scan stage
container-build:
  stage: scan
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - docker build --cache-from $CI_REGISTRY_IMAGE:latest -t $IMAGE_TAG -t $CI_REGISTRY_IMAGE:latest .
    - docker push $IMAGE_TAG
    - docker push $CI_REGISTRY_IMAGE:latest
  only:
    - main

container-scan:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --severity HIGH,CRITICAL --exit-code 1 $IMAGE_TAG
  dependencies:
    - container-build
  only:
    - main

# Deploy stages
deploy-staging:
  stage: deploy
  image: bitnami/kubectl:latest
  environment:
    name: staging
    url: https://staging.example.com
  before_script:
    - kubectl config use-context $KUBE_CONTEXT_STAGING
  script:
    - kubectl set image deployment/myapp myapp=$IMAGE_TAG -n staging
    - kubectl rollout status deployment/myapp -n staging --timeout=5m
  only:
    - main

verify-staging:
  stage: verify
  image: curlimages/curl:latest
  script:
    - |
      for i in {1..30}; do
        if curl -f https://staging.example.com/health; then
          echo "Staging health check passed"
          exit 0
        fi
        sleep 10
      done
      echo "Staging health check failed"
      exit 1
  dependencies:
    - deploy-staging
  only:
    - main

deploy-production:
  stage: deploy
  image: bitnami/kubectl:latest
  environment:
    name: production
    url: https://example.com
  before_script:
    - kubectl config use-context $KUBE_CONTEXT_PROD
  script:
    - kubectl set image deployment/myapp myapp=$IMAGE_TAG -n production
    - kubectl rollout status deployment/myapp -n production --timeout=10m
  when: manual
  only:
    - main
```

---

### GitLab DAG Pipeline (Direct Acyclic Graph)

```yaml
# .gitlab-ci.yml - DAG pipeline for parallel execution
stages:
  - build
  - test
  - deploy

build-frontend:
  stage: build
  script:
    - cd frontend && npm ci && npm run build
  artifacts:
    paths:
      - frontend/dist/

build-backend:
  stage: build
  script:
    - cd backend && npm ci && npm run build
  artifacts:
    paths:
      - backend/dist/

test-frontend-unit:
  stage: test
  needs:
    - build-frontend
  script:
    - cd frontend && npm run test:unit

test-frontend-e2e:
  stage: test
  needs:
    - build-frontend
    - build-backend
  script:
    - docker-compose up -d
    - cd frontend && npm run test:e2e

test-backend-unit:
  stage: test
  needs:
    - build-backend
  script:
    - cd backend && npm run test:unit

test-backend-integration:
  stage: test
  needs:
    - build-backend
  services:
    - postgres:14
  script:
    - cd backend && npm run test:integration

deploy:
  stage: deploy
  needs:
    - test-frontend-unit
    - test-frontend-e2e
    - test-backend-unit
    - test-backend-integration
  script:
    - ./deploy.sh
```

---

### GitLab Parent-Child Pipelines

```yaml
# .gitlab-ci.yml - Parent pipeline
generate-child-pipelines:
  stage: setup
  script:
    - |
      cat > child-pipeline.yml <<EOF
      service-a-build:
        stage: build
        script:
          - cd services/service-a && npm ci && npm run build

      service-b-build:
        stage: build
        script:
          - cd services/service-b && npm ci && npm run build
      EOF
  artifacts:
    paths:
      - child-pipeline.yml

trigger-child-pipeline:
  stage: trigger
  trigger:
    include:
      - artifact: child-pipeline.yml
        job: generate-child-pipelines
    strategy: depend
```

---

## Jenkins Pipeline Examples

### Declarative Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
        timestamps()
    }

    environment {
        DOCKER_REGISTRY = 'docker.io'
        IMAGE_NAME = 'myorg/myapp'
        IMAGE_TAG = "${env.GIT_COMMIT.take(7)}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan - Secrets') {
            steps {
                sh 'gitleaks detect --source . --verbose --no-git'
            }
        }

        stage('Security Scan - SAST') {
            parallel {
                stage('Semgrep') {
                    steps {
                        sh 'semgrep --config=p/security-audit --sarif -o semgrep.sarif .'
                    }
                }
                stage('SonarQube') {
                    steps {
                        withSonarQubeEnv('SonarQube') {
                            sh 'mvn sonar:sonar'
                        }
                    }
                }
            }
        }

        stage('Build') {
            steps {
                sh 'npm ci'
                sh 'npm run build'
            }
        }

        stage('Test') {
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh 'npm run test:unit'
                    }
                    post {
                        always {
                            junit 'test-results/unit/*.xml'
                        }
                    }
                }
                stage('Integration Tests') {
                    steps {
                        sh 'docker-compose up -d postgres redis'
                        sh 'npm run test:integration'
                        sh 'docker-compose down'
                    }
                    post {
                        always {
                            junit 'test-results/integration/*.xml'
                        }
                    }
                }
            }
        }

        stage('Docker Build') {
            steps {
                script {
                    docker.build("${IMAGE_NAME}:${IMAGE_TAG}")
                    docker.image("${IMAGE_NAME}:${IMAGE_TAG}").tag('latest')
                }
            }
        }

        stage('Container Scan') {
            steps {
                sh "trivy image --severity HIGH,CRITICAL --exit-code 1 ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }

        stage('Push to Registry') {
            when {
                branch 'main'
            }
            steps {
                script {
                    docker.withRegistry("https://${DOCKER_REGISTRY}", 'docker-credentials') {
                        docker.image("${IMAGE_NAME}:${IMAGE_TAG}").push()
                        docker.image("${IMAGE_NAME}:latest").push()
                    }
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            steps {
                sh "kubectl set image deployment/myapp myapp=${IMAGE_NAME}:${IMAGE_TAG} -n staging"
                sh "kubectl rollout status deployment/myapp -n staging --timeout=5m"
            }
        }

        stage('Smoke Tests') {
            when {
                branch 'main'
            }
            steps {
                sh 'npm run test:smoke -- --env=staging'
            }
        }

        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            input {
                message "Deploy to production?"
                ok "Deploy"
            }
            steps {
                sh "kubectl set image deployment/myapp myapp=${IMAGE_NAME}:${IMAGE_TAG} -n production"
                sh "kubectl rollout status deployment/myapp -n production --timeout=10m"
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            slackSend(
                color: 'good',
                message: "Build succeeded: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
            )
        }
        failure {
            slackSend(
                color: 'danger',
                message: "Build failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
            )
        }
    }
}
```

---

### Scripted Jenkins Pipeline with Shared Library

```groovy
// Jenkinsfile - Using shared library
@Library('my-shared-library') _

node('docker') {
    try {
        stage('Checkout') {
            checkout scm
        }

        stage('Security') {
            parallel(
                'Secrets': {
                    securityScan.scanSecrets()
                },
                'SAST': {
                    securityScan.runSAST()
                },
                'SCA': {
                    securityScan.runSCA()
                }
            )
        }

        stage('Build & Test') {
            nodeBuild.buildAndTest(
                nodeVersion: '20',
                runTests: true,
                coverage: true
            )
        }

        stage('Docker') {
            def image = dockerBuild.buildImage(
                imageName: 'myapp',
                tag: env.GIT_COMMIT.take(7)
            )

            securityScan.scanImage(image)

            if (env.BRANCH_NAME == 'main') {
                dockerBuild.pushImage(image)
            }
        }

        if (env.BRANCH_NAME == 'main') {
            stage('Deploy Staging') {
                deploy.toKubernetes(
                    environment: 'staging',
                    image: "myapp:${env.GIT_COMMIT.take(7)}"
                )
            }

            stage('Verify Staging') {
                verify.healthCheck('https://staging.example.com')
            }

            stage('Deploy Production') {
                input message: 'Deploy to production?', ok: 'Deploy'
                deploy.toKubernetes(
                    environment: 'production',
                    image: "myapp:${env.GIT_COMMIT.take(7)}"
                )
            }
        }

        currentBuild.result = 'SUCCESS'
    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        throw e
    } finally {
        notifications.send(
            result: currentBuild.result,
            channel: '#deployments'
        )
    }
}
```

---

## Advanced Matrix Builds

### GitHub Actions - Complex Matrix

```yaml
name: Matrix Build

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        node-version: [18, 20, 21]
        database: [postgres, mysql, sqlite]
        include:
          # Add specific configurations
          - os: ubuntu-latest
            node-version: 20
            database: postgres
            experimental: false
          - os: ubuntu-latest
            node-version: 21
            database: postgres
            experimental: true
        exclude:
          # Don't test Windows with MySQL
          - os: windows-latest
            database: mysql
          # Skip macOS for all but latest node
          - os: macos-latest
            node-version: 18
          - os: macos-latest
            node-version: 20

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Setup Database
        run: |
          if [ "${{ matrix.database }}" == "postgres" ]; then
            echo "DATABASE_URL=postgresql://postgres:postgres@localhost:5432/test" >> $GITHUB_ENV
          elif [ "${{ matrix.database }}" == "mysql" ]; then
            echo "DATABASE_URL=mysql://root:root@localhost:3306/test" >> $GITHUB_ENV
          else
            echo "DATABASE_URL=sqlite:///tmp/test.db" >> $GITHUB_ENV
          fi

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test
        continue-on-error: ${{ matrix.experimental == true }}

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          flags: ${{ matrix.os }}-node${{ matrix.node-version }}-${{ matrix.database }}
```

---

### GitLab CI - Matrix with Dynamic Job Generation

```yaml
# .gitlab-ci.yml
.test-template:
  stage: test
  image: node:${NODE_VERSION}
  script:
    - npm ci
    - DATABASE_TYPE=${DB_TYPE} npm test

# Generate matrix jobs
test:node-18:postgres:
  extends: .test-template
  variables:
    NODE_VERSION: "18"
    DB_TYPE: "postgres"
  services:
    - postgres:14

test:node-18:mysql:
  extends: .test-template
  variables:
    NODE_VERSION: "18"
    DB_TYPE: "mysql"
  services:
    - mysql:8

test:node-20:postgres:
  extends: .test-template
  variables:
    NODE_VERSION: "20"
    DB_TYPE: "postgres"
  services:
    - postgres:14

test:node-20:mysql:
  extends: .test-template
  variables:
    NODE_VERSION: "20"
    DB_TYPE: "mysql"
  services:
    - mysql:8
```

---

## Monorepo Strategies

### Nx Monorepo with Affected Detection

```yaml
# .github/workflows/nx-monorepo.yml
name: Nx Monorepo CI

on:
  pull_request:
  push:
    branches: [main]

jobs:
  affected:
    runs-on: ubuntu-latest
    outputs:
      affected-libs: ${{ steps.affected.outputs.libs }}
      affected-apps: ${{ steps.affected.outputs.apps }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci

      - name: Get affected projects
        id: affected
        run: |
          echo "libs=$(npx nx print-affected --type=lib --select=projects)" >> $GITHUB_OUTPUT
          echo "apps=$(npx nx print-affected --type=app --select=projects)" >> $GITHUB_OUTPUT

  lint-affected:
    needs: affected
    if: ${{ needs.affected.outputs.affected-libs != '' || needs.affected.outputs.affected-apps != '' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci

      - name: Lint affected projects
        run: npx nx affected --target=lint --parallel=3

  test-affected:
    needs: affected
    if: ${{ needs.affected.outputs.affected-libs != '' || needs.affected.outputs.affected-apps != '' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci

      - name: Test affected projects
        run: npx nx affected --target=test --parallel=3 --coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build-affected:
    needs: [lint-affected, test-affected]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci

      - name: Build affected projects
        run: npx nx affected --target=build --parallel=3

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

---

## Docker Build Optimization

### Multi-Stage Build with BuildKit Cache

```yaml
name: Optimized Docker Build

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.sha }}
            ghcr.io/${{ github.repository }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            BUILDKIT_INLINE_CACHE=1
```

**Optimized Dockerfile**:

```dockerfile
# syntax=docker/dockerfile:1.4

# Stage 1: Dependencies
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --only=production

# Stage 2: Build
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci
COPY . .
RUN npm run build

# Stage 3: Production
FROM node:20-alpine AS production
WORKDIR /app

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy dependencies and build
COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=nodejs:nodejs /app/dist ./dist
COPY --chown=nodejs:nodejs package*.json ./

USER nodejs

EXPOSE 3000

CMD ["node", "dist/main.js"]
```

---

## GitOps with ArgoCD

### ArgoCD Deployment Pipeline

```yaml
# .github/workflows/gitops-deploy.yml
name: GitOps Deployment

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Checkout GitOps repo
        uses: actions/checkout@v4
        with:
          repository: myorg/gitops-manifests
          token: ${{ secrets.GITOPS_TOKEN }}
          path: gitops

      - name: Update image tag
        run: |
          cd gitops
          sed -i "s|image: ghcr.io/${{ github.repository }}:.*|image: ghcr.io/${{ github.repository }}:${{ github.sha }}|" \
            apps/myapp/overlays/staging/kustomization.yaml

      - name: Commit and push
        run: |
          cd gitops
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add .
          git commit -m "Update myapp to ${{ github.sha }}"
          git push

      - name: Sync ArgoCD application
        run: |
          argocd app sync myapp-staging \
            --auth-token ${{ secrets.ARGOCD_TOKEN }} \
            --server argocd.example.com \
            --prune

      - name: Wait for ArgoCD sync
        run: |
          argocd app wait myapp-staging \
            --auth-token ${{ secrets.ARGOCD_TOKEN }} \
            --server argocd.example.com \
            --health \
            --timeout 600
```

**ArgoCD Application Manifest**:

```yaml
# argocd-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp-staging
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/myorg/gitops-manifests
    targetRevision: main
    path: apps/myapp/overlays/staging
  destination:
    server: https://kubernetes.default.svc
    namespace: staging
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

---

## Performance Tips

### 1. Aggressive Caching Strategy

```yaml
# Cache everything possible
- name: Cache dependencies
  uses: actions/cache@v3
  with:
    path: |
      ~/.npm
      ~/.cache/pip
      ~/.m2/repository
      ~/.gradle/caches
      node_modules
      vendor
    key: ${{ runner.os }}-deps-${{ hashFiles('**/package-lock.json', '**/requirements.txt', '**/pom.xml') }}
    restore-keys: |
      ${{ runner.os }}-deps-
```

### 2. Parallel Job Execution

```yaml
# Run independent jobs in parallel
jobs:
  lint:
    runs-on: ubuntu-latest
    steps: [...]

  test-unit:
    runs-on: ubuntu-latest
    steps: [...]

  test-integration:
    runs-on: ubuntu-latest
    steps: [...]

  security-scan:
    runs-on: ubuntu-latest
    steps: [...]

  # All above jobs run in parallel
  deploy:
    needs: [lint, test-unit, test-integration, security-scan]
    runs-on: ubuntu-latest
    steps: [...]
```

### 3. Conditional Execution

```yaml
# Skip unnecessary builds
on:
  pull_request:
    paths:
      - 'src/**'
      - 'package*.json'
      - '.github/workflows/**'

jobs:
  build:
    if: github.event_name != 'pull_request' || !contains(github.event.pull_request.title, '[skip ci]')
    steps: [...]
```

---

## Additional Resources

- **GitHub Actions Documentation**: https://docs.github.com/en/actions
- **GitLab CI Documentation**: https://docs.gitlab.com/ee/ci/
- **Jenkins Documentation**: https://www.jenkins.io/doc/
- **ArgoCD Documentation**: https://argo-cd.readthedocs.io/
- **Docker BuildKit**: https://docs.docker.com/build/buildkit/
