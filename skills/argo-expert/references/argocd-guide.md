# Argo CD Complete Reference Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [App-of-Apps Pattern](#2-app-of-apps-pattern)
3. [Multi-Cluster Management](#3-multi-cluster-management)
4. [ApplicationSet Patterns](#4-applicationset-patterns)
5. [Advanced Sync Strategies](#5-advanced-sync-strategies)
6. [Security & RBAC](#6-security--rbac)
7. [High Availability](#7-high-availability)
8. [Monitoring & Observability](#8-monitoring--observability)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Installation & Setup

### 1.1 Production Installation

```bash
# Create namespace
kubectl create namespace argocd

# Install Argo CD (production, HA mode)
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.10.0/manifests/ha/install.yaml

# Wait for pods
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s

# Get initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

### 1.2 Configuration Management

**argocd-cm ConfigMap** (Core Settings):
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # Repository credentials
  repositories: |
    - url: https://github.com/org/apps
      type: git
      name: apps-repo
    - url: https://helm.example.com
      type: helm
      name: helm-charts

  # Credential templates (for multiple repos with same credentials)
  repository.credentials: |
    - url: https://github.com/org
      passwordSecret:
        name: github-creds
        key: password
      usernameSecret:
        name: github-creds
        key: username

  # Resource customizations
  resource.customizations: |
    cert-manager.io/Certificate:
      health.lua: |
        hs = {}
        if obj.status ~= nil then
          if obj.status.conditions ~= nil then
            for i, condition in ipairs(obj.status.conditions) do
              if condition.type == "Ready" and condition.status == "False" then
                hs.status = "Degraded"
                hs.message = condition.message
                return hs
              end
              if condition.type == "Ready" and condition.status == "True" then
                hs.status = "Healthy"
                hs.message = condition.message
                return hs
              end
            end
          end
        end
        hs.status = "Progressing"
        hs.message = "Waiting for certificate"
        return hs

  # Admin notification settings
  admin.enabled: "true"

  # Disable admin user (use SSO only)
  # admin.enabled: "false"

  # Server settings
  url: https://argocd.example.com
  dex.config: |
    connectors:
      - type: github
        id: github
        name: GitHub
        config:
          clientID: $github-client-id
          clientSecret: $github-client-secret
          orgs:
            - name: your-org

  # Application instance label key
  application.instanceLabelKey: argocd.argoproj.io/instance

  # Timeout settings
  timeout.reconciliation: 180s
  timeout.hard.reconciliation: 0s
```

**argocd-cmd-params-cm ConfigMap** (Server Parameters):
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cmd-params-cm
  namespace: argocd
data:
  # Controller
  repo.server: argocd-repo-server:8081
  status.processors: "20"
  operation.processors: "10"
  app.resync: "180"  # 3 minutes

  # Server
  server.insecure: "false"
  server.rootpath: "/"
  server.staticassets: "/shared/app"
  server.disable.auth: "false"

  # Repo server
  reposerver.parallelism.limit: "0"  # 0 = unlimited
```

### 1.3 TLS Configuration

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: argocd-server-tls
  namespace: argocd
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

**Ingress with TLS**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server
  namespace: argocd
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - argocd.example.com
      secretName: argocd-server-tls
  rules:
    - host: argocd.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: argocd-server
                port:
                  name: https
```

---

## 2. App-of-Apps Pattern

### 2.1 Basic App-of-Apps

**Root Application**:
```yaml
# bootstrap/root-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: root
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/org/gitops-bootstrap
    targetRevision: main
    path: applications
    directory:
      recurse: true
      jsonnet: {}
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

**Child Application Template**:
```yaml
# applications/infrastructure/cert-manager.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: cert-manager
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
  annotations:
    argocd.argoproj.io/sync-wave: "1"  # Deploy early
spec:
  project: infrastructure
  source:
    repoURL: https://charts.jetstack.io
    targetRevision: v1.13.0
    chart: cert-manager
    helm:
      values: |
        installCRDs: true
        replicaCount: 3
        resources:
          requests:
            cpu: 10m
            memory: 32Mi
          limits:
            cpu: 100m
            memory: 128Mi
        prometheus:
          enabled: true
          servicemonitor:
            enabled: true
  destination:
    server: https://kubernetes.default.svc
    namespace: cert-manager
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - ServerSideApply=true
  ignoreDifferences:
    - group: admissionregistration.k8s.io
      kind: ValidatingWebhookConfiguration
      jsonPointers:
        - /webhooks/0/clientConfig/caBundle
```

### 2.2 Layered App-of-Apps (Bootstrap → Infrastructure → Platform → Apps)

**Directory Structure**:
```
gitops-bootstrap/
├── bootstrap/
│   └── root-app.yaml           # Initial bootstrap
├── applications/
│   ├── infrastructure/          # Layer 1: Core infrastructure
│   │   ├── cert-manager.yaml
│   │   ├── ingress-nginx.yaml
│   │   ├── external-secrets.yaml
│   │   └── prometheus.yaml
│   ├── platform/                # Layer 2: Platform services
│   │   ├── argocd.yaml          # Manage Argo CD itself
│   │   ├── vault.yaml
│   │   └── keycloak.yaml
│   └── workloads/               # Layer 3: Application workloads
│       ├── backend-apps.yaml
│       └── frontend-apps.yaml
```

**Infrastructure Layer with Dependencies**:
```yaml
# applications/infrastructure/ingress-nginx.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ingress-nginx
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "2"  # After cert-manager
spec:
  project: infrastructure
  source:
    repoURL: https://kubernetes.github.io/ingress-nginx
    targetRevision: 4.8.3
    chart: ingress-nginx
    helm:
      values: |
        controller:
          replicaCount: 3
          service:
            type: LoadBalancer
            annotations:
              service.beta.kubernetes.io/aws-load-balancer-type: nlb
          metrics:
            enabled: true
            serviceMonitor:
              enabled: true
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
  destination:
    server: https://kubernetes.default.svc
    namespace: ingress-nginx
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

### 2.3 Self-Managing Argo CD (App-of-Apps manages itself)

```yaml
# applications/platform/argocd.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: argocd
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "0"
spec:
  project: platform
  source:
    repoURL: https://github.com/org/argocd-config
    targetRevision: main
    path: manifests/argocd
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - RespectIgnoreDifferences=true
  ignoreDifferences:
    - group: ""
      kind: Secret
      name: argocd-initial-admin-secret
      jsonPointers:
        - /data
```

---

## 3. Multi-Cluster Management

### 3.1 Cluster Registration

**Via CLI**:
```bash
# Get kubeconfig for remote cluster
export KUBECONFIG=/path/to/remote-cluster-kubeconfig

# Add cluster to Argo CD
argocd cluster add production-cluster-1 \
  --name prod-1 \
  --project production \
  --label env=production \
  --label region=us-east-1

# List clusters
argocd cluster list
```

**Via Secret (Declarative)**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cluster-prod-1
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: cluster
    env: production
    region: us-east-1
type: Opaque
stringData:
  name: prod-cluster-1
  server: https://prod-cluster-1.k8s.example.com
  config: |
    {
      "bearerToken": "<service-account-token>",
      "tlsClientConfig": {
        "insecure": false,
        "caData": "<base64-ca-cert>",
        "certData": "<base64-client-cert>",
        "keyData": "<base64-client-key>"
      }
    }
```

**Create Service Account in Remote Cluster**:
```yaml
# On remote cluster
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-manager
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: argocd-manager-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argocd-manager-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: argocd-manager-role
subjects:
  - kind: ServiceAccount
    name: argocd-manager
    namespace: kube-system
---
# Get token
apiVersion: v1
kind: Secret
metadata:
  name: argocd-manager-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: argocd-manager
type: kubernetes.io/service-account-token
```

### 3.2 Hub-Spoke Topology

**Hub Cluster**: Single Argo CD instance managing multiple spoke clusters

```yaml
# ApplicationSet targeting multiple clusters
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: monitoring-stack
  namespace: argocd
spec:
  generators:
    - clusters:
        selector:
          matchLabels:
            env: production
  template:
    metadata:
      name: 'monitoring-{{name}}'
    spec:
      project: monitoring
      source:
        repoURL: https://github.com/org/monitoring
        targetRevision: main
        path: 'overlays/{{metadata.labels.region}}'
      destination:
        server: '{{server}}'
        namespace: monitoring
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```

### 3.3 Cluster Generator Patterns

**Git File Generator** (clusters defined in Git):
```yaml
# clusters/prod-us-east-1/config.json
{
  "cluster": {
    "name": "prod-us-east-1",
    "server": "https://prod-us-east-1.k8s.example.com",
    "environment": "production",
    "region": "us-east-1",
    "targetRevision": "v2.0.0",
    "replicas": 5
  }
}
```

```yaml
# ApplicationSet using Git files
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: app-deployment
  namespace: argocd
spec:
  generators:
    - git:
        repoURL: https://github.com/org/cluster-configs
        revision: HEAD
        files:
          - path: "clusters/**/config.json"
  template:
    metadata:
      name: 'app-{{cluster.name}}'
      labels:
        env: '{{cluster.environment}}'
        region: '{{cluster.region}}'
    spec:
      project: '{{cluster.environment}}'
      source:
        repoURL: https://github.com/org/app
        targetRevision: '{{cluster.targetRevision}}'
        path: k8s/overlays/{{cluster.environment}}
        kustomize:
          replicas:
            - name: api
              count: '{{cluster.replicas}}'
      destination:
        server: '{{cluster.server}}'
        namespace: app
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
```

---

## 4. ApplicationSet Patterns

### 4.1 Matrix Generator (Combine Multiple Generators)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: matrix-example
  namespace: argocd
spec:
  generators:
    - matrix:
        generators:
          # Generator 1: Clusters
          - clusters:
              selector:
                matchLabels:
                  env: production

          # Generator 2: Git directories
          - git:
              repoURL: https://github.com/org/microservices
              revision: HEAD
              directories:
                - path: services/*
  template:
    metadata:
      name: '{{path.basename}}-{{name}}'
    spec:
      project: production
      source:
        repoURL: https://github.com/org/microservices
        targetRevision: HEAD
        path: '{{path}}/k8s'
      destination:
        server: '{{server}}'
        namespace: '{{path.basename}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
```

### 4.2 Pull Request Generator (Preview Environments)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: pr-preview
  namespace: argocd
spec:
  generators:
    - pullRequest:
        github:
          owner: org
          repo: frontend-app
          tokenRef:
            secretName: github-token
            key: token
          labels:
            - preview
        requeueAfterSeconds: 60
  template:
    metadata:
      name: 'pr-{{number}}-preview'
      annotations:
        notifications.argoproj.io/subscribe.on-sync-succeeded.github: ""
    spec:
      project: previews
      source:
        repoURL: https://github.com/org/frontend-app
        targetRevision: '{{head_sha}}'
        path: k8s/overlays/preview
        kustomize:
          nameSuffix: '-pr-{{number}}'
          commonLabels:
            pr: '{{number}}'
      destination:
        server: https://kubernetes.default.svc
        namespace: 'preview-pr-{{number}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
      # Auto-delete after 7 days
      info:
        - name: 'PR #{{number}}'
          value: '{{title}}'
```

### 4.3 List Generator with Template Override

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: tenant-apps
  namespace: argocd
spec:
  generators:
    - list:
        elements:
          - name: team-alpha
            namespace: team-alpha
            replicas: 3
            cpuLimit: "500m"
            memLimit: "512Mi"
          - name: team-beta
            namespace: team-beta
            replicas: 5
            cpuLimit: "1000m"
            memLimit: "1Gi"
          - name: team-gamma
            namespace: team-gamma
            replicas: 2
            cpuLimit: "250m"
            memLimit: "256Mi"
  template:
    metadata:
      name: '{{name}}-app'
    spec:
      project: tenants
      source:
        repoURL: https://github.com/org/tenant-app
        targetRevision: main
        path: k8s
        helm:
          parameters:
            - name: replicas
              value: '{{replicas}}'
            - name: resources.limits.cpu
              value: '{{cpuLimit}}'
            - name: resources.limits.memory
              value: '{{memLimit}}'
      destination:
        server: https://kubernetes.default.svc
        namespace: '{{namespace}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```

---

## 5. Advanced Sync Strategies

### 5.1 Sync Waves (Ordered Deployment)

```yaml
# Wave -5: Namespaces
apiVersion: v1
kind: Namespace
metadata:
  name: app
  annotations:
    argocd.argoproj.io/sync-wave: "-5"
---
# Wave -3: CRDs
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: mycrds.example.com
  annotations:
    argocd.argoproj.io/sync-wave: "-3"
---
# Wave -1: Secrets
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: app
  annotations:
    argocd.argoproj.io/sync-wave: "-1"
---
# Wave 0: ConfigMaps
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: app
  annotations:
    argocd.argoproj.io/sync-wave: "0"
---
# Wave 2: Database
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: app
  annotations:
    argocd.argoproj.io/sync-wave: "2"
---
# Wave 5: Application
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: app
  annotations:
    argocd.argoproj.io/sync-wave: "5"
---
# Wave 10: Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: app
  annotations:
    argocd.argoproj.io/sync-wave: "10"
```

### 5.2 Sync Hooks

**PreSync Hook** (runs before sync):
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: db-backup
  namespace: app
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      containers:
        - name: backup
          image: postgres:15
          command: ["pg_dump", "-h", "postgres", "-U", "admin", ">", "/backup/dump.sql"]
      restartPolicy: Never
```

**PostSync Hook** (runs after successful sync):
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: smoke-test
  namespace: app
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
spec:
  template:
    spec:
      containers:
        - name: test
          image: curlimages/curl:latest
          command:
            - sh
            - -c
            - |
              curl -f http://api-server:8080/health || exit 1
      restartPolicy: Never
```

**SyncFail Hook** (runs on sync failure):
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: send-alert
  namespace: app
  annotations:
    argocd.argoproj.io/hook: SyncFail
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
data:
  alert.sh: |
    #!/bin/sh
    curl -X POST https://alerts.example.com/webhook \
      -d '{"message": "Argo CD sync failed for app"}'
```

### 5.3 Sync Options

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: advanced-sync
  namespace: argocd
spec:
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
      # Create namespace if missing
      - CreateNamespace=true

      # Validate resources before applying
      - Validate=true

      # Delete resources in reverse order
      - PruneLast=true

      # Prune resources during final sync wave
      - PrunePropagationPolicy=foreground

      # Use server-side apply (K8s 1.22+)
      - ServerSideApply=true

      # Skip pruning for specific resource types
      - PruneResourcesOnDeletion=false

      # Respect ignore differences
      - RespectIgnoreDifferences=true

      # Apply out-of-sync resources only
      - ApplyOutOfSyncOnly=true
```

### 5.4 Selective Sync

**Sync specific resources**:
```bash
# Sync only deployments
argocd app sync myapp --resource apps:Deployment:myapp

# Sync with prune
argocd app sync myapp --prune

# Sync with force (replace resources)
argocd app sync myapp --force

# Dry run
argocd app sync myapp --dry-run
```

---

## 6. Security & RBAC

### 6.1 AppProject with RBAC

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: production
  namespace: argocd
spec:
  description: Production applications

  # Source repositories
  sourceRepos:
    - https://github.com/org/prod-*
    - https://helm.example.com

  # Allowed destinations
  destinations:
    - namespace: prod-*
      server: https://prod-cluster-1.k8s.example.com
    - namespace: prod-*
      server: https://prod-cluster-2.k8s.example.com

  # Cluster resource whitelist (cluster-scoped)
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
    - group: rbac.authorization.k8s.io
      kind: ClusterRoleBinding

  # Namespace resource whitelist
  namespaceResourceWhitelist:
    - group: apps
      kind: Deployment
    - group: apps
      kind: StatefulSet
    - group: ""
      kind: Service
    - group: ""
      kind: ConfigMap
    - group: ""
      kind: Secret
    - group: networking.k8s.io
      kind: Ingress
    - group: autoscaling
      kind: HorizontalPodAutoscaler

  # Deny specific resource types
  namespaceResourceBlacklist:
    - group: ""
      kind: ResourceQuota
    - group: ""
      kind: LimitRange

  # Orphaned resources monitoring
  orphanedResources:
    warn: true

  # Roles
  roles:
    - name: developer
      description: Developer role
      policies:
        - p, proj:production:developer, applications, get, production/*, allow
        - p, proj:production:developer, applications, sync, production/*, allow
        - p, proj:production:developer, applications, override, production/*, deny
        - p, proj:production:developer, applications, delete, production/*, deny
      groups:
        - prod-developers
        - developers

    - name: operator
      description: Operator role (sync + rollback)
      policies:
        - p, proj:production:operator, applications, get, production/*, allow
        - p, proj:production:operator, applications, sync, production/*, allow
        - p, proj:production:operator, applications, action/*, production/*, allow
      groups:
        - prod-operators
        - sre-team

    - name: admin
      description: Full admin access
      policies:
        - p, proj:production:admin, applications, *, production/*, allow
        - p, proj:production:admin, repositories, *, *, allow
        - p, proj:production:admin, clusters, *, *, allow
      groups:
        - prod-admins

  # Sync windows (maintenance windows)
  syncWindows:
    # Deny syncs during business hours
    - kind: deny
      schedule: "0 9-17 * * 1-5"  # Mon-Fri, 9am-5pm
      duration: 8h
      applications:
        - '*-production'
      namespaces:
        - prod-*
      clusters:
        - prod-cluster-1
      manualSync: true  # Allow manual syncs

    # Allow syncs during maintenance window
    - kind: allow
      schedule: "0 2 * * 0"  # Sundays at 2am
      duration: 4h
      applications:
        - '*'
```

### 6.2 SSO Integration (Dex + OIDC)

**GitHub SSO**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  url: https://argocd.example.com
  dex.config: |
    connectors:
      - type: github
        id: github
        name: GitHub
        config:
          clientID: $dex.github.clientID
          clientSecret: $dex.github.clientSecret
          orgs:
            - name: my-org
              teams:
                - sre-team
                - developers
```

**RBAC Policy with SSO**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.default: role:readonly
  policy.csv: |
    # Admins (from GitHub team)
    g, my-org:sre-team, role:admin

    # Developers (limited access)
    g, my-org:developers, role:developer
    p, role:developer, applications, get, */*, allow
    p, role:developer, applications, sync, */*, allow
    p, role:developer, applications, delete, */*, deny
    p, role:developer, clusters, get, *, allow
    p, role:developer, repositories, get, *, allow

    # Read-only for everyone else
    g, my-org:*, role:readonly
    p, role:readonly, applications, get, */*, allow
    p, role:readonly, logs, get, */*, allow

  scopes: '[groups, email]'
```

### 6.3 Secret Management

**External Secrets Operator**:
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: app
spec:
  provider:
    vault:
      server: https://vault.example.com
      path: secret
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: argocd
          serviceAccountRef:
            name: argocd-app-controller
```

**Application with External Secret**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: app-with-secrets
  namespace: argocd
spec:
  source:
    repoURL: https://github.com/org/app
    targetRevision: main
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: app
  syncPolicy:
    syncOptions:
      - CreateNamespace=true
    # Sync external secrets first
    automated:
      prune: true
      selfHeal: true
```

---

## 7. High Availability

### 7.1 HA Installation

```yaml
# argocd-server (3 replicas)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-server
  namespace: argocd
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-server
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app.kubernetes.io/name: argocd-server
              topologyKey: kubernetes.io/hostname
      containers:
        - name: argocd-server
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
# argocd-repo-server (3 replicas)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-repo-server
  namespace: argocd
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-repo-server
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app.kubernetes.io/name: argocd-repo-server
              topologyKey: kubernetes.io/hostname
      containers:
        - name: argocd-repo-server
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
---
# argocd-application-controller (sharding)
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: argocd-application-controller
  namespace: argocd
spec:
  replicas: 3  # 3 shards
  serviceName: argocd-application-controller
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-application-controller
  template:
    spec:
      containers:
        - name: argocd-application-controller
          env:
            - name: ARGOCD_CONTROLLER_REPLICAS
              value: "3"
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
            limits:
              cpu: 2000m
              memory: 4Gi
```

### 7.2 Redis HA

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: argocd-redis-ha-server
  namespace: argocd
spec:
  replicas: 3
  serviceName: argocd-redis-ha
  selector:
    matchLabels:
      app: redis-ha
  template:
    spec:
      containers:
        - name: redis
          image: redis:7.2-alpine
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
# Redis Sentinel
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-redis-ha-sentinel
  namespace: argocd
spec:
  replicas: 3
  selector:
    matchLabels:
      app: redis-ha-sentinel
  template:
    spec:
      containers:
        - name: sentinel
          image: redis:7.2-alpine
          command:
            - redis-sentinel
            - /etc/redis/sentinel.conf
```

### 7.3 Backup & Restore

**Backup with Velero**:
```bash
# Backup Argo CD namespace
velero backup create argocd-backup \
  --include-namespaces argocd \
  --include-cluster-resources=true \
  --ttl 168h

# Backup specific applications
velero backup create apps-backup \
  --selector argocd.argoproj.io/instance \
  --include-cluster-resources=false
```

**Export Configuration**:
```bash
# Export all applications
kubectl get applications -n argocd -o yaml > applications-backup.yaml

# Export all AppProjects
kubectl get appprojects -n argocd -o yaml > appprojects-backup.yaml

# Export ConfigMaps
kubectl get cm -n argocd -o yaml > configmaps-backup.yaml

# Export Secrets (encrypted)
kubectl get secrets -n argocd -o yaml | kubeseal > secrets-backup-sealed.yaml
```

---

## 8. Monitoring & Observability

### 8.1 Prometheus Metrics

**ServiceMonitor**:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argocd-metrics
  namespace: argocd
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-server
  endpoints:
    - port: metrics
      interval: 30s
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argocd-repo-server-metrics
  namespace: argocd
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-repo-server
  endpoints:
    - port: metrics
      interval: 30s
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argocd-applicationset-controller-metrics
  namespace: argocd
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-applicationset-controller
  endpoints:
    - port: metrics
      interval: 30s
```

**Key Metrics**:
```promql
# Application health
argocd_app_info{health_status="Healthy"}

# Sync status
argocd_app_sync_total

# Sync duration
histogram_quantile(0.95, rate(argocd_app_sync_bucket[5m]))

# Application count by health
count(argocd_app_info) by (health_status)

# Application count by sync status
count(argocd_app_info) by (sync_status)

# Repository requests
rate(argocd_git_request_total[5m])

# Reconciliation performance
rate(argocd_app_reconcile_count[5m])
```

**Alerting Rules**:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: argocd-alerts
  namespace: argocd
spec:
  groups:
    - name: argocd
      interval: 30s
      rules:
        - alert: ArgoCDAppUnhealthy
          expr: |
            argocd_app_info{health_status!="Healthy"} == 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "ArgoCD Application {{ $labels.name }} is unhealthy"
            description: "Application {{ $labels.name }} in namespace {{ $labels.namespace }} has been unhealthy for more than 5 minutes"

        - alert: ArgoCDAppOutOfSync
          expr: |
            argocd_app_info{sync_status!="Synced"} == 1
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "ArgoCD Application {{ $labels.name }} is out of sync"

        - alert: ArgoCDSyncFailed
          expr: |
            increase(argocd_app_sync_total{phase="Error"}[5m]) > 0
          labels:
            severity: critical
          annotations:
            summary: "ArgoCD sync failed for {{ $labels.name }}"
```

### 8.2 Notifications

**Notifications ConfigMap**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-notifications-cm
  namespace: argocd
data:
  service.slack: |
    token: $slack-token

  service.webhook.github: |
    url: https://api.github.com
    headers:
      - name: Authorization
        value: token $github-token

  template.app-deployed: |
    message: |
      Application {{.app.metadata.name}} has been deployed.
      Sync Status: {{.app.status.sync.status}}
      Health Status: {{.app.status.health.status}}
      Revision: {{.app.status.sync.revision}}
    slack:
      attachments: |
        [{
          "title": "{{ .app.metadata.name}}",
          "color": "good",
          "fields": [{
            "title": "Sync Status",
            "value": "{{.app.status.sync.status}}",
            "short": true
          }, {
            "title": "Health Status",
            "value": "{{.app.status.health.status}}",
            "short": true
          }]
        }]

  template.app-health-degraded: |
    message: |
      Application {{.app.metadata.name}} health is degraded.
      Health Status: {{.app.status.health.status}}
    slack:
      attachments: |
        [{
          "title": "{{ .app.metadata.name}}",
          "color": "danger",
          "fields": [{
            "title": "Health Status",
            "value": "{{.app.status.health.status}}",
            "short": true
          }]
        }]

  trigger.on-deployed: |
    - when: app.status.operationState.phase in ['Succeeded']
      send: [app-deployed]

  trigger.on-health-degraded: |
    - when: app.status.health.status == 'Degraded'
      send: [app-health-degraded]

  subscriptions: |
    - recipients:
        - slack:deployments
      triggers:
        - on-deployed
        - on-health-degraded
```

**Application Notifications**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
  annotations:
    notifications.argoproj.io/subscribe.on-deployed.slack: deployments
    notifications.argoproj.io/subscribe.on-health-degraded.slack: alerts
spec:
  # ... application spec
```

---

## 9. Troubleshooting

### 9.1 Common Issues

**Application Stuck in Progressing**:
```bash
# Check application status
argocd app get myapp

# Check sync status
kubectl get application myapp -n argocd -o jsonpath='{.status.sync.status}'

# Check health status
kubectl get application myapp -n argocd -o jsonpath='{.status.health.status}'

# Manual sync with force
argocd app sync myapp --force --prune
```

**OutOfSync but no differences shown**:
```bash
# Refresh application
argocd app get myapp --refresh

# Hard refresh (bypass cache)
argocd app get myapp --hard-refresh

# Check ignored differences
kubectl get application myapp -n argocd -o jsonpath='{.spec.ignoreDifferences}'
```

**Sync hook failures**:
```bash
# Check hook status
kubectl get pods -n myapp -l argocd.argoproj.io/hook

# View hook logs
kubectl logs -n myapp job/migration-hook

# Delete failed hook (if delete policy allows)
kubectl delete job -n myapp migration-hook
```

### 9.2 Debugging Commands

```bash
# Application details
argocd app get myapp -o yaml

# Application resources
argocd app resources myapp

# Application manifests
argocd app manifests myapp

# Compare live vs desired state
argocd app diff myapp

# Application logs
argocd app logs myapp --follow

# Application events
kubectl describe application myapp -n argocd
```

### 9.3 Performance Tuning

```yaml
# argocd-cmd-params-cm
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cmd-params-cm
  namespace: argocd
data:
  # Increase parallel processing
  status.processors: "40"
  operation.processors: "20"

  # Adjust reconciliation interval
  app.resync: "180"  # 3 minutes (default)

  # Repo server parallelism
  reposerver.parallelism.limit: "10"

  # Enable controller sharding
  controller.sharding.algorithm: "round-robin"
```

This comprehensive guide covers the essential Argo CD patterns for production use. For workflow orchestration, see `workflows-guide.md`, and for progressive delivery, see `rollouts-guide.md`.
