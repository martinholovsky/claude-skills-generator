# Argo Rollouts Complete Reference Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Canary Deployments](#2-canary-deployments)
3. [Blue-Green Deployments](#3-blue-green-deployments)
4. [Analysis Templates](#4-analysis-templates)
5. [Traffic Management](#5-traffic-management)
6. [Advanced Strategies](#6-advanced-strategies)
7. [Metrics Providers](#7-metrics-providers)
8. [Integration Patterns](#8-integration-patterns)
9. [Monitoring & Observability](#9-monitoring--observability)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Installation & Setup

### 1.1 Installation

```bash
# Install Argo Rollouts
kubectl create namespace argo-rollouts
kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/download/v1.6.0/install.yaml

# Install kubectl plugin
curl -LO https://github.com/argoproj/argo-rollouts/releases/download/v1.6.0/kubectl-argo-rollouts-linux-amd64
chmod +x kubectl-argo-rollouts-linux-amd64
sudo mv kubectl-argo-rollouts-linux-amd64 /usr/local/bin/kubectl-argo-rollouts

# Verify installation
kubectl argo rollouts version
```

### 1.2 Controller Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argo-rollouts-config
  namespace: argo-rollouts
data:
  # Default analysis templates
  defaultAnalysisTemplates: |
    - templateName: success-rate
    - templateName: error-rate

  # Notification configuration
  notificationEngine:
    serviceAccountName: argo-rollouts
    triggers:
      - name: on-rollout-completed
        template: rollout-complete
        condition: rollout.status.phase == "Healthy"

  # Traffic router plugin config
  trafficRouterPlugins: |
    - name: istio
      location: https://github.com/argoproj-labs/rollouts-plugin-trafficrouter-istio
```

### 1.3 RBAC Setup

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argo-rollouts
  namespace: argo-rollouts
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: argo-rollouts-role
rules:
  - apiGroups: [argoproj.io]
    resources: [rollouts, rollouts/status, rollouts/finalizers]
    verbs: [get, list, watch, update, patch]
  - apiGroups: [argoproj.io]
    resources: [analysisruns, analysisruns/status, analysisruns/finalizers]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [argoproj.io]
    resources: [experiments, experiments/status]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [apps]
    resources: [replicasets]
    verbs: [get, list, watch, create, update, patch, delete]
  - apiGroups: [""]
    resources: [services]
    verbs: [get, list, watch, patch, update]
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argo-rollouts-binding
subjects:
  - kind: ServiceAccount
    name: argo-rollouts
    namespace: argo-rollouts
roleRef:
  kind: ClusterRole
  name: argo-rollouts-role
  apiGroup: rbac.authorization.k8s.io
```

---

## 2. Canary Deployments

### 2.1 Basic Canary with Manual Promotion

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: api-server
  namespace: production
spec:
  replicas: 10
  revisionHistoryLimit: 5
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
        version: v2
    spec:
      containers:
        - name: api
          image: myapp/api:v2.0.0
          ports:
            - name: http
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
  strategy:
    canary:
      maxSurge: "25%"
      maxUnavailable: 0
      steps:
        - setWeight: 10
        - pause: {}  # Manual promotion

        - setWeight: 25
        - pause: {duration: 5m}

        - setWeight: 50
        - pause: {duration: 10m}

        - setWeight: 75
        - pause: {duration: 5m}
```

**Promote canary**:
```bash
# Promote to next step
kubectl argo rollouts promote api-server -n production

# Promote all the way
kubectl argo rollouts promote api-server -n production --full

# Watch rollout
kubectl argo rollouts get rollout api-server -n production --watch
```

### 2.2 Canary with Automated Analysis

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: payment-api
  namespace: payments
spec:
  replicas: 10
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      containers:
        - name: api
          image: payment-api:v2.1.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
  strategy:
    canary:
      maxSurge: "25%"
      maxUnavailable: 0
      steps:
        - setWeight: 10
        - pause: {duration: 2m}

        - analysis:
            templates:
              - templateName: success-rate
              - templateName: latency-p95
            args:
              - name: service-name
                value: payment-api
              - name: canary-hash
                valueFrom:
                  podTemplateHashValue: Latest

        - setWeight: 25
        - pause: {duration: 5m}

        - analysis:
            templates:
              - templateName: success-rate
              - templateName: error-rate
            args:
              - name: service-name
                value: payment-api

        - setWeight: 50
        - pause: {duration: 10m}

        - setWeight: 75
        - pause: {duration: 5m}

      analysis:
        templates:
          - templateName: success-rate
          - templateName: error-rate
        startingStep: 2  # Start analysis after 25% traffic
        args:
          - name: service-name
            value: payment-api
```

### 2.3 Canary with Anti-Affinity

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: critical-api
  namespace: production
spec:
  replicas: 12
  selector:
    matchLabels:
      app: critical-api
  template:
    metadata:
      labels:
        app: critical-api
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: critical-api
              topologyKey: kubernetes.io/hostname
      containers:
        - name: api
          image: critical-api:v3.0.0
  strategy:
    canary:
      canaryService: critical-api-canary
      stableService: critical-api-stable
      trafficRouting:
        istio:
          virtualService:
            name: critical-api
            routes:
              - primary
      steps:
        - setWeight: 5
        - pause: {duration: 2m}
        - setWeight: 10
        - pause: {duration: 5m}
        - setWeight: 20
        - pause: {duration: 10m}
        - setWeight: 40
        - pause: {duration: 10m}
        - setWeight: 60
        - pause: {duration: 10m}
        - setWeight: 80
        - pause: {duration: 5m}
```

---

## 3. Blue-Green Deployments

### 3.1 Basic Blue-Green

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 5
  revisionHistoryLimit: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
        - name: web
          image: myapp/web:v2.0.0
          ports:
            - containerPort: 80
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
  strategy:
    blueGreen:
      activeService: web-app-active
      previewService: web-app-preview
      autoPromotionEnabled: false  # Manual promotion
      scaleDownDelaySeconds: 300   # Wait 5 min before scaling down old version
      scaleDownDelayRevisionLimit: 2
```

**Services**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: web-app-active
  namespace: production
spec:
  selector:
    app: web-app
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web-app-preview
  namespace: production
spec:
  selector:
    app: web-app
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
```

### 3.2 Blue-Green with Automated Promotion

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: api-v2
  namespace: production
spec:
  replicas: 10
  selector:
    matchLabels:
      app: api-v2
  template:
    metadata:
      labels:
        app: api-v2
    spec:
      containers:
        - name: api
          image: myapp/api:v2.0.0
  strategy:
    blueGreen:
      activeService: api-active
      previewService: api-preview
      autoPromotionEnabled: false
      prePromotionAnalysis:
        templates:
          - templateName: smoke-tests
          - templateName: load-tests
        args:
          - name: service-name
            value: api-preview
      postPromotionAnalysis:
        templates:
          - templateName: success-rate
        args:
          - name: service-name
            value: api-active
      scaleDownDelaySeconds: 600
      scaleDownDelayRevisionLimit: 2
```

### 3.3 Blue-Green with Preview Replica Count

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: backend-service
  namespace: production
spec:
  replicas: 20
  selector:
    matchLabels:
      app: backend-service
  template:
    metadata:
      labels:
        app: backend-service
    spec:
      containers:
        - name: backend
          image: backend:v3.0.0
  strategy:
    blueGreen:
      activeService: backend-active
      previewService: backend-preview
      previewReplicaCount: 5  # Only 5 pods for preview (instead of all 20)
      autoPromotionEnabled: false
      autoPromotionSeconds: 300  # Auto-promote after 5 min if analysis passes
      prePromotionAnalysis:
        templates:
          - templateName: integration-tests
        args:
          - name: service-url
            value: "http://backend-preview"
```

---

## 4. Analysis Templates

### 4.1 Prometheus-Based Analysis

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: success-rate
  namespace: production
spec:
  args:
    - name: service-name
    - name: threshold
      value: "0.95"

  metrics:
    - name: success-rate
      interval: 1m
      count: 5
      successCondition: result[0] >= {{args.threshold}}
      failureLimit: 3
      provider:
        prometheus:
          address: http://prometheus.monitoring:9090
          query: |
            sum(rate(http_requests_total{
              service="{{args.service-name}}",
              status=~"2.."
            }[5m]))
            /
            sum(rate(http_requests_total{
              service="{{args.service-name}}"
            }[5m]))
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: latency-p95
  namespace: production
spec:
  args:
    - name: service-name
    - name: threshold-ms
      value: "500"

  metrics:
    - name: latency-p95
      interval: 1m
      count: 5
      successCondition: result[0] < {{args.threshold-ms}}
      failureLimit: 3
      provider:
        prometheus:
          address: http://prometheus.monitoring:9090
          query: |
            histogram_quantile(0.95,
              sum(rate(http_request_duration_seconds_bucket{
                service="{{args.service-name}}"
              }[5m])) by (le)
            ) * 1000
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: error-rate
  namespace: production
spec:
  args:
    - name: service-name
    - name: max-error-rate
      value: "0.05"

  metrics:
    - name: error-rate
      interval: 1m
      count: 5
      successCondition: result[0] <= {{args.max-error-rate}}
      failureLimit: 2
      provider:
        prometheus:
          address: http://prometheus.monitoring:9090
          query: |
            sum(rate(http_requests_total{
              service="{{args.service-name}}",
              status=~"5.."
            }[5m]))
            /
            sum(rate(http_requests_total{
              service="{{args.service-name}}"
            }[5m]))
```

### 4.2 Job-Based Analysis (Smoke Tests)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: smoke-tests
  namespace: production
spec:
  args:
    - name: service-name

  metrics:
    - name: smoke-test
      provider:
        job:
          spec:
            backoffLimit: 0
            template:
              spec:
                containers:
                  - name: test
                    image: curlimages/curl:latest
                    command:
                      - sh
                      - -c
                      - |
                        # Test health endpoint
                        curl -f http://{{args.service-name}}:80/health || exit 1

                        # Test API endpoints
                        curl -f http://{{args.service-name}}:80/api/v1/status || exit 1

                        # Test with authentication
                        curl -f -H "Authorization: Bearer test-token" \
                          http://{{args.service-name}}:80/api/v1/protected || exit 1

                        echo "All smoke tests passed"
                restartPolicy: Never
```

### 4.3 Web/REST API Analysis

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: external-healthcheck
  namespace: production
spec:
  args:
    - name: url

  metrics:
    - name: healthcheck
      interval: 30s
      count: 10
      successCondition: result == "200"
      failureLimit: 3
      provider:
        web:
          url: "{{args.url}}/health"
          timeoutSeconds: 10
          jsonPath: "{$.status}"
          headers:
            - key: "X-Health-Check"
              value: "argo-rollouts"
```

### 4.4 Datadog Analysis

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: datadog-analysis
  namespace: production
spec:
  args:
    - name: service-name
    - name: apiKey
      valueFrom:
        secretKeyRef:
          name: datadog
          key: api-key
    - name: appKey
      valueFrom:
        secretKeyRef:
          name: datadog
          key: app-key

  metrics:
    - name: error-rate
      interval: 1m
      count: 5
      successCondition: result < 0.05
      failureLimit: 3
      provider:
        datadog:
          apiVersion: v1
          interval: 5m
          query: |
            avg:trace.http.request.errors{service:{{args.service-name}}}
```

### 4.5 New Relic Analysis

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: newrelic-analysis
  namespace: production
spec:
  args:
    - name: service-name
    - name: account-id
    - name: api-key
      valueFrom:
        secretKeyRef:
          name: newrelic
          key: api-key

  metrics:
    - name: error-rate
      interval: 1m
      count: 5
      successCondition: result[0] < 1.0
      failureLimit: 3
      provider:
        newRelic:
          profile: default
          query: |
            FROM Transaction
            SELECT percentage(count(*), WHERE error IS true)
            WHERE appName = '{{args.service-name}}'
```

### 4.6 ClusterAnalysisTemplate (Cluster-Wide)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ClusterAnalysisTemplate
metadata:
  name: global-success-rate
spec:
  args:
    - name: service-name
    - name: namespace

  metrics:
    - name: success-rate
      interval: 1m
      count: 5
      successCondition: result[0] >= 0.95
      failureLimit: 3
      provider:
        prometheus:
          address: http://prometheus.monitoring:9090
          query: |
            sum(rate(http_requests_total{
              service="{{args.service-name}}",
              namespace="{{args.namespace}}",
              status=~"2.."
            }[5m]))
            /
            sum(rate(http_requests_total{
              service="{{args.service-name}}",
              namespace="{{args.namespace}}"
            }[5m]))
```

---

## 5. Traffic Management

### 5.1 Istio Traffic Routing

**VirtualService**:
```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: payment-api
  namespace: payments
spec:
  hosts:
    - payment-api
  http:
    - name: primary
      match:
        - headers:
            x-canary:
              exact: "true"
      route:
        - destination:
            host: payment-api
            subset: canary
          weight: 100
    - name: default
      route:
        - destination:
            host: payment-api
            subset: stable
          weight: 100
        - destination:
            host: payment-api
            subset: canary
          weight: 0
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: payment-api
  namespace: payments
spec:
  host: payment-api
  subsets:
    - name: stable
      labels:
        rollouts-pod-template-hash: stable
    - name: canary
      labels:
        rollouts-pod-template-hash: canary
```

**Rollout with Istio**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: payment-api
  namespace: payments
spec:
  replicas: 10
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      containers:
        - name: api
          image: payment-api:v2.0.0
  strategy:
    canary:
      canaryService: payment-api-canary
      stableService: payment-api-stable
      trafficRouting:
        istio:
          virtualService:
            name: payment-api
            routes:
              - primary
          destinationRule:
            name: payment-api
            canarySubsetName: canary
            stableSubsetName: stable
      steps:
        - setWeight: 10
        - pause: {duration: 2m}
        - setWeight: 25
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 10m}
        - setWeight: 75
        - pause: {duration: 5m}
```

### 5.2 NGINX Ingress Traffic Routing

**Ingress**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-app
  namespace: production
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-app-stable
                port:
                  number: 80
```

**Rollout with NGINX**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 5
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
        - name: web
          image: web-app:v2.0.0
  strategy:
    canary:
      canaryService: web-app-canary
      stableService: web-app-stable
      trafficRouting:
        nginx:
          stableIngress: web-app
          additionalIngressAnnotations:
            canary-by-header: X-Canary
            canary-by-header-value: "true"
      steps:
        - setWeight: 10
        - pause: {duration: 2m}
        - setHeaderRoute:
            name: header-route
            match:
              - headerName: X-Canary
                headerValue:
                  exact: "always"
        - pause: {duration: 5m}
        - setWeight: 25
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 10m}
```

### 5.3 AWS ALB Traffic Routing

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: mobile-api
  namespace: production
spec:
  replicas: 10
  selector:
    matchLabels:
      app: mobile-api
  template:
    metadata:
      labels:
        app: mobile-api
    spec:
      containers:
        - name: api
          image: mobile-api:v3.0.0
  strategy:
    canary:
      canaryService: mobile-api-canary
      stableService: mobile-api-stable
      trafficRouting:
        alb:
          ingress: mobile-api
          servicePort: 80
          rootService: mobile-api-root
      steps:
        - setWeight: 10
        - pause: {duration: 5m}
        - setWeight: 20
        - pause: {duration: 5m}
        - setWeight: 40
        - pause: {duration: 10m}
        - setWeight: 60
        - pause: {duration: 10m}
        - setWeight: 80
        - pause: {duration: 5m}
```

### 5.4 SMI (Service Mesh Interface)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: smi-app
  namespace: production
spec:
  replicas: 5
  selector:
    matchLabels:
      app: smi-app
  template:
    metadata:
      labels:
        app: smi-app
    spec:
      containers:
        - name: app
          image: smi-app:v2.0.0
  strategy:
    canary:
      canaryService: smi-app-canary
      stableService: smi-app-stable
      trafficRouting:
        smi:
          rootService: smi-app-root
          trafficSplitName: smi-app-split
      steps:
        - setWeight: 10
        - pause: {duration: 2m}
        - setWeight: 25
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 10m}
```

---

## 6. Advanced Strategies

### 6.1 Experiment (A/B Testing)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Experiment
metadata:
  name: ab-test-checkout
  namespace: production
spec:
  duration: 1h
  progressDeadlineSeconds: 600

  templates:
    # Baseline (current version)
    - name: baseline
      replicas: 5
      selector:
        matchLabels:
          app: checkout
          version: baseline
      template:
        metadata:
          labels:
            app: checkout
            version: baseline
        spec:
          containers:
            - name: checkout
              image: checkout:v1.0.0

    # Variant A (new algorithm)
    - name: variant-a
      replicas: 5
      selector:
        matchLabels:
          app: checkout
          version: variant-a
      template:
        metadata:
          labels:
            app: checkout
            version: variant-a
        spec:
          containers:
            - name: checkout
              image: checkout:v2.0.0-variant-a

    # Variant B (different UI)
    - name: variant-b
      replicas: 5
      selector:
        matchLabels:
          app: checkout
          version: variant-b
      template:
        metadata:
          labels:
            app: checkout
            version: variant-b
        spec:
          containers:
            - name: checkout
              image: checkout:v2.0.0-variant-b

  analyses:
    - name: conversion-rate
      templateName: conversion-analysis
      args:
        - name: service-name
          value: checkout
```

### 6.2 Rollout with Experiments

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: recommendation-engine
  namespace: production
spec:
  replicas: 10
  selector:
    matchLabels:
      app: recommendation
  template:
    metadata:
      labels:
        app: recommendation
    spec:
      containers:
        - name: engine
          image: recommendation:v2.0.0
  strategy:
    canary:
      steps:
        - setWeight: 10
        - pause: {duration: 1m}

        - experiment:
            duration: 10m
            templates:
              - name: variant-a
                specRef: canary
                weight: 50
              - name: variant-b
                specRef: stable
                weight: 50
            analyses:
              - name: success-rate
                templateName: success-rate
                args:
                  - name: service-name
                    value: recommendation

        - setWeight: 25
        - pause: {duration: 5m}
        - setWeight: 50
```

### 6.3 Progressive Delivery with Notifications

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: critical-service
  namespace: production
  annotations:
    notifications.argoproj.io/subscribe.on-rollout-completed.slack: production-alerts
    notifications.argoproj.io/subscribe.on-rollout-aborted.slack: production-alerts
    notifications.argoproj.io/subscribe.on-analysis-run-failed.slack: production-alerts
spec:
  replicas: 20
  selector:
    matchLabels:
      app: critical-service
  template:
    metadata:
      labels:
        app: critical-service
    spec:
      containers:
        - name: service
          image: critical-service:v3.0.0
  strategy:
    canary:
      maxSurge: "25%"
      maxUnavailable: 0
      steps:
        - setWeight: 5
        - pause: {duration: 2m}

        - analysis:
            templates:
              - templateName: success-rate
              - templateName: error-rate
              - templateName: latency-p95
              - templateName: latency-p99
            args:
              - name: service-name
                value: critical-service

        - setWeight: 10
        - pause: {duration: 5m}

        - setWeight: 20
        - pause: {duration: 10m}

        - setWeight: 40
        - pause: {duration: 15m}

        - setWeight: 60
        - pause: {duration: 15m}

        - setWeight: 80
        - pause: {duration: 10m}

      abortScaleDownDelaySeconds: 600
```

### 6.4 Multi-Phase Rollout

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: global-api
  namespace: production
spec:
  replicas: 100
  selector:
    matchLabels:
      app: global-api
  template:
    metadata:
      labels:
        app: global-api
    spec:
      containers:
        - name: api
          image: global-api:v4.0.0
  strategy:
    canary:
      steps:
        # Phase 1: Internal testing (1%)
        - setWeight: 1
        - pause: {duration: 10m}
        - analysis:
            templates:
              - templateName: comprehensive-analysis

        # Phase 2: Beta users (5%)
        - setWeight: 5
        - pause: {duration: 30m}
        - analysis:
            templates:
              - templateName: comprehensive-analysis

        # Phase 3: Early adopters (10%)
        - setWeight: 10
        - pause: {duration: 1h}

        # Phase 4: Gradual rollout (25%, 50%, 75%)
        - setWeight: 25
        - pause: {duration: 2h}

        - setWeight: 50
        - pause: {duration: 3h}

        - setWeight: 75
        - pause: {duration: 2h}

        # Phase 5: Full rollout
        - setWeight: 100
```

---

## 7. Metrics Providers

### 7.1 Prometheus Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argo-rollouts-config
  namespace: argo-rollouts
data:
  metricProviderPlugins: |
    - name: prometheus
      location: builtin
```

### 7.2 Datadog Configuration

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: datadog-api-key
  namespace: argo-rollouts
type: Opaque
stringData:
  api-key: <your-datadog-api-key>
  app-key: <your-datadog-app-key>
```

### 7.3 New Relic Configuration

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: newrelic-api-key
  namespace: argo-rollouts
type: Opaque
stringData:
  api-key: <your-newrelic-api-key>
  account-id: <your-account-id>
```

### 7.4 Wavefront Configuration

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: wavefront-analysis
spec:
  args:
    - name: service-name

  metrics:
    - name: error-rate
      interval: 1m
      count: 5
      successCondition: result[0] < 0.05
      provider:
        wavefront:
          address: https://your-instance.wavefront.com
          query: |
            sum(rate(ts("http.errors", source="{{args.service-name}}")))
```

---

## 8. Integration Patterns

### 8.1 Argo CD Integration

**Application with Rollout**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: payment-service
  namespace: argocd
spec:
  project: production
  source:
    repoURL: https://github.com/org/payment-service
    targetRevision: v2.0.0
    path: k8s/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: payments
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
  # Argo CD will manage the Rollout resource
```

**Sync with Rollout Promotion**:
```bash
# Deploy new version via Argo CD
argocd app sync payment-service

# Rollout will start automatically
kubectl argo rollouts get rollout payment-api -n payments --watch

# Promote canary
kubectl argo rollouts promote payment-api -n payments
```

### 8.2 Flagger Migration Pattern

**From Flagger to Argo Rollouts**:
```yaml
# Original Flagger Canary
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: myapp
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myapp
  progressDeadlineSeconds: 600
  service:
    port: 80
  analysis:
    interval: 1m
    threshold: 5
    maxWeight: 50
    stepWeight: 10
    metrics:
      - name: request-success-rate
        threshold: 99

# Equivalent Argo Rollout
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: myapp
spec:
  replicas: 5
  selector:
    matchLabels:
      app: myapp
  template:
    # ... pod template
  strategy:
    canary:
      maxUnavailable: 0
      steps:
        - setWeight: 10
        - pause: {duration: 1m}
        - analysis:
            templates:
              - templateName: success-rate
            args:
              - name: threshold
                value: "0.99"
        - setWeight: 20
        - pause: {duration: 1m}
        - setWeight: 30
        - pause: {duration: 1m}
        - setWeight: 40
        - pause: {duration: 1m}
        - setWeight: 50
```

---

## 9. Monitoring & Observability

### 9.1 Prometheus Metrics

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argo-rollouts
  namespace: argo-rollouts
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: argo-rollouts
  endpoints:
    - port: metrics
      interval: 30s
```

**Key Metrics**:
```promql
# Rollout info
rollout_info{name="myapp",namespace="production"}

# Rollout phase
rollout_phase{name="myapp",namespace="production",phase="Progressing"}

# Analysis run status
analysis_run_metric_phase{name="myapp-analysis",phase="Successful"}

# Rollout duration
histogram_quantile(0.95, rate(rollout_reconcile_duration_seconds_bucket[5m]))
```

### 9.2 Grafana Dashboards

**Example Queries**:
```promql
# Success rate of rollouts
sum(rate(rollout_phase{phase="Healthy"}[5m])) / sum(rate(rollout_phase[5m]))

# Failed analysis runs
sum(increase(analysis_run_metric_phase{phase="Failed"}[1h]))

# Active canary rollouts
count(rollout_phase{phase="Progressing"})

# Time to complete rollout
histogram_quantile(0.95,
  sum(rate(rollout_reconcile_duration_seconds_bucket[5m])) by (le)
)
```

### 9.3 Notifications

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argo-rollouts-notification-configmap
  namespace: argo-rollouts
data:
  service.slack: |
    token: $slack-token

  template.rollout-completed: |
    message: |
      Rollout {{.rollout.metadata.name}} completed successfully in namespace {{.rollout.metadata.namespace}}
    slack:
      attachments: |
        [{
          "title": "Rollout Completed",
          "color": "good",
          "fields": [{
            "title": "Name",
            "value": "{{.rollout.metadata.name}}",
            "short": true
          }]
        }]

  trigger.on-rollout-completed: |
    - when: rollout.status.phase == 'Healthy'
      send: [rollout-completed]
```

---

## 10. Troubleshooting

### 10.1 Common Issues

**Rollout stuck in Progressing**:
```bash
# Check rollout status
kubectl argo rollouts get rollout myapp -n production

# Check analysis runs
kubectl get analysisrun -n production

# Check replica sets
kubectl get rs -n production -l app=myapp

# Describe rollout
kubectl describe rollout myapp -n production
```

**Analysis failing**:
```bash
# Check analysis run
kubectl get analysisrun myapp-canary-12345 -n production -o yaml

# Check metric results
kubectl describe analysisrun myapp-canary-12345 -n production

# Test Prometheus query manually
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Visit http://localhost:9090 and run the query
```

**Traffic not shifting**:
```bash
# Verify services exist
kubectl get svc -n production -l app=myapp

# Check Istio VirtualService
kubectl get virtualservice myapp -n production -o yaml

# Verify DestinationRule
kubectl get destinationrule myapp -n production -o yaml

# Check pod labels
kubectl get pods -n production -l app=myapp --show-labels
```

### 10.2 Debugging Commands

```bash
# Watch rollout progress
kubectl argo rollouts get rollout myapp -n production --watch

# List all rollouts
kubectl argo rollouts list rollouts -n production

# Abort rollout
kubectl argo rollouts abort myapp -n production

# Retry rollout
kubectl argo rollouts retry rollout myapp -n production

# Set image
kubectl argo rollouts set image myapp api=myapp:v2.1.0 -n production

# Undo rollout
kubectl argo rollouts undo myapp -n production

# Pause rollout
kubectl argo rollouts pause myapp -n production

# Resume rollout
kubectl argo rollouts resume myapp -n production

# Get rollout history
kubectl argo rollouts history myapp -n production
```

### 10.3 Performance Tuning

```yaml
# Controller tuning
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argo-rollouts
  namespace: argo-rollouts
spec:
  template:
    spec:
      containers:
        - name: argo-rollouts
          env:
            # Increase worker threads
            - name: ARGO_ROLLOUTS_CONTROLLER_WORKERS
              value: "10"

            # Adjust reconciliation interval
            - name: ARGO_ROLLOUTS_RESYNC_PERIOD
              value: "30s"

            # Set log level
            - name: LOG_LEVEL
              value: "info"
```

This comprehensive guide covers Argo Rollouts patterns for production progressive delivery. For GitOps workflows, see `argocd-guide.md`, and for CI/CD orchestration, see `workflows-guide.md`.
