# Argo Workflows Complete Reference Guide

## Table of Contents
1. [Installation & Setup](#1-installation--setup)
2. [Workflow Fundamentals](#2-workflow-fundamentals)
3. [DAG Workflows](#3-dag-workflows)
4. [Artifact Management](#4-artifact-management)
5. [Retry Strategies](#5-retry-strategies)
6. [Workflow Templates](#6-workflow-templates)
7. [Advanced Patterns](#7-advanced-patterns)
8. [CI/CD Integration](#8-cicd-integration)
9. [Security & RBAC](#9-security--rbac)
10. [Monitoring & Troubleshooting](#10-monitoring--troubleshooting)

---

## 1. Installation & Setup

### 1.1 Quick Installation

```bash
# Install Argo Workflows
kubectl create namespace argo
kubectl apply -n argo -f https://github.com/argoproj/argo-workflows/releases/download/v3.5.0/install.yaml

# Wait for pods
kubectl wait --for=condition=Ready pods --all -n argo --timeout=300s

# Port-forward UI
kubectl -n argo port-forward deployment/argo-server 2746:2746

# Access UI at https://localhost:2746
```

### 1.2 Production Configuration

**Server ConfigMap**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: workflow-controller-configmap
  namespace: argo
data:
  # Artifact repository
  artifactRepository: |
    archiveLogs: true
    s3:
      endpoint: s3.amazonaws.com
      bucket: my-workflows-artifacts
      region: us-east-1
      insecure: false
      accessKeySecret:
        name: s3-credentials
        key: accessKey
      secretKeySecret:
        name: s3-credentials
        key: secretKey

  # Resource limits
  containerRuntimeExecutor: emissary
  executor: |
    resources:
      requests:
        cpu: 10m
        memory: 64Mi
      limits:
        cpu: 100m
        memory: 128Mi

  # Workflow defaults
  workflowDefaults: |
    spec:
      ttlStrategy:
        secondsAfterCompletion: 86400  # 1 day
        secondsAfterSuccess: 3600      # 1 hour
        secondsAfterFailure: 604800    # 7 days
      podGC:
        strategy: OnWorkflowCompletion

  # Parallelism limits
  parallelism: 10
  resourceQuota: |
    limits:
      cpu: 10
      memory: 20Gi

  # Metrics
  metricsConfig: |
    enabled: true
    path: /metrics
    port: 9090
```

### 1.3 RBAC Setup

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: workflow-executor
  namespace: argo
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: workflow-executor-role
  namespace: argo
rules:
  - apiGroups: [""]
    resources: [pods, pods/log]
    verbs: [get, watch, list]
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
  - apiGroups: [argoproj.io]
    resources: [workflows, workflowtemplates, cronworkflows]
    verbs: [get, list, watch, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: workflow-executor-binding
  namespace: argo
subjects:
  - kind: ServiceAccount
    name: workflow-executor
    namespace: argo
roleRef:
  kind: Role
  name: workflow-executor-role
  apiGroup: rbac.authorization.k8s.io
```

---

## 2. Workflow Fundamentals

### 2.1 Basic Step Workflow

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: hello-world-
  namespace: argo
spec:
  entrypoint: main
  serviceAccountName: workflow-executor

  templates:
    - name: main
      steps:
        - - name: step1
            template: print-message
            arguments:
              parameters:
                - name: message
                  value: "Hello"

        - - name: step2
            template: print-message
            arguments:
              parameters:
                - name: message
                  value: "World"

    - name: print-message
      inputs:
        parameters:
          - name: message
      container:
        image: alpine:latest
        command: [echo]
        args: ["{{inputs.parameters.message}}"]
```

### 2.2 Parallel Steps

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: parallel-steps-
spec:
  entrypoint: main
  templates:
    - name: main
      steps:
        # All steps in same array element run in parallel
        - - name: step1a
            template: process
            arguments:
              parameters:
                - name: task
                  value: "A"

          - name: step1b
            template: process
            arguments:
              parameters:
                - name: task
                  value: "B"

          - name: step1c
            template: process
            arguments:
              parameters:
                - name: task
                  value: "C"

        # Next step waits for all above to complete
        - - name: step2
            template: summarize

    - name: process
      inputs:
        parameters:
          - name: task
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Processing {{inputs.parameters.task}}; sleep 5"]

    - name: summarize
      container:
        image: alpine:latest
        command: [echo, "All tasks complete"]
```

### 2.3 Conditional Execution

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: conditional-
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: environment
        value: "production"

  templates:
    - name: main
      steps:
        - - name: check-env
            template: print-env

        - - name: run-tests
            template: test
            when: "{{workflow.parameters.environment}} != production"

        - - name: deploy
            template: deploy
            when: "{{workflow.parameters.environment}} == production"

    - name: print-env
      container:
        image: alpine:latest
        command: [echo, "Environment: {{workflow.parameters.environment}}"]

    - name: test
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Running tests; exit 0"]

    - name: deploy
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Deploying to production"]
```

---

## 3. DAG Workflows

### 3.1 Basic DAG

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: dag-workflow-
spec:
  entrypoint: main

  templates:
    - name: main
      dag:
        tasks:
          - name: A
            template: task
            arguments:
              parameters:
                - name: name
                  value: "A"

          - name: B
            template: task
            dependencies: [A]
            arguments:
              parameters:
                - name: name
                  value: "B"

          - name: C
            template: task
            dependencies: [A]
            arguments:
              parameters:
                - name: name
                  value: "C"

          - name: D
            template: task
            dependencies: [B, C]
            arguments:
              parameters:
                - name: name
                  value: "D"

    - name: task
      inputs:
        parameters:
          - name: name
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Task {{inputs.parameters.name}}; sleep 5"]
```

### 3.2 Complex CI/CD DAG

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: cicd-pipeline-
spec:
  entrypoint: main
  serviceAccountName: workflow-executor
  volumeClaimTemplates:
    - metadata:
        name: workspace
      spec:
        accessModes: [ReadWriteOnce]
        resources:
          requests:
            storage: 10Gi

  arguments:
    parameters:
      - name: repo-url
        value: "https://github.com/org/app.git"
      - name: branch
        value: "main"
      - name: image-tag
        value: "v1.0.0"

  templates:
    - name: main
      dag:
        tasks:
          # Checkout code
          - name: checkout
            template: git-clone
            arguments:
              parameters:
                - name: repo-url
                  value: "{{workflow.parameters.repo-url}}"
                - name: branch
                  value: "{{workflow.parameters.branch}}"

          # Parallel: Linting and unit tests
          - name: lint
            template: run-lint
            dependencies: [checkout]

          - name: unit-tests
            template: run-tests
            dependencies: [checkout]
            arguments:
              parameters:
                - name: test-type
                  value: "unit"

          # Build image
          - name: build
            template: build-image
            dependencies: [lint, unit-tests]
            arguments:
              parameters:
                - name: tag
                  value: "{{workflow.parameters.image-tag}}"

          # Parallel: Security scan and integration tests
          - name: security-scan
            template: scan-image
            dependencies: [build]
            arguments:
              parameters:
                - name: image
                  value: "myregistry/app:{{workflow.parameters.image-tag}}"

          - name: integration-tests
            template: run-tests
            dependencies: [build]
            arguments:
              parameters:
                - name: test-type
                  value: "integration"

          # Deploy to staging
          - name: deploy-staging
            template: deploy
            dependencies: [security-scan, integration-tests]
            arguments:
              parameters:
                - name: environment
                  value: "staging"
                - name: image
                  value: "myregistry/app:{{workflow.parameters.image-tag}}"

          # Smoke tests
          - name: smoke-tests
            template: run-tests
            dependencies: [deploy-staging]
            arguments:
              parameters:
                - name: test-type
                  value: "smoke"

          # Deploy to production (manual approval via suspend)
          - name: approval
            template: suspend
            dependencies: [smoke-tests]

          - name: deploy-production
            template: deploy
            dependencies: [approval]
            arguments:
              parameters:
                - name: environment
                  value: "production"
                - name: image
                  value: "myregistry/app:{{workflow.parameters.image-tag}}"

    - name: git-clone
      inputs:
        parameters:
          - name: repo-url
          - name: branch
      container:
        image: alpine/git:latest
        command: [sh, -c]
        args:
          - |
            git clone {{inputs.parameters.repo-url}} /workspace/src
            cd /workspace/src && git checkout {{inputs.parameters.branch}}
        volumeMounts:
          - name: workspace
            mountPath: /workspace

    - name: run-lint
      container:
        image: golangci/golangci-lint:latest
        command: [sh, -c]
        args:
          - |
            cd /workspace/src
            golangci-lint run ./...
        volumeMounts:
          - name: workspace
            mountPath: /workspace

    - name: run-tests
      inputs:
        parameters:
          - name: test-type
      container:
        image: golang:1.21
        command: [sh, -c]
        args:
          - |
            cd /workspace/src
            go test -v ./... -tags={{inputs.parameters.test-type}}
        volumeMounts:
          - name: workspace
            mountPath: /workspace
      outputs:
        artifacts:
          - name: test-results
            path: /workspace/src/test-results.xml
            s3:
              key: "{{workflow.name}}/{{inputs.parameters.test-type}}-results.xml"

    - name: build-image
      inputs:
        parameters:
          - name: tag
      container:
        image: gcr.io/kaniko-project/executor:latest
        args:
          - --context=/workspace/src
          - --dockerfile=/workspace/src/Dockerfile
          - --destination=myregistry/app:{{inputs.parameters.tag}}
          - --cache=true
          - --cache-ttl=24h
        volumeMounts:
          - name: workspace
            mountPath: /workspace
      outputs:
        parameters:
          - name: digest
            valueFrom:
              path: /workspace/digest

    - name: scan-image
      inputs:
        parameters:
          - name: image
      container:
        image: aquasec/trivy:latest
        command: [sh, -c]
        args:
          - |
            trivy image --severity HIGH,CRITICAL \
              --exit-code 1 \
              --format json \
              --output /tmp/scan-results.json \
              {{inputs.parameters.image}}
      outputs:
        artifacts:
          - name: scan-results
            path: /tmp/scan-results.json
            s3:
              key: "{{workflow.name}}/scan-results.json"

    - name: deploy
      inputs:
        parameters:
          - name: environment
          - name: image
      resource:
        action: apply
        manifest: |
          apiVersion: apps/v1
          kind: Deployment
          metadata:
            name: app
            namespace: {{inputs.parameters.environment}}
          spec:
            replicas: 3
            selector:
              matchLabels:
                app: myapp
            template:
              metadata:
                labels:
                  app: myapp
              spec:
                containers:
                  - name: app
                    image: {{inputs.parameters.image}}
                    ports:
                      - containerPort: 8080

    - name: suspend
      suspend: {}
```

### 3.3 DAG with Fan-Out/Fan-In

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: fan-out-fan-in-
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: items
        value: '["item1", "item2", "item3", "item4"]'

  templates:
    - name: main
      dag:
        tasks:
          - name: generate
            template: generate-items

          - name: process
            template: process-item
            dependencies: [generate]
            arguments:
              parameters:
                - name: item
                  value: "{{item}}"
            withParam: "{{tasks.generate.outputs.result}}"

          - name: aggregate
            template: aggregate-results
            dependencies: [process]

    - name: generate-items
      script:
        image: python:3.11
        command: [python]
        source: |
          import json
          items = {{workflow.parameters.items}}
          print(json.dumps(items))

    - name: process-item
      inputs:
        parameters:
          - name: item
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Processing {{inputs.parameters.item}}; sleep 2"]

    - name: aggregate-results
      container:
        image: alpine:latest
        command: [echo, "All items processed"]
```

---

## 4. Artifact Management

### 4.1 S3 Artifact Repository

```yaml
# S3 credentials secret
apiVersion: v1
kind: Secret
metadata:
  name: s3-credentials
  namespace: argo
type: Opaque
stringData:
  accessKey: AKIAIOSFODNN7EXAMPLE
  secretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: artifact-example-
spec:
  entrypoint: main
  artifactRepositoryRef:
    configMap: workflow-controller-configmap
    key: artifactRepository

  templates:
    - name: main
      steps:
        - - name: generate
            template: generate-artifact

        - - name: consume
            template: consume-artifact
            arguments:
              artifacts:
                - name: input-data
                  from: "{{steps.generate.outputs.artifacts.output-data}}"

    - name: generate-artifact
      container:
        image: alpine:latest
        command: [sh, -c]
        args:
          - |
            echo "Generated data" > /tmp/output.txt
            date >> /tmp/output.txt
      outputs:
        artifacts:
          - name: output-data
            path: /tmp/output.txt
            s3:
              key: "{{workflow.name}}/output.txt"

    - name: consume-artifact
      inputs:
        artifacts:
          - name: input-data
            path: /tmp/input.txt
      container:
        image: alpine:latest
        command: [cat, /tmp/input.txt]
```

### 4.2 Git Artifact Input

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: git-artifact-
spec:
  entrypoint: main

  templates:
    - name: main
      inputs:
        artifacts:
          - name: source-code
            path: /src
            git:
              repo: https://github.com/argoproj/argo-workflows.git
              revision: "v3.5.0"
              depth: 1
              singleBranch: true
      container:
        image: golang:1.21
        command: [sh, -c]
        args:
          - |
            cd /src
            go build -o /tmp/app ./cmd/argo
      outputs:
        artifacts:
          - name: binary
            path: /tmp/app
```

### 4.3 Artifact GC and Retention

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: artifact-retention-
spec:
  entrypoint: main
  artifactGC:
    strategy: OnWorkflowDeletion
    serviceAccountName: artifact-gc-sa

  templates:
    - name: main
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo test > /tmp/data.txt"]
      outputs:
        artifacts:
          - name: data
            path: /tmp/data.txt
            archive:
              none: {}  # Don't tar/gzip
            s3:
              key: "{{workflow.name}}/data.txt"
```

### 4.4 Multiple Artifact Repositories

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: multi-artifact-repo-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        - - name: save-to-s3
            template: save-s3

        - - name: save-to-gcs
            template: save-gcs

    - name: save-s3
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo S3 data > /tmp/s3.txt"]
      outputs:
        artifacts:
          - name: s3-artifact
            path: /tmp/s3.txt
            s3:
              endpoint: s3.amazonaws.com
              bucket: my-s3-bucket
              key: "{{workflow.name}}/s3.txt"
              accessKeySecret:
                name: s3-credentials
                key: accessKey
              secretKeySecret:
                name: s3-credentials
                key: secretKey

    - name: save-gcs
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo GCS data > /tmp/gcs.txt"]
      outputs:
        artifacts:
          - name: gcs-artifact
            path: /tmp/gcs.txt
            gcs:
              bucket: my-gcs-bucket
              key: "{{workflow.name}}/gcs.txt"
              serviceAccountKeySecret:
                name: gcs-credentials
                key: serviceAccountKey
```

---

## 5. Retry Strategies

### 5.1 Basic Retry

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: retry-basic-
spec:
  entrypoint: main

  templates:
    - name: main
      retryStrategy:
        limit: 3
        retryPolicy: "Always"
        backoff:
          duration: "5s"
          factor: 2
          maxDuration: "1m"
      container:
        image: alpine:latest
        command: [sh, -c]
        args:
          - |
            # 50% chance of failure
            if [ $((RANDOM % 2)) -eq 0 ]; then
              echo "Success!"
              exit 0
            else
              echo "Failed, will retry..."
              exit 1
            fi
```

### 5.2 Retry Policies

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: retry-policies-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        - - name: retry-always
            template: task
            arguments:
              parameters:
                - name: policy
                  value: "Always"

        - - name: retry-on-failure
            template: task
            arguments:
              parameters:
                - name: policy
                  value: "OnFailure"

        - - name: retry-on-error
            template: task
            arguments:
              parameters:
                - name: policy
                  value: "OnError"

        - - name: retry-on-transient-error
            template: task
            arguments:
              parameters:
                - name: policy
                  value: "OnTransientError"

    - name: task
      inputs:
        parameters:
          - name: policy
      retryStrategy:
        limit: 3
        retryPolicy: "{{inputs.parameters.policy}}"
        backoff:
          duration: "10s"
          factor: 2
      container:
        image: curlimages/curl:latest
        command: [sh, -c]
        args:
          - |
            # Simulate API call
            curl -f https://api.example.com/endpoint || exit 1
```

### 5.3 Expression-Based Retry

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: retry-expression-
spec:
  entrypoint: main

  templates:
    - name: main
      retryStrategy:
        limit: 5
        retryPolicy: "Always"
        backoff:
          duration: "10s"
          factor: 2
          maxDuration: "5m"
        expression: "asInt(lastRetry.exitCode) == 1"  # Only retry on exit code 1
      container:
        image: alpine:latest
        command: [sh, -c]
        args:
          - |
            # Exit with different codes
            exit $((RANDOM % 3))  # 0, 1, or 2
```

### 5.4 Per-Step Retry

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: per-step-retry-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        - - name: critical-step
            template: api-call
            retryStrategy:
              limit: 10
              retryPolicy: "OnError"
              backoff:
                duration: "5s"
                factor: 2
                maxDuration: "10m"

        - - name: non-critical-step
            template: log-event
            retryStrategy:
              limit: 2
              retryPolicy: "Always"

    - name: api-call
      container:
        image: curlimages/curl:latest
        command: [curl, -f, "https://api.example.com/critical"]

    - name: log-event
      container:
        image: curlimages/curl:latest
        command: [curl, -X, POST, "https://logs.example.com/event"]
```

### 5.5 Timeout with Retry

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: timeout-retry-
spec:
  entrypoint: main

  templates:
    - name: main
      timeout: "5m"  # Total workflow timeout
      retryStrategy:
        limit: 3
        backoff:
          duration: "30s"
      steps:
        - - name: step1
            template: long-running-task
            timeout: "2m"  # Per-step timeout

    - name: long-running-task
      retryStrategy:
        limit: 2
        backoff:
          duration: "10s"
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["sleep 30; echo Done"]
```

---

## 6. Workflow Templates

### 6.1 WorkflowTemplate (Reusable Workflows)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: build-test-deploy
  namespace: argo
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: repo-url
      - name: image-name
      - name: environment

  templates:
    - name: main
      dag:
        tasks:
          - name: checkout
            template: git-clone

          - name: test
            template: run-tests
            dependencies: [checkout]

          - name: build
            template: build-image
            dependencies: [test]

          - name: deploy
            template: deploy-app
            dependencies: [build]

    - name: git-clone
      container:
        image: alpine/git:latest
        command: [git, clone, "{{workflow.parameters.repo-url}}", /workspace]

    - name: run-tests
      container:
        image: golang:1.21
        command: [go, test, ./...]
        workingDir: /workspace

    - name: build-image
      container:
        image: gcr.io/kaniko-project/executor:latest
        args:
          - --dockerfile=/workspace/Dockerfile
          - --destination={{workflow.parameters.image-name}}

    - name: deploy-app
      resource:
        action: apply
        manifest: |
          apiVersion: apps/v1
          kind: Deployment
          metadata:
            name: app
            namespace: {{workflow.parameters.environment}}
          spec:
            template:
              spec:
                containers:
                  - name: app
                    image: {{workflow.parameters.image-name}}
```

**Using WorkflowTemplate**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: deploy-frontend-
spec:
  workflowTemplateRef:
    name: build-test-deploy
  arguments:
    parameters:
      - name: repo-url
        value: "https://github.com/org/frontend.git"
      - name: image-name
        value: "myregistry/frontend:v1.0.0"
      - name: environment
        value: "production"
```

### 6.2 ClusterWorkflowTemplate (Cluster-Wide)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ClusterWorkflowTemplate
metadata:
  name: security-scan
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: image

  templates:
    - name: main
      steps:
        - - name: trivy-scan
            template: trivy

        - - name: grype-scan
            template: grype

        - - name: aggregate-results
            template: aggregate

    - name: trivy
      container:
        image: aquasec/trivy:latest
        command: [trivy, image, "{{workflow.parameters.image}}"]

    - name: grype
      container:
        image: anchore/grype:latest
        command: [grype, "{{workflow.parameters.image}}"]

    - name: aggregate
      script:
        image: python:3.11
        command: [python]
        source: |
          # Aggregate scan results
          print("Security scan complete")
```

### 6.3 Template Reference

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: template-ref-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        - - name: security-check
            templateRef:
              name: security-scan
              template: main
              clusterScope: true
            arguments:
              parameters:
                - name: image
                  value: "myregistry/app:v1.0.0"
```

---

## 7. Advanced Patterns

### 7.1 Loops and Iteration

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: loop-example-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        # withItems: Static list
        - - name: process-items
            template: process
            arguments:
              parameters:
                - name: item
                  value: "{{item}}"
            withItems:
              - apple
              - banana
              - cherry

        # withParam: Dynamic list from JSON
        - - name: process-json
            template: process
            arguments:
              parameters:
                - name: item
                  value: "{{item.name}}"
            withParam: '[{"name":"one"},{"name":"two"},{"name":"three"}]'

        # withSequence: Numeric sequence
        - - name: process-sequence
            template: process
            arguments:
              parameters:
                - name: item
                  value: "batch-{{item}}"
            withSequence:
              count: "5"
              start: "1"
              end: "5"

    - name: process
      inputs:
        parameters:
          - name: item
      container:
        image: alpine:latest
        command: [echo, "Processing {{inputs.parameters.item}}"]
```

### 7.2 Data Processing Pipeline

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: data-pipeline-
spec:
  entrypoint: main
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: [ReadWriteOnce]
        resources:
          requests:
            storage: 50Gi

  templates:
    - name: main
      dag:
        tasks:
          - name: extract
            template: extract-data

          - name: transform
            template: transform-data
            dependencies: [extract]

          - name: load
            template: load-data
            dependencies: [transform]

          - name: validate
            template: validate-data
            dependencies: [load]

    - name: extract-data
      script:
        image: python:3.11
        command: [python]
        source: |
          import json
          import random

          # Simulate data extraction
          data = [{"id": i, "value": random.randint(1, 100)} for i in range(1000)]

          with open('/data/raw.json', 'w') as f:
              json.dump(data, f)

          print(f"Extracted {len(data)} records")
        volumeMounts:
          - name: data
            mountPath: /data

    - name: transform-data
      script:
        image: python:3.11
        command: [python]
        source: |
          import json

          with open('/data/raw.json', 'r') as f:
              data = json.load(f)

          # Transform: filter and enrich
          transformed = [
              {**item, "doubled": item["value"] * 2}
              for item in data
              if item["value"] > 50
          ]

          with open('/data/transformed.json', 'w') as f:
              json.dump(transformed, f)

          print(f"Transformed {len(transformed)} records")
        volumeMounts:
          - name: data
            mountPath: /data

    - name: load-data
      script:
        image: python:3.11
        command: [python]
        source: |
          import json

          with open('/data/transformed.json', 'r') as f:
              data = json.load(f)

          # Simulate loading to database
          print(f"Loading {len(data)} records to database...")
          # In real scenario: connect to DB and insert

          with open('/data/load-summary.txt', 'w') as f:
              f.write(f"Loaded {len(data)} records successfully")

          print("Load complete")
        volumeMounts:
          - name: data
            mountPath: /data

    - name: validate-data
      container:
        image: python:3.11
        command: [sh, -c]
        args:
          - |
            python3 -c "
            import json
            with open('/data/transformed.json', 'r') as f:
                data = json.load(f)
            assert len(data) > 0, 'No data found'
            print('Validation passed')
            "
        volumeMounts:
          - name: data
            mountPath: /data
```

### 7.3 Human Approval (Suspend)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: approval-workflow-
spec:
  entrypoint: main

  templates:
    - name: main
      steps:
        - - name: deploy-staging
            template: deploy
            arguments:
              parameters:
                - name: env
                  value: "staging"

        - - name: test-staging
            template: run-tests

        - - name: approval-gate
            template: wait-for-approval

        - - name: deploy-production
            template: deploy
            arguments:
              parameters:
                - name: env
                  value: "production"

    - name: wait-for-approval
      suspend:
        duration: "24h"  # Auto-resume after 24h if not manually approved

    - name: deploy
      inputs:
        parameters:
          - name: env
      container:
        image: alpine:latest
        command: [echo, "Deploying to {{inputs.parameters.env}}"]

    - name: run-tests
      container:
        image: alpine:latest
        command: [echo, "Running tests"]
```

**Resume workflow**:
```bash
# Resume suspended workflow
argo resume <workflow-name>

# Or via kubectl
kubectl patch workflow <workflow-name> -n argo --type='json' \
  -p='[{"op": "replace", "path": "/spec/suspend", "value": false}]'
```

### 7.4 Exit Handler (Cleanup)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: exit-handler-
spec:
  entrypoint: main
  onExit: cleanup

  templates:
    - name: main
      steps:
        - - name: step1
            template: work

        - - name: step2
            template: work

    - name: work
      container:
        image: alpine:latest
        command: [sh, -c]
        args: ["echo Working; sleep 5"]

    - name: cleanup
      container:
        image: alpine:latest
        command: [sh, -c]
        args:
          - |
            echo "Workflow status: {{workflow.status}}"
            echo "Workflow failures: {{workflow.failures}}"
            # Send notifications, cleanup resources, etc.
```

---

## 8. CI/CD Integration

### 8.1 GitHub Actions Trigger

```yaml
# .github/workflows/trigger-argo.yml
name: Trigger Argo Workflow
on:
  push:
    branches: [main]

jobs:
  trigger:
    runs-on: ubuntu-latest
    steps:
      - name: Submit Argo Workflow
        env:
          ARGO_SERVER: argocd.example.com:443
          ARGO_TOKEN: ${{ secrets.ARGO_TOKEN }}
        run: |
          argo submit --from workflowtemplate/build-test-deploy \
            --parameter repo-url=${{ github.repository }} \
            --parameter git-commit=${{ github.sha }} \
            --parameter image-tag=${{ github.ref_name }}-${{ github.sha }}
```

### 8.2 Webhooks (Argo Events Integration)

```yaml
apiVersion: argoproj.io/v1alpha1
kind: EventSource
metadata:
  name: webhook
  namespace: argo-events
spec:
  webhook:
    github:
      port: "12000"
      endpoint: /push
      method: POST
---
apiVersion: argoproj.io/v1alpha1
kind: Sensor
metadata:
  name: webhook-sensor
  namespace: argo-events
spec:
  dependencies:
    - name: github-dep
      eventSourceName: webhook
      eventName: github
  triggers:
    - template:
        name: trigger-workflow
        argoWorkflow:
          operation: submit
          source:
            resource:
              apiVersion: argoproj.io/v1alpha1
              kind: Workflow
              metadata:
                generateName: cicd-
              spec:
                workflowTemplateRef:
                  name: build-test-deploy
                arguments:
                  parameters:
                    - name: repo-url
                      value: "https://github.com/{{.Input.body.repository.full_name}}"
                    - name: git-commit
                      value: "{{.Input.body.after}}"
```

---

## 9. Security & RBAC

### 9.1 Pod Security

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: secure-workflow-
spec:
  entrypoint: main
  serviceAccountName: workflow-executor
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  templates:
    - name: main
      container:
        image: alpine:latest
        command: [sh, -c, "whoami; id"]
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: [ALL]
          readOnlyRootFilesystem: true
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

### 9.2 Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: workflow-network-policy
  namespace: argo
spec:
  podSelector:
    matchLabels:
      workflows.argoproj.io/workflow: "true"
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: argo-server
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow external HTTPS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443
```

---

## 10. Monitoring & Troubleshooting

### 10.1 Prometheus Metrics

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argo-workflows
  namespace: argo
spec:
  selector:
    matchLabels:
      app: workflow-controller
  endpoints:
    - port: metrics
      interval: 30s
```

**Key Metrics**:
```promql
# Workflow count by status
count(argo_workflow_info) by (status)

# Workflow duration
histogram_quantile(0.95, rate(argo_workflow_duration_seconds_bucket[5m]))

# Workflow error rate
rate(argo_workflow_error_count[5m])

# Pending workflows
argo_workflows_pending_count

# Running workflows
argo_workflows_running_count
```

### 10.2 Common Issues

**Workflow stuck pending**:
```bash
# Check workflow status
argo get <workflow-name>

# Check pod status
kubectl get pods -l workflows.argoproj.io/workflow=<workflow-name>

# Describe pod
kubectl describe pod <pod-name>

# Check resource quotas
kubectl describe resourcequota -n argo
```

**Artifact retrieval failures**:
```bash
# Check artifact repository config
kubectl get cm workflow-controller-configmap -n argo -o yaml

# Verify S3 credentials
kubectl get secret s3-credentials -n argo -o yaml

# Test S3 connectivity
kubectl run -it --rm debug --image=amazon/aws-cli --restart=Never -- \
  s3 ls s3://my-bucket
```

This comprehensive guide covers Argo Workflows patterns for production CI/CD. For GitOps delivery, see `argocd-guide.md`, and for progressive delivery, see `rollouts-guide.md`.
