# Sandboxing Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect

1. **Host System** - Sensitivity: CRITICAL
2. **Other Containers** - Sensitivity: HIGH
3. **Host Filesystem** - Sensitivity: HIGH
4. **Network Resources** - Sensitivity: MEDIUM

### Threat Actors

1. **Malicious Code** - Untrusted user input
2. **Compromised Dependencies** - Supply chain attacks
3. **Insider Threats** - Malicious administrators

---

## Attack Scenario 1: Container Escape via runC (CVE-2024-21626)

**Threat Category**: CWE-668 - Exposure of Resource to Wrong Sphere

**Threat Level**: CRITICAL

**Attack Description**:
File descriptor leak in runC allows container escape to host filesystem.

**Attack Flow**:
```
1. Attacker runs malicious container
2. Container image exploits fd leak in runC
3. Gains access to host /sys/fs/cgroup
4. Writes to release_agent for cgroup
5. Host executes attacker-controlled code
6. Full host system compromise
```

**Impact**:
- **Confidentiality**: CRITICAL - Full host access
- **Integrity**: CRITICAL - Host system modification
- **Availability**: CRITICAL - Host can be destroyed

**Mitigation**:
```yaml
# Update to fixed runC version
# Check version: runc --version
# Minimum: 1.1.12

# Additional protections
apiVersion: v1
kind: Pod
spec:
  securityContext:
    # User namespace isolation
    runAsNonRoot: true
    runAsUser: 65534

  containers:
  - name: app
    securityContext:
      # Prevent escape vectors
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

---

## Attack Scenario 2: Seccomp Profile Bypass (CVE-2023-2431)

**Threat Category**: CWE-863 - Incorrect Authorization

**Threat Level**: LOW-MEDIUM

**Attack Description**:
Empty seccomp profile field causes pod to run unconfined.

**Attack Flow**:
```
1. Pod spec has seccomp with empty profile:
   seccompProfile:
     type: Localhost
     localhostProfile: ""
2. Kubelet fails to apply profile
3. Pod runs with all syscalls allowed
4. Attacker executes dangerous syscalls
5. Potential container escape
```

**Mitigation**:
```yaml
# ALWAYS specify valid profile
securityContext:
  seccompProfile:
    type: RuntimeDefault  # Use this, not Localhost

# Or with valid local profile
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/audit.json  # Valid path
```

**Testing**:
```bash
# Verify seccomp is applied
kubectl exec pod-name -- cat /proc/self/status | grep Seccomp
# Should show: Seccomp: 2 (filter mode)
```

---

## Attack Scenario 3: Privilege Escalation via Capabilities

**Threat Category**: CWE-250 - Execution with Unnecessary Privileges

**Threat Level**: HIGH

**Attack Description**:
Container with CAP_SYS_ADMIN can escape via multiple vectors.

**Attack Flow**:
```
1. Container granted CAP_SYS_ADMIN
2. Attacker exploits one of:
   - Mount host filesystem
   - Modify cgroups
   - Load kernel modules
   - Access raw devices
3. Escapes to host system
```

**Mitigation**:
```python
# NEVER grant CAP_SYS_ADMIN

# Python: Verify capabilities are dropped
import os
import ctypes

def verify_no_caps():
    """Verify all capabilities are dropped."""
    # Read capabilities from /proc
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith('Cap'):
                name, value = line.split(':')
                value = int(value.strip(), 16)
                if name.strip() == 'CapEff' and value != 0:
                    raise SecurityError(
                        f"Capabilities not dropped: {value:x}"
                    )
```

---

## Attack Scenario 4: Kernel Exploit (CVE-2022-0185)

**Threat Category**: CWE-122 - Heap-based Buffer Overflow

**Threat Level**: HIGH

**Attack Description**:
Kernel heap overflow via fsconfig syscall allows privilege escalation.

**Attack Flow**:
```
1. Container calls fsconfig with malicious params
2. Triggers heap overflow in kernel
3. Gains CAP_SYS_ADMIN in init namespace
4. Full container escape
```

**Mitigation**:
```json
{
  "defaultAction": "SCMP_ACT_KILL",
  "syscalls": [
    {
      "names": ["fsconfig", "fsopen", "fsmount"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

Note: Docker's default seccomp profile blocks these syscalls.

---

## Attack Scenario 5: Resource Exhaustion DoS

**Threat Category**: CWE-400 - Uncontrolled Resource Consumption

**Threat Level**: MEDIUM

**Attack Description**:
Malicious container exhausts host resources, affecting other containers.

**Attack Flow**:
```
1. Attacker runs fork bomb or memory hog
2. Consumes all CPU/memory
3. Other containers starved
4. System becomes unresponsive
```

**Mitigation**:
```yaml
# Always set resource limits
resources:
  limits:
    cpu: "1"
    memory: "512Mi"
    ephemeral-storage: "1Gi"
  requests:
    cpu: "100m"
    memory: "128Mi"

# Also set pids limit in container runtime
spec:
  containers:
  - name: app
    # Docker: --pids-limit 100
```

**Cgroup Configuration**:
```python
class ResourceLimiter:
    """Enforce resource limits with cgroups."""

    def apply_limits(self, pid: int):
        cgroup = f'/sys/fs/cgroup/jarvis-{pid}'
        os.makedirs(cgroup, exist_ok=True)

        # Memory limit
        with open(f'{cgroup}/memory.max', 'w') as f:
            f.write('536870912')  # 512 MB

        # CPU limit (50% of one CPU)
        with open(f'{cgroup}/cpu.max', 'w') as f:
            f.write('50000 100000')

        # PID limit
        with open(f'{cgroup}/pids.max', 'w') as f:
            f.write('100')

        # Add process
        with open(f'{cgroup}/cgroup.procs', 'w') as f:
            f.write(str(pid))
```

---

## STRIDE Analysis

| Category | Threat | Mitigation | Priority |
|----------|--------|------------|----------|
| **Spoofing** | Container identity bypass | Network policies, pod identity | HIGH |
| **Tampering** | Host filesystem modification | Read-only FS, namespaces | CRITICAL |
| **Repudiation** | Untracked privileged operations | Audit logging, Falco | MEDIUM |
| **Information Disclosure** | Access to host secrets | Secret isolation, encryption | HIGH |
| **Denial of Service** | Resource exhaustion | Resource limits, quotas | MEDIUM |
| **Elevation of Privilege** | Container escape | Multi-layer defense | CRITICAL |

---

## Defense in Depth Checklist

### Layer 1: Runtime
- [ ] Container runtime updated (no CVEs)
- [ ] gVisor or Kata for high-risk workloads
- [ ] Seccomp RuntimeDefault applied

### Layer 2: Container
- [ ] Non-root user
- [ ] Read-only filesystem
- [ ] All capabilities dropped
- [ ] No privilege escalation

### Layer 3: Kernel
- [ ] Kernel updated
- [ ] AppArmor/SELinux enabled
- [ ] Dangerous syscalls blocked

### Layer 4: Network
- [ ] Network namespace isolated
- [ ] Network policies enforced
- [ ] No host network

### Layer 5: Monitoring
- [ ] Falco or similar for runtime detection
- [ ] Audit logging enabled
- [ ] Escape attempt alerts configured
