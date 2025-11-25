# Sandboxing Skill

---
name: sandboxing
version: 1.0.0
domain: security/isolation
risk_level: HIGH
languages: [python, c, rust, go]
frameworks: [seccomp, apparmor, selinux, bubblewrap]
requires_security_review: true
compliance: [SOC2, FedRAMP]
last_updated: 2025-01-15
---

> **MANDATORY READING PROTOCOL**: Before implementing sandboxing, read `references/advanced-patterns.md` for defense-in-depth strategies and `references/threat-model.md` for container escape scenarios.

## 1. Overview

### 1.1 Purpose and Scope

This skill provides process isolation and sandboxing for JARVIS components:

- **Linux**: seccomp-bpf, AppArmor/SELinux, namespaces, cgroups
- **Windows**: AppContainer, Job Objects, Restricted Tokens
- **macOS**: sandbox-exec, App Sandbox entitlements
- **Containers**: Docker/Podman security contexts, Kubernetes SecurityContext

### 1.2 Risk Assessment

**Risk Level**: HIGH

**Justification**:
- Sandbox escapes allow full system compromise
- Misconfigurations negate all isolation benefits
- Kernel vulnerabilities bypass userspace controls
- Plugin/extension execution requires strong isolation

**Attack Surface**:
- Syscall filtering gaps
- Namespace escape vectors
- Capability misconfigurations
- Resource exhaustion attacks

## 2. Core Responsibilities

### 2.1 Primary Functions

1. **Isolate untrusted code** execution from host system
2. **Restrict syscalls** to minimum required set
3. **Limit resources** (CPU, memory, network, filesystem)
4. **Enforce security policies** via MAC (AppArmor/SELinux)
5. **Contain failures** to prevent cascade effects

### 2.2 Core Principles

- **TDD First**: Write tests for sandbox restrictions before implementation
- **Performance Aware**: Cache permissions, lazy-load capabilities, minimize syscall overhead
- **Defense in Depth**: Layer multiple isolation mechanisms
- **Least Privilege**: Grant minimum permissions required
- **Fail Secure**: Default deny all access

### 2.3 Security Principles

- **NEVER** run untrusted code without syscall filtering
- **NEVER** grant CAP_SYS_ADMIN to sandboxed processes
- **ALWAYS** drop all capabilities not explicitly required
- **ALWAYS** use read-only root filesystem where possible
- **ALWAYS** apply defense-in-depth (multiple layers)

## 3. Technology Stack

| Platform | Primary | Secondary | MAC |
|----------|---------|-----------|-----|
| Linux | seccomp-bpf | namespaces | AppArmor/SELinux |
| Windows | AppContainer | Job Objects | WDAC |
| macOS | sandbox-exec | Entitlements | TCC |
| Containers | securityContext | RuntimeClass | Pod Security |

**Recommended Tools**: bubblewrap, firejail, nsjail, gVisor

## 4. Implementation Patterns

### 4.1 Seccomp-BPF Filter (python-seccomp)

```python
import seccomp
import os

def create_minimal_sandbox():
    """Create minimal seccomp sandbox for untrusted code."""
    filter = seccomp.SyscallFilter(defaction=seccomp.KILL)

    # Essential syscalls
    essential = [
        'read', 'write', 'close', 'fstat', 'lseek',
        'mmap', 'mprotect', 'munmap', 'brk',
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
        'exit', 'exit_group', 'futex', 'clock_gettime',
    ]

    for syscall in essential:
        filter.add_rule(seccomp.ALLOW, syscall)

    return filter

def run_sandboxed(func, *args, **kwargs):
    """Execute function in seccomp sandbox."""
    filter = create_minimal_sandbox()
    pid = os.fork()

    if pid == 0:
        filter.load()
        try:
            func(*args, **kwargs)
            os._exit(0)
        except Exception:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        return os.WEXITSTATUS(status) == 0
```

**📚 For custom BPF filters and advanced seccomp**:
- See `references/advanced-patterns.md#seccomp-bpf`

### 4.2 Bubblewrap Sandbox (Recommended)

```python
import subprocess
from typing import List

class BubblewrapSandbox:
    """High-level sandboxing using bubblewrap."""

    def __init__(self):
        self._args = ['bwrap']

    def with_minimal_filesystem(self) -> 'BubblewrapSandbox':
        self._args.extend([
            '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64',
            '--symlink', 'usr/bin', '/bin',
            '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp',
        ])
        return self

    def with_network_isolation(self) -> 'BubblewrapSandbox':
        self._args.append('--unshare-net')
        return self

    def drop_capabilities(self) -> 'BubblewrapSandbox':
        self._args.append('--cap-drop ALL')
        return self

    def run(self, command: List[str], timeout: int = 30):
        return subprocess.run(
            self._args + ['--'] + command,
            capture_output=True, timeout=timeout
        )

# Usage
def run_untrusted_script(script_path: str) -> str:
    sandbox = BubblewrapSandbox()
    sandbox.with_minimal_filesystem().with_network_isolation().drop_capabilities()
    result = sandbox.run(['python3', script_path], timeout=10)
    return result.stdout.decode()
```

**📚 For namespace isolation and advanced bubblewrap**:
- See `references/advanced-patterns.md#namespaces`

### 4.3 Kubernetes SecurityContext

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: jarvis-worker
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: worker
    image: jarvis-worker:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]

    resources:
      limits:
        cpu: "1"
        memory: "512Mi"

    volumeMounts:
    - name: tmp
      mountPath: /tmp

  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: 64Mi
```

## 5. Implementation Workflow (TDD)

### Step 1: Write Failing Test First

```python
import pytest
from sandbox import SandboxManager

class TestSandboxRestrictions:
    """Test sandbox isolation before implementation."""

    @pytest.fixture
    def sandbox(self):
        return SandboxManager()

    def test_network_blocked(self, sandbox):
        """WRITE FIRST: Network access must be blocked."""
        result = sandbox.run(['curl', '-s', 'http://example.com'])
        assert result.returncode != 0, "Network should be blocked"

    def test_filesystem_readonly(self, sandbox):
        """WRITE FIRST: Root filesystem must be read-only."""
        result = sandbox.run(['touch', '/test-file'])
        assert result.returncode != 0, "Root FS should be read-only"

    def test_capabilities_dropped(self, sandbox):
        """WRITE FIRST: All capabilities must be dropped."""
        result = sandbox.run(['cat', '/proc/self/status'])
        assert 'CapEff:\t0000000000000000' in result.stdout

    def test_syscall_blocked(self, sandbox):
        """WRITE FIRST: Dangerous syscalls must be blocked."""
        # ptrace should be blocked by seccomp
        result = sandbox.run(['strace', 'ls'])
        assert result.returncode != 0, "ptrace should be blocked"

    def test_escape_attempt_fails(self, sandbox):
        """WRITE FIRST: Container escape must fail."""
        result = sandbox.run(['ls', '/proc/1/root'])
        assert result.returncode != 0, "Namespace escape blocked"
```

### Step 2: Implement Minimum to Pass

```python
class SandboxManager:
    def __init__(self):
        self._bwrap_args = ['bwrap', '--unshare-net', '--ro-bind', '/', '/',
                           '--cap-drop', 'ALL', '--seccomp', '3']

    def run(self, command, timeout=30):
        import subprocess
        return subprocess.run(self._bwrap_args + ['--'] + command,
                              capture_output=True, text=True, timeout=timeout)
```

### Step 3: Refactor with Defense-in-Depth

```python
class SandboxManager:
    def __init__(self, profile: str = 'strict'):
        self._bwrap_args = ['bwrap', '--unshare-all']
        if profile == 'network': self._bwrap_args.append('--share-net')
        self._bwrap_args.extend(['--ro-bind', '/usr', '/usr', '--tmpfs', '/tmp',
                                 '--cap-drop', 'ALL', '--seccomp', '3'])
```

### Step 4: Run Full Verification

```bash
# Run all sandbox tests
pytest tests/sandbox/ -v --tb=short

# Test specific isolation features
pytest tests/sandbox/test_network.py -v
pytest tests/sandbox/test_capabilities.py -v
pytest tests/sandbox/test_escapes.py -v

# Security audit
python -m security_audit --sandbox
```

## 6. Performance Patterns

### 6.1 Permission Caching

```python
# Bad: Load permissions from disk on every operation
def run_sandboxed(command):
    permissions = load_permissions_from_disk()  # Slow I/O every time
    return execute(command)

# Good: Cache with TTL
class PermissionCache:
    def __init__(self, ttl=300):
        self._cache, self._ttl = {}, ttl

    def get(self, profile):
        if profile in self._cache and time() - self._cache[profile][1] < self._ttl:
            return self._cache[profile][0]
        perms = load_from_disk(profile)
        self._cache[profile] = (perms, time())
        return perms
```

### 6.2 Lazy Capability Loading

```python
# Bad: Load all security modules at startup
class Sandbox:
    def __init__(self):
        self.seccomp = load_seccomp_filters()      # Expensive
        self.apparmor = load_apparmor_profiles()   # Expensive

# Good: Lazy load only when needed
class Sandbox:
    _seccomp = None
    @property
    def seccomp(self):
        if self._seccomp is None: self._seccomp = load_seccomp_filters()
        return self._seccomp
```

### 6.3 Efficient IPC

```python
# Bad: Serialize full state for each call
def send_to_sandbox(data):
    return sandbox.communicate(serialize_full_state() + data)

# Good: Use shared memory for large data
class EfficientIPC:
    def __init__(self, size=1024*1024):
        self._shm = mmap.mmap(-1, size)
    def send(self, data): self._shm.seek(0); self._shm.write(data)
    def recv(self, size): self._shm.seek(0); return self._shm.read(size)
```

### 6.4 Resource Pooling

```python
# Bad: Create new sandbox for each task
for task in tasks:
    sandbox = create_sandbox()  # Expensive
    sandbox.run(task); sandbox.destroy()

# Good: Pool and reuse
class SandboxPool:
    def __init__(self, size=4):
        self._pool = Queue(size)
        for _ in range(size): self._pool.put(create_sandbox())
    def acquire(self): return self._pool.get()
    def release(self, sb): sb.reset(); self._pool.put(sb)
```

### 6.5 Minimal Privilege Sets

```python
# Bad: Request all capabilities upfront
CAPS = ['CAP_NET_ADMIN', 'CAP_SYS_ADMIN', 'CAP_DAC_OVERRIDE', ...]

# Good: Minimal sets per operation
CAPABILITY_SETS = {
    'network_bind': ['CAP_NET_BIND_SERVICE'],
    'file_read': [],
    'file_write': ['CAP_DAC_OVERRIDE'],
}
def get_caps(op): return CAPABILITY_SETS.get(op, [])
```

## 7. Security Standards

### 7.1 Known Vulnerabilities

| CVE | Severity | Component | Mitigation |
|-----|----------|-----------|------------|
| CVE-2024-21626 | Critical | runC | Container escape - runC 1.1.12+ |
| CVE-2022-0185 | High | Linux kernel | Heap overflow - Kernel update |
| CVE-2022-0492 | High | cgroups | Escape - Drop CAP_SYS_ADMIN |
| CVE-2022-0847 | High | Linux kernel | Dirty Pipe - Kernel 5.16.11+ |
| CVE-2023-2431 | Low | Kubernetes | Seccomp bypass - K8s patch |

### 7.2 OWASP Mapping

| OWASP 2025 | Risk | Implementation |
|------------|------|----------------|
| A01: Broken Access Control | Critical | Namespace isolation, MAC |
| A04: Insecure Design | High | Defense in depth |
| A05: Security Misconfiguration | Critical | Secure defaults |

### 7.3 Defense-in-Depth Layers

1. **Seccomp**: Syscall filtering
2. **Namespaces**: Resource isolation
3. **Capabilities**: Privilege reduction
4. **MAC**: Mandatory access control (AppArmor/SELinux)
5. **Cgroups**: Resource limits

**📚 For detailed OWASP coverage**:
- See `references/security-examples.md`

## 8. Testing Requirements

```python
class TestSandboxSecurity:
    def test_network_isolated(self, sandbox):
        assert sandbox.run(['curl', '-s', 'https://example.com']).returncode != 0
    def test_capabilities_dropped(self, sandbox):
        assert 'CapEff:\t0' in sandbox.run(['cat', '/proc/self/status']).stdout
    def test_escape_attempts_blocked(self, sandbox):
        assert sandbox.run(['ls', '/proc/1/root']).returncode != 0
```

**📚 For complete test suite**: See `references/security-examples.md#testing`

## 9. Common Mistakes

### Critical Anti-Patterns

```yaml
# ❌ NEVER: runAsUser: 0 (root)          ✅ ALWAYS: runAsNonRoot: true, runAsUser: 1000
# ❌ NEVER: add: [SYS_ADMIN]              ✅ ALWAYS: drop: [ALL], add only needed
# ❌ NEVER: privileged: true              ✅ ALWAYS: privileged: false
# ❌ NEVER: No seccomp profile            ✅ ALWAYS: seccompProfile: RuntimeDefault
```

```yaml
# Example secure configuration
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  privileged: false
  allowPrivilegeEscalation: false
  capabilities: {drop: [ALL]}
  seccompProfile: {type: RuntimeDefault}
```

**📚 For complete anti-patterns**: See `references/advanced-patterns.md#anti-patterns`

## 10. Pre-Implementation Checklist

### Phase 1: Before Writing Code
- [ ] Identify isolation requirements from PRD
- [ ] Review threat model for attack vectors
- [ ] Define minimal capability set needed
- [ ] Choose appropriate isolation layers
- [ ] Write failing tests for all restrictions

### Phase 2: During Implementation
- [ ] Implement defense-in-depth layers
- [ ] Drop all capabilities, add back only required
- [ ] Apply seccomp filters for syscall blocking
- [ ] Configure namespace isolation
- [ ] Set up resource limits (cgroups)
- [ ] Use read-only root filesystem
- [ ] Run tests after each layer added

### Phase 3: Before Committing
- [ ] All sandbox restriction tests pass
- [ ] Escape attempt tests verified
- [ ] No containers running as root
- [ ] allowPrivilegeEscalation: false
- [ ] seccompProfile: RuntimeDefault or stricter
- [ ] Resource limits defined
- [ ] Security audit completed
- [ ] Performance benchmarks acceptable

## 11. Summary

### Key Objectives
1. **Multi-layer defense**: Combine seccomp, namespaces, capabilities, MAC
2. **Minimal privileges**: Drop all capabilities, run as non-root
3. **Syscall filtering**: Block dangerous syscalls by default
4. **Container hardening**: Read-only filesystem, no privilege escalation

### Security Reminders
- A single misconfiguration can negate all sandboxing
- Defense-in-depth is essential - no single layer is sufficient
- Test escape attempts as part of security validation

### References
- `references/advanced-patterns.md` - Custom seccomp, gVisor, namespaces
- `references/security-examples.md` - Platform-specific implementations
- `references/threat-model.md` - Container escape scenarios

**Sandboxing is your last line of defense. When everything else fails, the sandbox must hold.**
