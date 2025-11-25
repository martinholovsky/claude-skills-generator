# Advanced Sandboxing Patterns

## Custom Seccomp Profiles

### Creating Allowlist Profile

```python
import seccomp
import json

class SeccompProfileBuilder:
    """Build custom seccomp profiles for specific workloads."""

    def __init__(self, name: str):
        self.name = name
        self.default_action = seccomp.KILL
        self.syscalls = []

    def allow(self, syscall: str, args: list = None) -> 'SeccompProfileBuilder':
        """Allow syscall with optional argument filtering."""
        self.syscalls.append({
            'names': [syscall],
            'action': 'SCMP_ACT_ALLOW',
            'args': args or []
        })
        return self

    def errno(self, syscall: str, errno: int) -> 'SeccompProfileBuilder':
        """Return error instead of killing."""
        self.syscalls.append({
            'names': [syscall],
            'action': 'SCMP_ACT_ERRNO',
            'errnoRet': errno
        })
        return self

    def to_oci_profile(self) -> dict:
        """Export as OCI seccomp profile (Docker/containerd)."""
        return {
            'defaultAction': 'SCMP_ACT_KILL',
            'architectures': ['SCMP_ARCH_X86_64', 'SCMP_ARCH_AARCH64'],
            'syscalls': self.syscalls
        }

    def save(self, path: str):
        """Save profile to file."""
        with open(path, 'w') as f:
            json.dump(self.to_oci_profile(), f, indent=2)


# Profile for Python computation workload
def create_python_compute_profile():
    """Seccomp profile for pure Python computation."""
    return SeccompProfileBuilder('python-compute') \
        .allow('read') \
        .allow('write') \
        .allow('close') \
        .allow('fstat') \
        .allow('lseek') \
        .allow('mmap') \
        .allow('mprotect') \
        .allow('munmap') \
        .allow('brk') \
        .allow('rt_sigaction') \
        .allow('rt_sigprocmask') \
        .allow('rt_sigreturn') \
        .allow('ioctl') \
        .allow('pread64') \
        .allow('pwrite64') \
        .allow('access') \
        .allow('getcwd') \
        .allow('getpid') \
        .allow('getuid') \
        .allow('getgid') \
        .allow('geteuid') \
        .allow('getegid') \
        .allow('arch_prctl') \
        .allow('futex') \
        .allow('set_tid_address') \
        .allow('set_robust_list') \
        .allow('clock_gettime') \
        .allow('clock_getres') \
        .allow('exit_group') \
        .allow('exit') \
        .errno('clone', 1)  # EPERM - block process creation \
        .errno('fork', 1) \
        .errno('execve', 1)  # Block exec \
        .errno('socket', 1)  # Block networking


# Profile for network service
def create_network_service_profile():
    """Seccomp profile for network service."""
    builder = create_python_compute_profile()

    # Add network syscalls
    return builder \
        .allow('socket') \
        .allow('bind') \
        .allow('listen') \
        .allow('accept') \
        .allow('accept4') \
        .allow('connect') \
        .allow('sendto') \
        .allow('recvfrom') \
        .allow('setsockopt') \
        .allow('getsockopt') \
        .allow('getpeername') \
        .allow('getsockname') \
        .allow('poll') \
        .allow('epoll_create1') \
        .allow('epoll_ctl') \
        .allow('epoll_wait')
```

## gVisor Integration

### Using gVisor for Strong Isolation

```python
"""
gVisor provides kernel-level isolation by intercepting syscalls.

Much stronger than seccomp alone - implements entire syscall surface.
"""

import subprocess
from pathlib import Path

class GVisorSandbox:
    """
    Sandbox using gVisor runsc runtime.

    gVisor interposes between application and host kernel,
    providing additional isolation layer.
    """

    def __init__(self, runtime: str = 'runsc'):
        self._runtime = runtime
        self._verify_runtime()

    def _verify_runtime(self):
        """Verify gVisor runtime is available."""
        result = subprocess.run(
            [self._runtime, '--version'],
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"gVisor runtime '{self._runtime}' not found. "
                "Install from https://gvisor.dev"
            )

    def run_container(
        self,
        image: str,
        command: list,
        network: str = 'none',
        memory_limit: str = '256m'
    ) -> subprocess.CompletedProcess:
        """
        Run container with gVisor runtime.

        Args:
            image: Container image
            command: Command to run
            network: Network mode (none, host, bridge)
            memory_limit: Memory limit
        """
        cmd = [
            'docker', 'run',
            '--runtime', self._runtime,
            '--rm',
            '--network', network,
            '--memory', memory_limit,
            '--read-only',
            '--security-opt', 'no-new-privileges',
            image
        ] + command

        return subprocess.run(cmd, capture_output=True, timeout=30)


# Kubernetes with gVisor
GVISOR_RUNTIME_CLASS = """
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
"""

GVISOR_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: sandboxed-pod
spec:
  runtimeClassName: gvisor
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
"""
```

## Resource Control with Cgroups v2

```python
import os
from pathlib import Path

class CgroupV2Controller:
    """
    Control resources using cgroups v2.

    Limits CPU, memory, I/O for sandboxed processes.
    """

    def __init__(self, name: str):
        self._name = name
        self._cgroup_path = Path(f'/sys/fs/cgroup/{name}')

    def create(self):
        """Create cgroup."""
        self._cgroup_path.mkdir(parents=True, exist_ok=True)

    def set_memory_limit(self, bytes_limit: int):
        """Set memory limit in bytes."""
        mem_max = self._cgroup_path / 'memory.max'
        mem_max.write_text(str(bytes_limit))

    def set_cpu_limit(self, quota_us: int, period_us: int = 100000):
        """
        Set CPU limit.

        Args:
            quota_us: CPU time quota in microseconds
            period_us: Period in microseconds (default 100ms)
        """
        cpu_max = self._cgroup_path / 'cpu.max'
        cpu_max.write_text(f'{quota_us} {period_us}')

    def set_io_limit(self, device: str, rbps: int = None, wbps: int = None):
        """Set I/O bandwidth limits."""
        io_max = self._cgroup_path / 'io.max'

        limits = []
        if rbps:
            limits.append(f'rbps={rbps}')
        if wbps:
            limits.append(f'wbps={wbps}')

        if limits:
            io_max.write_text(f'{device} {" ".join(limits)}')

    def add_process(self, pid: int):
        """Add process to cgroup."""
        procs = self._cgroup_path / 'cgroup.procs'
        procs.write_text(str(pid))

    def cleanup(self):
        """Remove cgroup."""
        if self._cgroup_path.exists():
            self._cgroup_path.rmdir()


def sandbox_with_limits(func, memory_mb: int = 256, cpu_percent: int = 50):
    """Execute function with resource limits."""
    import os

    cgroup = CgroupV2Controller(f'jarvis-sandbox-{os.getpid()}')
    cgroup.create()

    try:
        # Set limits
        cgroup.set_memory_limit(memory_mb * 1024 * 1024)
        cgroup.set_cpu_limit(cpu_percent * 1000)  # percentage of 100ms

        # Fork and add to cgroup
        pid = os.fork()

        if pid == 0:
            # Child: add self to cgroup
            cgroup.add_process(os.getpid())

            try:
                result = func()
                os._exit(0)
            except Exception:
                os._exit(1)
        else:
            # Parent: wait
            _, status = os.waitpid(pid, 0)
            return os.WEXITSTATUS(status) == 0

    finally:
        cgroup.cleanup()
```

## AppArmor Profile Generation

```python
class AppArmorProfile:
    """Generate AppArmor profiles for sandboxed applications."""

    def __init__(self, name: str):
        self.name = name
        self._rules = []

    def deny_network(self) -> 'AppArmorProfile':
        """Deny all network access."""
        self._rules.append('deny network,')
        return self

    def allow_network(self, protocol: str = None) -> 'AppArmorProfile':
        """Allow network access."""
        if protocol:
            self._rules.append(f'network {protocol},')
        else:
            self._rules.append('network,')
        return self

    def allow_read(self, path: str) -> 'AppArmorProfile':
        """Allow read access to path."""
        self._rules.append(f'{path} r,')
        return self

    def allow_write(self, path: str) -> 'AppArmorProfile':
        """Allow write access to path."""
        self._rules.append(f'{path} w,')
        return self

    def allow_exec(self, path: str) -> 'AppArmorProfile':
        """Allow execution of path."""
        self._rules.append(f'{path} ix,')
        return self

    def deny_caps(self) -> 'AppArmorProfile':
        """Deny all capabilities."""
        self._rules.append('deny capability,')
        return self

    def generate(self) -> str:
        """Generate AppArmor profile."""
        return f"""
#include <tunables/global>

profile {self.name} flags=(attach_disconnected,mediate_deleted) {{
  #include <abstractions/base>

  # Custom rules
  {chr(10).join('  ' + r for r in self._rules)}

  # Deny everything else
  deny /** wl,
}}
"""


def create_jarvis_worker_profile():
    """Create AppArmor profile for JARVIS worker."""
    return AppArmorProfile('jarvis-worker') \
        .deny_network() \
        .deny_caps() \
        .allow_read('/usr/lib/**') \
        .allow_read('/lib/**') \
        .allow_read('/etc/ld.so.cache') \
        .allow_read('/etc/passwd') \
        .allow_exec('/usr/bin/python3') \
        .allow_write('/tmp/**') \
        .generate()
```

## Rootless Container Patterns

```python
"""
Rootless container patterns for maximum security.

No root privileges required on host.
"""

import subprocess
import os

class RootlessContainer:
    """Run containers without root privileges."""

    def __init__(self, runtime: str = 'podman'):
        self._runtime = runtime

    def run(
        self,
        image: str,
        command: list,
        user_ns: bool = True,
        userns_keep_id: bool = True
    ) -> subprocess.CompletedProcess:
        """
        Run rootless container.

        Args:
            image: Container image
            command: Command to run
            user_ns: Use user namespace
            userns_keep_id: Keep same UID inside container
        """
        cmd = [self._runtime, 'run', '--rm']

        if user_ns:
            cmd.append('--userns=auto')
        if userns_keep_id:
            cmd.append('--userns=keep-id')

        cmd.extend([
            '--security-opt', 'no-new-privileges',
            '--cap-drop=ALL',
            '--read-only',
            image
        ] + command)

        return subprocess.run(cmd, capture_output=True)


def setup_rootless_environment():
    """Setup environment for rootless containers."""
    # Check subuid/subgid mapping
    uid = os.getuid()

    with open('/etc/subuid') as f:
        if str(uid) not in f.read():
            raise RuntimeError(
                f"User {uid} not in /etc/subuid. "
                "Add: username:{uid*65536}:65536"
            )

    with open('/etc/subgid') as f:
        if str(uid) not in f.read():
            raise RuntimeError(
                f"User {uid} not in /etc/subgid. "
                "Add: username:{uid*65536}:65536"
            )

    # Verify user namespace support
    try:
        result = subprocess.run(
            ['unshare', '--user', 'true'],
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError("User namespaces not available")
    except FileNotFoundError:
        raise RuntimeError("unshare command not found")
```

## Windows AppContainer

```python
"""
Windows AppContainer sandboxing.

Provides capability-based isolation on Windows.
"""

import subprocess
from typing import List, Optional

class WindowsAppContainer:
    """
    Windows AppContainer sandbox.

    Uses low-integrity level and capability restrictions.
    """

    def __init__(self, name: str):
        self._name = name
        self._capabilities = []

    def add_capability(self, capability: str) -> 'WindowsAppContainer':
        """Add capability to container."""
        self._capabilities.append(capability)
        return self

    def run(
        self,
        executable: str,
        args: List[str] = None,
        working_dir: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """
        Run process in AppContainer.

        Requires Windows 10 1607+.
        """
        import ctypes
        from ctypes import wintypes

        # Would use Windows APIs:
        # - CreateAppContainerProfile
        # - DeriveAppContainerSidFromAppContainerName
        # - CreateProcess with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES

        # Simplified: use PowerShell approach
        ps_script = f"""
        $AppContainer = New-Object -ComObject "AppContainerSecurity"
        $AppContainer.CreateAppContainer("{self._name}")
        """

        # Full implementation would use pywin32 or ctypes

        raise NotImplementedError(
            "Full AppContainer requires Windows APIs. "
            "Use Windows Sandbox or Hyper-V containers instead."
        )
```
