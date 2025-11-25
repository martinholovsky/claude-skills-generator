# Sandboxing Security Examples

## Complete Bubblewrap Sandbox Implementation

```python
"""
Production-ready sandboxing using bubblewrap.
"""

import subprocess
import tempfile
import os
import json
from pathlib import Path
from typing import List, Optional, Dict

class JarvisSandbox:
    """
    Comprehensive sandbox for executing untrusted code.

    Combines:
    - Namespace isolation
    - Seccomp filtering
    - Filesystem restrictions
    - Resource limits
    """

    def __init__(self):
        self._verify_bwrap()

    def _verify_bwrap(self):
        """Verify bubblewrap is installed."""
        result = subprocess.run(
            ['bwrap', '--version'],
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError("bubblewrap not installed")

    def execute_python(
        self,
        code: str,
        timeout: int = 30,
        memory_mb: int = 256,
        allow_network: bool = False
    ) -> Dict:
        """
        Execute Python code in sandbox.

        Args:
            code: Python code to execute
            timeout: Maximum execution time
            memory_mb: Memory limit in MB
            allow_network: Allow network access

        Returns:
            Dict with stdout, stderr, exit_code
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write code to file
            script_path = Path(tmpdir) / 'script.py'
            script_path.write_text(code)

            # Build bwrap command
            cmd = self._build_bwrap_command(
                script_path=str(script_path),
                tmpdir=tmpdir,
                allow_network=allow_network
            )

            # Execute with timeout
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout
                )

                return {
                    'stdout': result.stdout.decode('utf-8', errors='replace'),
                    'stderr': result.stderr.decode('utf-8', errors='replace'),
                    'exit_code': result.returncode
                }

            except subprocess.TimeoutExpired:
                return {
                    'stdout': '',
                    'stderr': 'Execution timed out',
                    'exit_code': -1
                }

    def _build_bwrap_command(
        self,
        script_path: str,
        tmpdir: str,
        allow_network: bool
    ) -> List[str]:
        """Build bubblewrap command."""
        cmd = [
            'bwrap',

            # User namespace (rootless)
            '--unshare-user',

            # Mount namespace
            '--unshare-mount',

            # PID namespace (isolated process tree)
            '--unshare-pid',

            # IPC namespace
            '--unshare-ipc',

            # UTS namespace (hostname)
            '--unshare-uts',
            '--hostname', 'sandbox',

            # Cgroup namespace
            '--unshare-cgroup',

            # Die when parent dies
            '--die-with-parent',

            # Minimal filesystem
            '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64',
            '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/sbin', '/sbin',

            # Proc filesystem (restricted)
            '--proc', '/proc',

            # Dev filesystem (minimal)
            '--dev', '/dev',

            # Writable /tmp
            '--tmpfs', '/tmp',

            # Bind script
            '--ro-bind', script_path, '/app/script.py',

            # Set working directory
            '--chdir', '/app',

            # Clear environment
            '--clearenv',
            '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'HOME', '/tmp',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
        ]

        # Network isolation
        if not allow_network:
            cmd.append('--unshare-net')

        # Command to execute
        cmd.extend([
            '--',
            '/usr/bin/python3',
            '-u',  # Unbuffered output
            '/app/script.py'
        ])

        return cmd


class SeccompProfileManager:
    """Manage seccomp profiles for different workloads."""

    PROFILES_DIR = '/etc/jarvis/seccomp'

    @classmethod
    def get_profile_path(cls, name: str) -> str:
        """Get path to named profile."""
        return f'{cls.PROFILES_DIR}/{name}.json'

    @classmethod
    def create_python_compute_profile(cls):
        """Create profile for Python computation."""
        profile = {
            'defaultAction': 'SCMP_ACT_KILL',
            'architectures': ['SCMP_ARCH_X86_64'],
            'syscalls': [
                # File I/O
                {'names': ['read', 'write', 'close', 'fstat', 'lseek',
                           'pread64', 'pwrite64', 'access', 'stat'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Memory management
                {'names': ['mmap', 'mprotect', 'munmap', 'brk', 'mremap'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Signals
                {'names': ['rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
                           'sigaltstack'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Process info
                {'names': ['getpid', 'gettid', 'getuid', 'getgid',
                           'geteuid', 'getegid', 'getcwd'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Threading
                {'names': ['futex', 'set_tid_address', 'set_robust_list',
                           'clone'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Time
                {'names': ['clock_gettime', 'clock_getres', 'gettimeofday',
                           'nanosleep'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Exit
                {'names': ['exit', 'exit_group'],
                 'action': 'SCMP_ACT_ALLOW'},

                # Misc
                {'names': ['arch_prctl', 'uname', 'getrandom'],
                 'action': 'SCMP_ACT_ALLOW'},
            ]
        }

        Path(cls.PROFILES_DIR).mkdir(parents=True, exist_ok=True)
        path = cls.get_profile_path('python-compute')
        with open(path, 'w') as f:
            json.dump(profile, f, indent=2)

        return path
```

## Kubernetes Pod Security

```yaml
# Complete secure pod specification
apiVersion: v1
kind: Pod
metadata:
  name: jarvis-secure-worker
  labels:
    app: jarvis
    security: hardened
  annotations:
    container.apparmor.security.beta.kubernetes.io/worker: runtime/default
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534  # nobody
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups: []

  # Prevent privilege escalation at pod level
  hostNetwork: false
  hostPID: false
  hostIPC: false

  # Service account
  serviceAccountName: jarvis-worker
  automountServiceAccountToken: false

  containers:
  - name: worker
    image: jarvis/worker:v1.0.0@sha256:abc123...
    imagePullPolicy: Always

    # Container security context
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      privileged: false
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault

    # Resource limits (prevent DoS)
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
        ephemeral-storage: "100Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"

    # Volume mounts
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache
    - name: config
      mountPath: /etc/jarvis
      readOnly: true

    # Health checks
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 10

    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5

  volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: 64Mi
  - name: cache
    emptyDir:
      sizeLimit: 100Mi
  - name: config
    configMap:
      name: jarvis-worker-config

---
# Network policy for pod
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: jarvis-worker-netpol
spec:
  podSelector:
    matchLabels:
      app: jarvis
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: jarvis-api
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: jarvis-db
    ports:
    - protocol: TCP
      port: 5432

---
# Pod Security Standard
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: jarvis-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'MustRunAs'
    ranges:
    - min: 1
      max: 65535
  readOnlyRootFilesystem: true
```

## Docker Secure Container

```python
"""
Secure Docker container execution.
"""

import docker
import json
from typing import Dict, Optional

class SecureDockerRunner:
    """Run containers with security hardening."""

    def __init__(self):
        self._client = docker.from_env()

    def run_secure(
        self,
        image: str,
        command: list,
        memory_limit: str = '256m',
        cpu_limit: float = 0.5,
        network_mode: str = 'none',
        read_only: bool = True,
        seccomp_profile: Optional[str] = None
    ) -> Dict:
        """
        Run container with full security hardening.

        Args:
            image: Container image
            command: Command to run
            memory_limit: Memory limit (e.g., '256m')
            cpu_limit: CPU limit (fraction of 1 CPU)
            network_mode: Network mode (none, bridge, host)
            read_only: Read-only root filesystem
            seccomp_profile: Path to seccomp profile

        Returns:
            Container output
        """
        security_opts = [
            'no-new-privileges:true',
        ]

        if seccomp_profile:
            with open(seccomp_profile) as f:
                profile = json.load(f)
            security_opts.append(f'seccomp={json.dumps(profile)}')

        container = self._client.containers.run(
            image,
            command,
            detach=True,
            remove=True,

            # Security
            user='65534:65534',  # nobody
            read_only=read_only,
            security_opt=security_opts,
            cap_drop=['ALL'],
            privileged=False,

            # Resource limits
            mem_limit=memory_limit,
            memswap_limit=memory_limit,  # No swap
            cpu_period=100000,
            cpu_quota=int(cpu_limit * 100000),
            pids_limit=100,

            # Network
            network_mode=network_mode,

            # Filesystem
            tmpfs={'/tmp': 'rw,noexec,nosuid,size=64m'},
        )

        # Wait for completion
        result = container.wait()

        return {
            'exit_code': result['StatusCode'],
            'logs': container.logs().decode('utf-8')
        }


def secure_container_example():
    """Example of running secure container."""
    runner = SecureDockerRunner()

    result = runner.run_secure(
        image='python:3.11-slim',
        command=['python', '-c', 'print("Hello from sandbox")'],
        memory_limit='128m',
        cpu_limit=0.25,
        network_mode='none',
        read_only=True
    )

    print(f"Exit code: {result['exit_code']}")
    print(f"Output: {result['logs']}")
```

## macOS Sandbox Profile

```scheme
;; JARVIS worker sandbox profile for macOS
;; Apply with: sandbox-exec -f jarvis-worker.sb /path/to/worker

(version 1)

; Default: deny everything
(deny default)

; Allow reading standard libraries
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System/Library/Frameworks")
    (subpath "/Library/Frameworks"))

; Allow reading application
(allow file-read*
    (subpath "/Applications/JARVIS.app"))

; Allow temp directory
(allow file-read* file-write*
    (subpath (param "TMPDIR"))
    (subpath "/private/tmp"))

; Allow basic system functionality
(allow process-exec)
(allow sysctl-read)
(allow mach-lookup
    (global-name "com.apple.system.logger"))

; Deny network access
(deny network*)

; Deny IPC
(deny ipc-posix*)
(deny ipc-sysv*)

; Allow reading user defaults
(allow user-preference-read)

; Logging
(allow file-write*
    (regex #"^/private/var/log/"))
```
