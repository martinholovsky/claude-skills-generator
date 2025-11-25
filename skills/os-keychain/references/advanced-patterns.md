# Advanced OS Keychain Patterns

## Cross-Platform Credential Factory

```python
import platform
from abc import ABC, abstractmethod
from typing import Optional

class CredentialBackend(ABC):
    """Abstract credential storage backend."""

    @abstractmethod
    def store(self, service: str, key: str, secret: str) -> None:
        pass

    @abstractmethod
    def retrieve(self, service: str, key: str) -> str:
        pass

    @abstractmethod
    def delete(self, service: str, key: str) -> None:
        pass


class CredentialStoreFactory:
    """Factory for platform-appropriate credential storage."""

    @staticmethod
    def create(service: str) -> 'UnifiedCredentialStore':
        system = platform.system()

        if system == 'Darwin':
            backend = MacOSKeychainBackend()
        elif system == 'Windows':
            backend = WindowsCredentialBackend()
        elif system == 'Linux':
            backend = LinuxSecretServiceBackend()
        else:
            raise RuntimeError(f"Unsupported platform: {system}")

        return UnifiedCredentialStore(service, backend)


class UnifiedCredentialStore:
    """Unified credential interface across platforms."""

    def __init__(self, service: str, backend: CredentialBackend):
        self._service = service
        self._backend = backend

    def store(self, key: str, secret: str) -> None:
        self._backend.store(self._service, key, secret)

    def retrieve(self, key: str) -> str:
        return self._backend.retrieve(self._service, key)

    def delete(self, key: str) -> None:
        self._backend.delete(self._service, key)
```

## Credential Migration

```python
class CredentialMigrator:
    """Migrate credentials between versions or platforms."""

    def __init__(self, source: CredentialBackend, target: CredentialBackend):
        self._source = source
        self._target = target
        self._migrated = []

    def migrate_credential(self, service: str, key: str) -> bool:
        """Migrate single credential."""
        try:
            secret = self._source.retrieve(service, key)
            self._target.store(service, key, secret)

            # Verify migration
            if self._target.retrieve(service, key) == secret:
                self._migrated.append((service, key))
                return True

            return False
        except Exception as e:
            logger.error(f"Migration failed for {service}/{key}: {e}")
            return False

    def cleanup_source(self) -> None:
        """Remove successfully migrated credentials from source."""
        for service, key in self._migrated:
            try:
                self._source.delete(service, key)
            except Exception:
                pass  # Best effort cleanup

    def rollback(self) -> None:
        """Remove migrated credentials from target on failure."""
        for service, key in self._migrated:
            try:
                self._target.delete(service, key)
            except Exception:
                pass
```

## Credential Versioning

```python
from datetime import datetime, timezone
import json

class VersionedCredentialStore:
    """
    Credential storage with version history.

    Supports:
    - Credential rotation with version tracking
    - Rollback to previous versions
    - Audit trail of changes
    """

    def __init__(self, store: SecureCredentialStore):
        self._store = store
        self._metadata_key = "__credential_metadata__"

    def _get_metadata(self) -> dict:
        """Get credential version metadata."""
        try:
            data = self._store.retrieve(self._metadata_key)
            return json.loads(data)
        except KeyError:
            return {"credentials": {}}

    def _save_metadata(self, metadata: dict) -> None:
        self._store.store(self._metadata_key, json.dumps(metadata))

    def store(self, key: str, secret: str, reason: str = "initial") -> int:
        """
        Store credential with version tracking.

        Returns:
            Version number of stored credential
        """
        metadata = self._get_metadata()

        if key not in metadata["credentials"]:
            metadata["credentials"][key] = {"versions": [], "current": 0}

        cred_meta = metadata["credentials"][key]
        version = len(cred_meta["versions"]) + 1

        # Store with version suffix
        versioned_key = f"{key}_v{version}"
        self._store.store(versioned_key, secret)

        # Update metadata
        cred_meta["versions"].append({
            "version": version,
            "key": versioned_key,
            "created": datetime.now(timezone.utc).isoformat(),
            "reason": reason
        })
        cred_meta["current"] = version

        self._save_metadata(metadata)
        return version

    def retrieve(self, key: str, version: int = None) -> str:
        """
        Retrieve credential, optionally specific version.

        Args:
            key: Credential key
            version: Specific version (None for current)
        """
        metadata = self._get_metadata()

        if key not in metadata["credentials"]:
            raise KeyError(f"Credential not found: {key}")

        cred_meta = metadata["credentials"][key]

        if version is None:
            version = cred_meta["current"]

        for v in cred_meta["versions"]:
            if v["version"] == version:
                return self._store.retrieve(v["key"])

        raise KeyError(f"Version {version} not found for {key}")

    def rotate(self, key: str, new_secret: str, reason: str = "rotation") -> int:
        """Rotate credential to new value."""
        return self.store(key, new_secret, reason)

    def rollback(self, key: str, version: int) -> None:
        """Set active version to previous value."""
        metadata = self._get_metadata()

        if key not in metadata["credentials"]:
            raise KeyError(f"Credential not found: {key}")

        cred_meta = metadata["credentials"][key]
        valid_versions = [v["version"] for v in cred_meta["versions"]]

        if version not in valid_versions:
            raise ValueError(f"Invalid version: {version}")

        cred_meta["current"] = version
        self._save_metadata(metadata)
```

## Secure Enclave Integration (macOS)

```swift
import Security
import LocalAuthentication

/// Credential storage with Secure Enclave protection.
class SecureEnclaveCredentialStore {

    private let service: String
    private let accessGroup: String?

    init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    /// Store credential requiring biometric authentication.
    func storeWithBiometric(key: String, secret: Data) throws {
        // Create access control requiring biometric
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            nil
        )!

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: secret,
            kSecAttrAccessControl as String: access
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        // Delete existing
        SecItemDelete(query as CFDictionary)

        // Add new
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
    }

    /// Retrieve credential with biometric prompt.
    func retrieveWithBiometric(key: String, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data else {
            throw KeychainError.unhandledError(status: status)
        }

        return data
    }
}
```

## Credential Synchronization

```python
import hashlib
from dataclasses import dataclass
from typing import List

@dataclass
class CredentialSyncState:
    """Sync state for credential across nodes."""
    key: str
    version: int
    hash: str
    modified: str

class CredentialSynchronizer:
    """
    Synchronize credentials across multiple nodes.

    SECURITY WARNING: Only for non-sensitive metadata.
    Actual secrets should use secure replication (e.g., Vault).
    """

    def __init__(self, store: SecureCredentialStore, node_id: str):
        self._store = store
        self._node_id = node_id

    def get_local_state(self, keys: List[str]) -> List[CredentialSyncState]:
        """Get sync state for local credentials."""
        states = []
        for key in keys:
            try:
                secret = self._store.retrieve(key)
                # Hash secret for comparison (never transmit actual value)
                secret_hash = hashlib.sha256(secret.encode()).hexdigest()
                # Version from metadata system
                states.append(CredentialSyncState(
                    key=key,
                    version=1,  # Get from versioned store
                    hash=secret_hash,
                    modified=""  # Get from metadata
                ))
            except KeyError:
                pass
        return states

    def needs_sync(self, local: CredentialSyncState, remote: CredentialSyncState) -> bool:
        """Determine if credential needs synchronization."""
        if local.hash != remote.hash:
            # Different values - need to resolve
            if remote.version > local.version:
                return True
            elif remote.version == local.version:
                # Same version but different hash = conflict
                raise ConflictError(f"Conflict on {local.key}")
        return False
```

## Audit Logging for Credentials

```python
import json
import logging
from datetime import datetime, timezone
from typing import Optional

class CredentialAuditLogger:
    """Audit logging for credential operations."""

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def log_access(
        self,
        operation: str,
        service: str,
        key: str,
        success: bool,
        user: Optional[str] = None,
        reason: Optional[str] = None
    ):
        """Log credential access attempt."""
        self._logger.info(
            f"credential.{operation}",
            extra={
                'event_type': f'credential_{operation}',
                'service': service,
                'key': key,
                'success': success,
                'user': user or 'system',
                'reason': reason,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                # NEVER log the actual credential value
            }
        )

    def log_rotation(self, service: str, key: str, old_version: int, new_version: int):
        """Log credential rotation."""
        self._logger.info(
            "credential.rotated",
            extra={
                'event_type': 'credential_rotation',
                'service': service,
                'key': key,
                'old_version': old_version,
                'new_version': new_version,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )

    def log_migration(self, service: str, key: str, source: str, target: str, success: bool):
        """Log credential migration between backends."""
        self._logger.info(
            "credential.migrated",
            extra={
                'event_type': 'credential_migration',
                'service': service,
                'key': key,
                'source_backend': source,
                'target_backend': target,
                'success': success,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )
```
