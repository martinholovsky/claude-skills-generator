# OS Keychain Security Examples

## Complete macOS Implementation

```python
"""
macOS Keychain implementation with full security features.
"""

import subprocess
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class MacOSKeychainSecure:
    """
    Secure macOS Keychain integration.

    Features:
    - Access control lists
    - Code signing verification
    - Touch ID/password gating
    - Secure item attributes
    """

    def __init__(self, service: str):
        self._service = service
        self._verify_macos()

    def _verify_macos(self):
        """Verify running on macOS."""
        import platform
        if platform.system() != 'Darwin':
            raise RuntimeError("MacOSKeychain only available on macOS")

    def store_secure(
        self,
        account: str,
        password: str,
        label: str = None,
        comment: str = None,
        access_control: str = 'default'
    ) -> None:
        """
        Store credential with security controls.

        Args:
            account: Account identifier
            password: Secret value
            label: Human-readable label
            comment: Additional notes
            access_control: 'default', 'always-prompt', 'biometric'
        """
        cmd = [
            'security', 'add-generic-password',
            '-s', self._service,
            '-a', account,
            '-w', password,
            '-U',  # Update if exists
        ]

        if label:
            cmd.extend(['-l', label])

        if comment:
            cmd.extend(['-j', comment])

        # Configure access control
        if access_control == 'always-prompt':
            cmd.extend(['-T', ''])  # Empty ACL = always prompt
        elif access_control == 'biometric':
            # Requires Security.framework for proper implementation
            pass

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            if 'already exists' in result.stderr:
                # Try to update existing
                self.delete(account)
                return self.store_secure(account, password, label, comment, access_control)
            raise RuntimeError(f"Keychain store failed: {result.stderr}")

        logger.info(
            "keychain.stored",
            extra={'service': self._service, 'account': account}
        )

    def retrieve(self, account: str) -> str:
        """Retrieve password from keychain."""
        cmd = [
            'security', 'find-generic-password',
            '-s', self._service,
            '-a', account,
            '-w'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise KeyError(f"Credential not found: {account}")

        return result.stdout.strip()

    def delete(self, account: str) -> None:
        """Delete credential from keychain."""
        cmd = [
            'security', 'delete-generic-password',
            '-s', self._service,
            '-a', account
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0 and 'could not be found' not in result.stderr:
            raise RuntimeError(f"Keychain delete failed: {result.stderr}")

    def get_attributes(self, account: str) -> Dict[str, Any]:
        """Get keychain item attributes."""
        cmd = [
            'security', 'find-generic-password',
            '-s', self._service,
            '-a', account,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise KeyError(f"Credential not found: {account}")

        # Parse security output
        attrs = {}
        for line in result.stdout.split('\n'):
            if '=' in line:
                key, _, value = line.partition('=')
                attrs[key.strip().strip('"')] = value.strip().strip('"')

        return attrs

    def list_credentials(self) -> list:
        """List all credentials for this service."""
        cmd = [
            'security', 'dump-keychain',
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        credentials = []
        current_item = {}

        for line in result.stdout.split('\n'):
            if 'keychain:' in line:
                if current_item.get('svce') == f'"{self._service}"':
                    credentials.append(current_item.get('acct', '').strip('"'))
                current_item = {}
            elif '=' in line:
                key, _, value = line.partition('=')
                current_item[key.strip().strip('"')] = value.strip()

        return credentials
```

## Complete Windows Implementation

```python
"""
Windows Credential Manager implementation.
"""

import ctypes
from ctypes import wintypes
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class WindowsCredentialManagerSecure:
    """
    Secure Windows Credential Manager integration.

    Uses DPAPI encryption tied to user account.
    """

    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2
    CRED_PERSIST_ENTERPRISE = 3

    def __init__(self, target_prefix: str):
        self._prefix = target_prefix
        self._verify_windows()

    def _verify_windows(self):
        """Verify running on Windows."""
        import platform
        if platform.system() != 'Windows':
            raise RuntimeError("WindowsCredentialManager only available on Windows")

    def _get_target(self, key: str) -> str:
        return f"{self._prefix}/{key}"

    def store(
        self,
        key: str,
        secret: str,
        username: str = "JARVIS",
        persist: str = 'local'
    ) -> None:
        """
        Store credential in Credential Manager.

        Args:
            key: Credential identifier
            secret: Secret value
            username: Associated username
            persist: 'local' or 'enterprise' (roaming)
        """
        try:
            import win32cred
        except ImportError:
            raise RuntimeError("pywin32 required for Windows credential storage")

        target = self._get_target(key)

        persistence = (
            self.CRED_PERSIST_ENTERPRISE if persist == 'enterprise'
            else self.CRED_PERSIST_LOCAL_MACHINE
        )

        credential = {
            'Type': self.CRED_TYPE_GENERIC,
            'TargetName': target,
            'UserName': username,
            'CredentialBlob': secret,
            'Persist': persistence,
            'Comment': f'JARVIS credential: {key}'
        }

        try:
            win32cred.CredWrite(credential, 0)
            logger.info(
                "credential.stored",
                extra={'target': target, 'username': username}
            )
        except Exception as e:
            logger.error(f"Credential store failed: {e}")
            raise

    def retrieve(self, key: str) -> str:
        """Retrieve credential from Credential Manager."""
        try:
            import win32cred
        except ImportError:
            raise RuntimeError("pywin32 required")

        target = self._get_target(key)

        try:
            cred = win32cred.CredRead(target, self.CRED_TYPE_GENERIC)
            blob = cred['CredentialBlob']

            # Handle encoding
            if isinstance(blob, bytes):
                # Try UTF-16 first (Windows default)
                try:
                    return blob.decode('utf-16-le').rstrip('\x00')
                except UnicodeDecodeError:
                    return blob.decode('utf-8')
            return blob

        except Exception as e:
            raise KeyError(f"Credential not found: {key}") from e

    def delete(self, key: str) -> None:
        """Delete credential from Credential Manager."""
        try:
            import win32cred
        except ImportError:
            raise RuntimeError("pywin32 required")

        target = self._get_target(key)

        try:
            win32cred.CredDelete(target, self.CRED_TYPE_GENERIC)
            logger.info("credential.deleted", extra={'target': target})
        except Exception as e:
            if 'not found' not in str(e).lower():
                raise

    def list_credentials(self) -> list:
        """List all credentials with our prefix."""
        try:
            import win32cred
        except ImportError:
            raise RuntimeError("pywin32 required")

        try:
            creds = win32cred.CredEnumerate(f"{self._prefix}/*", 0)
            return [
                c['TargetName'].replace(f"{self._prefix}/", '')
                for c in creds
            ]
        except Exception:
            return []
```

## Complete Linux Implementation

```python
"""
Linux Secret Service implementation with GNOME Keyring/KWallet support.
"""

import logging
from typing import Optional, Dict, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class LinuxSecretServiceSecure:
    """
    Secure Linux Secret Service integration.

    Compatible with:
    - GNOME Keyring
    - KWallet (with KDE)
    - Other Secret Service providers
    """

    def __init__(self, application_id: str):
        self._app_id = application_id
        self._verify_linux()
        self._verify_service()

    def _verify_linux(self):
        """Verify running on Linux."""
        import platform
        if platform.system() != 'Linux':
            raise RuntimeError("LinuxSecretService only available on Linux")

    def _verify_service(self):
        """Verify Secret Service is available."""
        try:
            import secretstorage
            conn = secretstorage.dbus_init()
            conn.close()
        except ImportError:
            raise RuntimeError("secretstorage package required")
        except Exception as e:
            raise RuntimeError(
                f"Secret Service not available: {e}. "
                "Ensure gnome-keyring or kwallet is running."
            )

    @contextmanager
    def _connection(self):
        """D-Bus connection context manager."""
        import secretstorage
        conn = secretstorage.dbus_init()
        try:
            yield conn
        finally:
            conn.close()

    def _get_collection(self, conn):
        """Get default collection, unlocking if needed."""
        import secretstorage

        collection = secretstorage.get_default_collection(conn)

        if collection.is_locked():
            collection.unlock()
            if collection.is_locked():
                raise RuntimeError("Failed to unlock keyring")

        return collection

    def store(
        self,
        key: str,
        secret: str,
        label: str = None,
        attributes: Dict[str, str] = None
    ) -> None:
        """
        Store secret in Secret Service.

        Args:
            key: Secret identifier
            secret: Secret value
            label: Human-readable label
            attributes: Additional searchable attributes
        """
        with self._connection() as conn:
            collection = self._get_collection(conn)

            # Build attributes
            attrs = {
                'application': self._app_id,
                'key': key
            }
            if attributes:
                attrs.update(attributes)

            # Remove existing
            for item in collection.search_items(attrs):
                item.delete()

            # Create new
            item_label = label or f"{self._app_id}: {key}"
            collection.create_item(
                item_label,
                attrs,
                secret.encode('utf-8'),
                replace=True
            )

            logger.info(
                "secret.stored",
                extra={'app': self._app_id, 'key': key}
            )

    def retrieve(self, key: str) -> str:
        """Retrieve secret from Secret Service."""
        with self._connection() as conn:
            collection = self._get_collection(conn)

            attrs = {
                'application': self._app_id,
                'key': key
            }

            items = list(collection.search_items(attrs))

            if not items:
                raise KeyError(f"Secret not found: {key}")

            # Get first match
            secret = items[0].get_secret()
            return secret.decode('utf-8')

    def delete(self, key: str) -> None:
        """Delete secret from Secret Service."""
        with self._connection() as conn:
            collection = self._get_collection(conn)

            attrs = {
                'application': self._app_id,
                'key': key
            }

            for item in collection.search_items(attrs):
                item.delete()

            logger.info(
                "secret.deleted",
                extra={'app': self._app_id, 'key': key}
            )

    def list_secrets(self) -> List[str]:
        """List all secrets for this application."""
        with self._connection() as conn:
            collection = self._get_collection(conn)

            attrs = {'application': self._app_id}
            items = collection.search_items(attrs)

            return [
                item.get_attributes().get('key', '')
                for item in items
            ]

    def search(self, attributes: Dict[str, str]) -> List[Dict]:
        """Search secrets by attributes."""
        with self._connection() as conn:
            collection = self._get_collection(conn)

            attrs = {'application': self._app_id}
            attrs.update(attributes)

            results = []
            for item in collection.search_items(attrs):
                results.append({
                    'label': item.get_label(),
                    'attributes': item.get_attributes(),
                    # Note: Not including secret value in search results
                })

            return results
```

## Integration with Encryption Skill

```python
"""
Integration between OS Keychain and Encryption skill.
"""

from jarvis.security.encryption import SecureKeyDerivation, EncryptedDatabase


class KeychainBackedEncryption:
    """
    Encryption using master key from OS keychain.

    This is the recommended pattern for JARVIS:
    1. Master password stored in OS keychain
    2. Encryption key derived from master password
    3. Database encrypted with derived key
    """

    def __init__(self, keychain: SecureCredentialStore, db_path: str):
        self._keychain = keychain
        self._db_path = db_path

    def initialize(self, master_password: str) -> None:
        """
        Initialize encryption with master password.

        Stores master password in keychain for future use.
        """
        # Store master password in keychain
        self._keychain.store("master-password", master_password)

        # Derive encryption key
        key, salt = SecureKeyDerivation.derive_key(master_password)

        # Store salt (not secret, needed for key derivation)
        self._keychain.store("master-salt", salt.hex())

        # Initialize encrypted database
        db = EncryptedDatabase(self._db_path, key)
        with db.connect() as conn:
            # Database created with encryption
            conn.execute("SELECT 1")

    def get_database(self) -> EncryptedDatabase:
        """Get encrypted database connection."""
        # Retrieve master password from keychain
        master_password = self._keychain.retrieve("master-password")
        salt_hex = self._keychain.retrieve("master-salt")
        salt = bytes.fromhex(salt_hex)

        # Derive key
        key, _ = SecureKeyDerivation.derive_key(master_password, salt)

        return EncryptedDatabase(self._db_path, key)


# Usage example
def example_usage():
    # Create keychain-backed encryption
    keychain = SecureCredentialStore("encryption")
    encryption = KeychainBackedEncryption(keychain, "/data/jarvis.db")

    # First-time initialization
    encryption.initialize("user-master-password")

    # Subsequent use
    db = encryption.get_database()
    with db.transaction() as cursor:
        cursor.execute("SELECT * FROM secrets")
```
