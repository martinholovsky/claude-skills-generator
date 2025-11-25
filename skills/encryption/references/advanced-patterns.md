# Advanced Encryption Patterns

## Key Rotation Strategy

### Versioned Encryption

```python
import json
from dataclasses import dataclass
from typing import Optional

@dataclass
class EncryptedPayload:
    """Versioned encrypted data structure."""
    version: int
    key_id: str
    salt: bytes
    ciphertext: bytes

class VersionedEncryption:
    """Support key rotation with versioned encryption."""

    def __init__(self, key_store: 'KeyStore'):
        self._key_store = key_store

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with current key version."""
        current_key = self._key_store.get_current_key()

        encryptor = SecureEncryption(current_key.material)
        ciphertext = encryptor.encrypt(plaintext)

        payload = EncryptedPayload(
            version=2,  # Payload format version
            key_id=current_key.id,
            salt=current_key.salt,
            ciphertext=ciphertext
        )

        return self._serialize(payload)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt with appropriate key version."""
        payload = self._deserialize(data)

        key = self._key_store.get_key(payload.key_id)
        if key is None:
            raise KeyError(f"Key {payload.key_id} not found - may be retired")

        decryptor = SecureEncryption(key.material)
        return decryptor.decrypt(payload.ciphertext)

    def rotate_encryption(self, data: bytes) -> bytes:
        """Re-encrypt data with current key."""
        plaintext = self.decrypt(data)
        return self.encrypt(plaintext)
```

### SQLCipher Key Rotation

```python
class DatabaseKeyRotation:
    """Rotate SQLCipher database encryption keys."""

    def __init__(self, db_path: str, key_store: 'KeyStore'):
        self._db_path = db_path
        self._key_store = key_store

    def rotate_key(self):
        """
        Atomic key rotation with backup.

        IMPORTANT: This operation locks the database.
        Schedule during maintenance window.
        """
        import shutil
        from pathlib import Path

        db_path = Path(self._db_path)
        backup_path = db_path.with_suffix('.backup')

        # 1. Create backup before rotation
        shutil.copy2(db_path, backup_path)

        try:
            # 2. Get current and new keys
            current_key = self._key_store.get_current_key()
            new_key = self._key_store.generate_new_key()

            # 3. Perform rekey operation
            with EncryptedDatabase(self._db_path, current_key.material).connect() as conn:
                conn.execute(f"PRAGMA rekey = \"x'{new_key.material.hex()}'\";")

            # 4. Verify new key works
            with EncryptedDatabase(self._db_path, new_key.material).connect() as conn:
                conn.execute("SELECT count(*) FROM sqlite_master;").fetchone()

            # 5. Mark rotation complete
            self._key_store.activate_key(new_key.id)
            self._key_store.retire_key(current_key.id)

            # 6. Remove backup after successful rotation
            backup_path.unlink()

        except Exception as e:
            # Restore from backup on failure
            shutil.copy2(backup_path, db_path)
            backup_path.unlink()
            raise RuntimeError(f"Key rotation failed: {e}") from e
```

## Secure Memory Handling

### Memory Protection Patterns

```python
import ctypes
import secrets
from contextlib import contextmanager

class SecureBuffer:
    """
    Memory buffer that is zeroed on destruction.

    WARNING: Python's memory management limits effectiveness.
    Use for reducing exposure window, not guarantee.
    """

    def __init__(self, size: int):
        self._size = size
        self._buffer = ctypes.create_string_buffer(size)

    def write(self, data: bytes):
        """Write data to secure buffer."""
        if len(data) > self._size:
            raise ValueError("Data exceeds buffer size")
        ctypes.memmove(self._buffer, data, len(data))

    def read(self) -> bytes:
        """Read data from buffer."""
        return self._buffer.raw[:self._size]

    def clear(self):
        """Overwrite buffer with zeros."""
        ctypes.memset(self._buffer, 0, self._size)

    def __del__(self):
        """Zero memory on destruction."""
        self.clear()


@contextmanager
def secure_key_context(key: bytes):
    """
    Context manager for temporary key usage.

    Zeros key memory on exit (best effort).
    """
    buffer = SecureBuffer(len(key))
    buffer.write(key)
    try:
        yield buffer.read()
    finally:
        buffer.clear()
        # Overwrite original bytes object (limited effectiveness)
        try:
            ctypes.memset(id(key) + 32, 0, len(key))
        except Exception:
            pass  # Best effort
```

### Memory-Mapped Key Storage

```python
import mmap
import os

class MemoryLockedKey:
    """
    Store key in memory-locked region.

    Prevents key from being swapped to disk.
    Requires appropriate privileges on some systems.
    """

    def __init__(self, key: bytes):
        self._size = len(key)

        # Create anonymous memory mapping
        self._mmap = mmap.mmap(-1, self._size, mmap.MAP_PRIVATE)

        # Attempt to lock memory (prevent swapping)
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (self._size, self._size))
        except (ImportError, ValueError):
            pass  # Not available on all platforms

        # Write key to locked memory
        self._mmap.write(key)

    def get(self) -> bytes:
        """Retrieve key from locked memory."""
        self._mmap.seek(0)
        return self._mmap.read(self._size)

    def destroy(self):
        """Securely destroy key material."""
        # Overwrite with random data
        self._mmap.seek(0)
        self._mmap.write(secrets.token_bytes(self._size))

        # Then zero
        self._mmap.seek(0)
        self._mmap.write(b'\x00' * self._size)

        self._mmap.close()
```

## Hardware Security Module Integration

### PKCS#11 Interface

```python
class HSMKeyManager:
    """
    Key management using Hardware Security Module.

    Keys never leave the HSM - all operations performed inside.
    """

    def __init__(self, pkcs11_lib: str, slot: int, pin: str):
        import pkcs11

        self._lib = pkcs11.lib(pkcs11_lib)
        self._token = self._lib.get_token(slot=slot)
        self._session = self._token.open(user_pin=pin)

    def generate_key(self, label: str) -> str:
        """Generate AES-256 key inside HSM."""
        from pkcs11 import KeyType, Attribute, Mechanism

        key = self._session.generate_key(
            KeyType.AES,
            256,
            label=label,
            template={
                Attribute.EXTRACTABLE: False,  # Key cannot leave HSM
                Attribute.SENSITIVE: True,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            }
        )

        return key.id.hex()

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using HSM key."""
        from pkcs11 import Mechanism
        import secrets

        key = self._session.get_key(id=bytes.fromhex(key_id))
        nonce = secrets.token_bytes(12)

        ciphertext = key.encrypt(
            plaintext,
            mechanism=Mechanism.AES_GCM,
            mechanism_param={'iv': nonce, 'tag_bits': 128}
        )

        return nonce + ciphertext

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using HSM key."""
        from pkcs11 import Mechanism

        key = self._session.get_key(id=bytes.fromhex(key_id))
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]

        return key.decrypt(
            actual_ciphertext,
            mechanism=Mechanism.AES_GCM,
            mechanism_param={'iv': nonce, 'tag_bits': 128}
        )
```

## Envelope Encryption

### Multi-Layer Key Hierarchy

```python
class EnvelopeEncryption:
    """
    Envelope encryption with key hierarchy.

    Structure:
    - Master Key (in HSM/Keychain): Encrypts key encryption keys
    - Key Encryption Key (KEK): Encrypts data encryption keys
    - Data Encryption Key (DEK): Encrypts actual data
    """

    def __init__(self, master_key_provider: 'MasterKeyProvider'):
        self._master = master_key_provider

    def encrypt(self, plaintext: bytes) -> dict:
        """Encrypt with envelope encryption."""
        # Generate random DEK for this data
        dek = secrets.token_bytes(32)

        # Encrypt data with DEK
        data_encryptor = SecureEncryption(dek)
        encrypted_data = data_encryptor.encrypt(plaintext)

        # Encrypt DEK with master key
        encrypted_dek = self._master.encrypt(dek)

        return {
            'version': 1,
            'encrypted_dek': encrypted_dek,
            'encrypted_data': encrypted_data,
            'master_key_id': self._master.key_id
        }

    def decrypt(self, envelope: dict) -> bytes:
        """Decrypt envelope encrypted data."""
        # Decrypt DEK using master key
        dek = self._master.decrypt(envelope['encrypted_dek'])

        # Decrypt data with DEK
        data_decryptor = SecureEncryption(dek)
        return data_decryptor.decrypt(envelope['encrypted_data'])
```

## Performance Optimization

### Parallel Encryption for Large Data

```python
import concurrent.futures
from typing import List

class ParallelEncryption:
    """Encrypt large data in parallel chunks."""

    CHUNK_SIZE = 64 * 1024  # 64 KB chunks

    def __init__(self, key: bytes, max_workers: int = 4):
        self._key = key
        self._max_workers = max_workers

    def encrypt_large(self, plaintext: bytes) -> bytes:
        """Encrypt large data using parallel processing."""
        chunks = [
            plaintext[i:i + self.CHUNK_SIZE]
            for i in range(0, len(plaintext), self.CHUNK_SIZE)
        ]

        with concurrent.futures.ThreadPoolExecutor(self._max_workers) as executor:
            futures = [
                executor.submit(self._encrypt_chunk, i, chunk)
                for i, chunk in enumerate(chunks)
            ]

            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        # Sort by index and concatenate
        results.sort(key=lambda x: x[0])
        encrypted_chunks = [r[1] for r in results]

        # Serialize with chunk count
        return self._serialize_chunks(encrypted_chunks)

    def _encrypt_chunk(self, index: int, chunk: bytes) -> tuple:
        """Encrypt single chunk with unique nonce."""
        encryptor = SecureEncryption(self._key)
        return (index, encryptor.encrypt(chunk))
```

## Compliance Integration

### Audit Trail for Cryptographic Operations

```python
import logging
from datetime import datetime, timezone

class CryptoAuditLogger:
    """Audit logging for cryptographic operations."""

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def log_key_generation(self, key_id: str, algorithm: str, purpose: str):
        """Log key generation event."""
        self._logger.info(
            "crypto.key.generated",
            extra={
                'event_type': 'key_generation',
                'key_id': key_id,
                'algorithm': algorithm,
                'purpose': purpose,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )

    def log_key_rotation(self, old_key_id: str, new_key_id: str, reason: str):
        """Log key rotation event."""
        self._logger.info(
            "crypto.key.rotated",
            extra={
                'event_type': 'key_rotation',
                'old_key_id': old_key_id,
                'new_key_id': new_key_id,
                'reason': reason,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )

    def log_decryption_failure(self, key_id: str, error_type: str):
        """Log decryption failure - potential attack indicator."""
        self._logger.warning(
            "crypto.decryption.failed",
            extra={
                'event_type': 'decryption_failure',
                'key_id': key_id,
                'error_type': error_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )
```
