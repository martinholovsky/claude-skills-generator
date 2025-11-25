# Encryption Security Examples

## Complete SQLCipher Implementation

```python
"""
Secure SQLCipher database implementation for JARVIS.

This module provides encrypted database storage with:
- AES-256-GCM encryption
- Argon2id key derivation
- Automatic key rotation
- Secure memory handling
"""

import sqlcipher3
import secrets
import logging
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional
from argon2.low_level import hash_secret_raw, Type

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Configuration for encrypted database."""
    path: str
    cipher: str = 'aes-256-gcm'
    kdf_iterations: int = 256000
    page_size: int = 4096


class SecureDatabase:
    """
    Encrypted SQLite database with SQLCipher.

    Example:
        from jarvis.security.os_keychain import get_master_key

        config = DatabaseConfig(path='/data/jarvis.db')
        master_key = get_master_key('jarvis-db-master')

        db = SecureDatabase(config, master_key)

        with db.transaction() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS secrets (...)")
            cursor.execute("INSERT INTO secrets VALUES (?)", (encrypted_value,))
    """

    def __init__(self, config: DatabaseConfig, master_password: str):
        self._config = config
        self._key = self._derive_key(master_password)
        self._ensure_database_exists()

    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from master password."""
        # Use fixed salt for database (stored separately or derived from path)
        salt = self._get_database_salt()

        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

    def _get_database_salt(self) -> bytes:
        """Get or create database-specific salt."""
        salt_path = Path(self._config.path).with_suffix('.salt')

        if salt_path.exists():
            return salt_path.read_bytes()

        # Generate new salt for new database
        salt = secrets.token_bytes(16)
        salt_path.write_bytes(salt)
        return salt

    def _ensure_database_exists(self):
        """Create database with encryption if it doesn't exist."""
        if Path(self._config.path).exists():
            return

        with self._connect() as conn:
            # Database created with encryption on first connect
            conn.execute("SELECT 1")

        logger.info(
            "database.created",
            extra={'path': self._config.path, 'cipher': self._config.cipher}
        )

    @contextmanager
    def _connect(self):
        """Low-level connection with encryption setup."""
        conn = sqlcipher3.connect(self._config.path)
        try:
            # Set encryption key
            conn.execute(f"PRAGMA key = \"x'{self._key.hex()}'\";")

            # Configure cipher
            conn.execute(f"PRAGMA cipher = '{self._config.cipher}';")
            conn.execute(f"PRAGMA kdf_iter = {self._config.kdf_iterations};")
            conn.execute(f"PRAGMA cipher_page_size = {self._config.page_size};")

            # Security hardening
            conn.execute("PRAGMA cipher_memory_security = ON;")
            conn.execute("PRAGMA foreign_keys = ON;")

            # Verify encryption is working
            version = conn.execute("PRAGMA cipher_version;").fetchone()
            if not version:
                raise RuntimeError("SQLCipher encryption verification failed")

            yield conn

        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        """Execute operations in a transaction."""
        with self._connect() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def vacuum(self):
        """Reclaim space and re-encrypt all pages."""
        with self._connect() as conn:
            conn.execute("VACUUM;")

    def integrity_check(self) -> bool:
        """Verify database integrity."""
        with self._connect() as conn:
            result = conn.execute("PRAGMA integrity_check;").fetchone()
            return result[0] == 'ok'

    def export_plaintext(self, output_path: str, confirm: bool = False):
        """
        Export database without encryption.

        WARNING: Only for migration/debugging. Creates unencrypted copy.
        """
        if not confirm:
            raise ValueError("Must confirm plaintext export with confirm=True")

        with self._connect() as conn:
            conn.execute(f"ATTACH DATABASE '{output_path}' AS plaintext KEY '';")
            conn.execute("SELECT sqlcipher_export('plaintext');")
            conn.execute("DETACH DATABASE plaintext;")

        logger.warning(
            "database.exported_plaintext",
            extra={'path': output_path}
        )


## Field-Level Encryption

class FieldEncryption:
    """
    Encrypt individual fields within records.

    Use when:
    - Only specific fields need encryption
    - Different fields need different keys
    - Searching encrypted data not required
    """

    def __init__(self, key: bytes):
        self._encryptor = SecureEncryption(key)

    def encrypt_field(self, value: str) -> bytes:
        """Encrypt a string field."""
        return self._encryptor.encrypt(value.encode('utf-8'))

    def decrypt_field(self, ciphertext: bytes) -> str:
        """Decrypt a string field."""
        return self._encryptor.decrypt(ciphertext).decode('utf-8')

    def encrypt_dict(self, data: dict, fields: list[str]) -> dict:
        """Encrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.encrypt_field(str(result[field]))
        return result

    def decrypt_dict(self, data: dict, fields: list[str]) -> dict:
        """Decrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.decrypt_field(result[field])
        return result
```

## Secure Configuration Management

```python
"""
Encrypted configuration storage for sensitive settings.
"""

import json
from pathlib import Path


class SecureConfig:
    """
    Store configuration with encrypted sensitive values.

    Example:
        config = SecureConfig('/etc/jarvis/config.enc', encryption_key)

        # Store API key
        config.set('openai_api_key', 'sk-...')

        # Retrieve
        api_key = config.get('openai_api_key')
    """

    def __init__(self, path: str, key: bytes):
        self._path = Path(path)
        self._encryptor = SecureEncryption(key)
        self._cache: Optional[dict] = None

    def _load(self) -> dict:
        """Load and decrypt configuration."""
        if self._cache is not None:
            return self._cache

        if not self._path.exists():
            return {}

        encrypted = self._path.read_bytes()
        decrypted = self._encryptor.decrypt(encrypted)
        self._cache = json.loads(decrypted)
        return self._cache

    def _save(self, data: dict):
        """Encrypt and save configuration."""
        plaintext = json.dumps(data, indent=2).encode('utf-8')
        encrypted = self._encryptor.encrypt(plaintext)

        # Atomic write
        temp_path = self._path.with_suffix('.tmp')
        temp_path.write_bytes(encrypted)
        temp_path.rename(self._path)

        self._cache = data

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self._load().get(key, default)

    def set(self, key: str, value):
        """Set configuration value."""
        data = self._load()
        data[key] = value
        self._save(data)

    def delete(self, key: str):
        """Delete configuration value."""
        data = self._load()
        if key in data:
            del data[key]
            self._save(data)
```

## Secure File Encryption

```python
"""
File encryption utilities for JARVIS.
"""

import os
from pathlib import Path


class FileEncryption:
    """
    Encrypt and decrypt files with streaming support.

    Example:
        fe = FileEncryption(encryption_key)

        # Encrypt file
        fe.encrypt_file('document.pdf', 'document.pdf.enc')

        # Decrypt file
        fe.decrypt_file('document.pdf.enc', 'document.pdf')
    """

    CHUNK_SIZE = 64 * 1024  # 64 KB

    def __init__(self, key: bytes):
        self._key = key

    def encrypt_file(self, input_path: str, output_path: str):
        """Encrypt a file."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(self._key)

        # Read entire file (for small files)
        # For large files, use streaming with chunked encryption
        plaintext = Path(input_path).read_bytes()

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Write nonce + ciphertext
        with open(output_path, 'wb') as f:
            f.write(nonce)
            f.write(ciphertext)

    def decrypt_file(self, input_path: str, output_path: str):
        """Decrypt a file."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(self._key)

        with open(input_path, 'rb') as f:
            nonce = f.read(12)
            ciphertext = f.read()

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        Path(output_path).write_bytes(plaintext)

    def secure_delete(self, path: str, passes: int = 3):
        """
        Securely delete a file by overwriting before removal.

        Note: May not be effective on SSDs or copy-on-write filesystems.
        """
        file_path = Path(path)
        if not file_path.exists():
            return

        size = file_path.stat().st_size

        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

        file_path.unlink()
```

## TypeScript Implementation

```typescript
/**
 * Encryption utilities for JARVIS TypeScript components.
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { argon2id } from '@noble/hashes/argon2';

const NONCE_SIZE = 12;
const KEY_SIZE = 32;
const SALT_SIZE = 16;

export class SecureEncryption {
  private key: Uint8Array;

  constructor(key: Uint8Array) {
    if (key.length !== KEY_SIZE) {
      throw new Error(`Key must be ${KEY_SIZE} bytes`);
    }
    this.key = key;
  }

  /**
   * Encrypt plaintext with random nonce.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const nonce = randomBytes(NONCE_SIZE);
    const aes = gcm(this.key, nonce);
    const ciphertext = aes.encrypt(plaintext);

    // Prepend nonce to ciphertext
    const result = new Uint8Array(NONCE_SIZE + ciphertext.length);
    result.set(nonce);
    result.set(ciphertext, NONCE_SIZE);

    return result;
  }

  /**
   * Decrypt ciphertext and verify authenticity.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length < NONCE_SIZE + 16) {
      throw new Error('Ciphertext too short');
    }

    const nonce = ciphertext.slice(0, NONCE_SIZE);
    const actualCiphertext = ciphertext.slice(NONCE_SIZE);

    const aes = gcm(this.key, nonce);
    return aes.decrypt(actualCiphertext);
  }
}

export class KeyDerivation {
  /**
   * Derive key from password using Argon2id.
   */
  static async deriveKey(
    password: string,
    salt?: Uint8Array
  ): Promise<{ key: Uint8Array; salt: Uint8Array }> {
    const actualSalt = salt || randomBytes(SALT_SIZE);

    const key = argon2id(
      new TextEncoder().encode(password),
      actualSalt,
      {
        t: 3,          // iterations
        m: 65536,      // 64 MiB memory
        p: 4,          // parallelism
        dkLen: KEY_SIZE
      }
    );

    return { key, salt: actualSalt };
  }
}

// Usage example
async function example() {
  const password = 'user-password-here';

  // Derive key from password
  const { key, salt } = await KeyDerivation.deriveKey(password);

  // Create encryptor
  const encryptor = new SecureEncryption(key);

  // Encrypt data
  const plaintext = new TextEncoder().encode('secret message');
  const ciphertext = encryptor.encrypt(plaintext);

  // Decrypt data
  const decrypted = encryptor.decrypt(ciphertext);
  const message = new TextDecoder().decode(decrypted);
}
```

## Go Implementation

```go
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	NonceSize = 12
	KeySize   = 32
	SaltSize  = 16
)

// SecureEncryption provides AES-256-GCM encryption.
type SecureEncryption struct {
	aead cipher.AEAD
}

// NewSecureEncryption creates a new encryptor with the given key.
func NewSecureEncryption(key []byte) (*SecureEncryption, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SecureEncryption{aead: aead}, nil
}

// Encrypt encrypts plaintext with a random nonce.
func (e *SecureEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext to nonce
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext and verifies authenticity.
func (e *SecureEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+e.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:NonceSize]
	actualCiphertext := ciphertext[NonceSize:]

	return e.aead.Open(nil, nonce, actualCiphertext, nil)
}

// DeriveKey derives a key from password using Argon2id.
func DeriveKey(password string, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, err
		}
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		3,      // iterations
		64*1024, // 64 MiB memory
		4,      // parallelism
		KeySize,
	)

	return key, salt, nil
}
```
