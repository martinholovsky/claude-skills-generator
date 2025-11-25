# Database Design Security Examples

## Sensitive Data Storage

### Password Storage

```sql
-- NEVER store plaintext passwords
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,  -- Argon2id or bcrypt hash
    password_changed_at TEXT DEFAULT (datetime('now')),
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT
);

-- Failed login tracking
CREATE TRIGGER track_failed_login AFTER UPDATE ON users
WHEN new.failed_attempts > old.failed_attempts
BEGIN
    UPDATE users
    SET locked_until = CASE
        WHEN new.failed_attempts >= 5 THEN datetime('now', '+15 minutes')
        ELSE NULL
    END
    WHERE id = new.id;
END;
```

### PII Storage with Encryption Markers

```sql
-- Mark encrypted fields
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    email_encrypted BLOB NOT NULL,  -- Application-level encryption
    email_hash TEXT NOT NULL,       -- For lookup without decryption
    name_encrypted BLOB NOT NULL,
    address_encrypted BLOB,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Index on hash for lookup
CREATE UNIQUE INDEX idx_customers_email ON customers(email_hash);
```

### Tokenization Pattern

```sql
-- Store tokens instead of sensitive data
CREATE TABLE payment_methods (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,          -- Payment processor token
    last_four TEXT NOT NULL,      -- Last 4 digits for display
    card_type TEXT NOT NULL,      -- visa, mastercard, etc.
    expiry_month INTEGER NOT NULL,
    expiry_year INTEGER NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- NEVER store: full card number, CVV, PIN
```

---

## Access Control Patterns

### Row-Level Security (Application Enforced)

```sql
-- Multi-tenant data isolation
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT,

    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- Always filter by tenant
CREATE INDEX idx_documents_tenant ON documents(tenant_id);

-- View for current tenant (application sets tenant_id)
-- In application code:
-- SELECT * FROM documents WHERE tenant_id = ?
```

### Permission-Based Access

```sql
-- Role-based access control tables
CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE permissions (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,  -- 'documents:read', 'documents:write'
    resource TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Check permission
SELECT EXISTS(
    SELECT 1 FROM user_roles ur
    JOIN role_permissions rp ON ur.role_id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE ur.user_id = ?
      AND p.resource = 'documents'
      AND p.action = 'write'
);
```

---

## Audit Trail Implementation

### Complete Audit Log

```sql
-- Audit log for all changes
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_values TEXT,  -- JSON
    new_values TEXT,  -- JSON
    changed_at TEXT DEFAULT (datetime('now')),
    changed_by TEXT,  -- User ID or system
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX idx_audit_table_record ON audit_log(table_name, record_id);
CREATE INDEX idx_audit_time ON audit_log(changed_at DESC);
CREATE INDEX idx_audit_user ON audit_log(changed_by);

-- Generic audit trigger (create for each audited table)
CREATE TRIGGER audit_users_insert AFTER INSERT ON users
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, new_values)
    VALUES ('users', new.id, 'INSERT', json_object(
        'email', new.email,
        'name', new.name
    ));
END;

CREATE TRIGGER audit_users_update AFTER UPDATE ON users
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, old_values, new_values)
    VALUES ('users', new.id, 'UPDATE',
        json_object('email', old.email, 'name', old.name),
        json_object('email', new.email, 'name', new.name)
    );
END;

CREATE TRIGGER audit_users_delete AFTER DELETE ON users
BEGIN
    INSERT INTO audit_log (table_name, record_id, action, old_values)
    VALUES ('users', old.id, 'DELETE', json_object(
        'email', old.email,
        'name', old.name
    ));
END;
```

### Security Event Log

```sql
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
    user_id INTEGER,
    description TEXT NOT NULL,
    metadata TEXT,  -- JSON
    occurred_at TEXT DEFAULT (datetime('now')),
    ip_address TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_security_events_type ON security_events(event_type, occurred_at DESC);
CREATE INDEX idx_security_events_user ON security_events(user_id, occurred_at DESC);
CREATE INDEX idx_security_events_severity ON security_events(severity, occurred_at DESC);

-- Example events
-- 'login_success', 'login_failure', 'password_change', 'permission_denied',
-- 'suspicious_activity', 'data_export', 'admin_action'
```

---

## Data Integrity Patterns

### Optimistic Locking

```sql
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Update with version check (in application)
-- UPDATE documents
-- SET title = ?, content = ?, version = version + 1, updated_at = datetime('now')
-- WHERE id = ? AND version = ?
-- If rows_affected = 0, concurrent modification detected
```

### Immutable Records

```sql
-- Immutable transaction log
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    type TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),

    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- Prevent updates and deletes
CREATE TRIGGER prevent_transaction_update
BEFORE UPDATE ON transactions
BEGIN
    SELECT RAISE(ABORT, 'Transactions are immutable');
END;

CREATE TRIGGER prevent_transaction_delete
BEFORE DELETE ON transactions
BEGIN
    SELECT RAISE(ABORT, 'Transactions cannot be deleted');
END;
```

---

## Data Retention and Cleanup

### Soft Delete with Retention

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    deleted_at TEXT,
    purge_after TEXT  -- Hard delete after this date
);

-- View for active messages
CREATE VIEW active_messages AS
SELECT * FROM messages WHERE deleted_at IS NULL;

-- Cleanup job (run periodically)
-- DELETE FROM messages WHERE purge_after < datetime('now');
```

### Data Anonymization

```sql
-- Instead of deleting user data, anonymize it
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    anonymized_at TEXT
);

-- Anonymize user (preserves referential integrity)
-- UPDATE users
-- SET email = 'deleted_' || id || '@anonymized.local',
--     name = 'Deleted User',
--     anonymized_at = datetime('now')
-- WHERE id = ?;
```

---

## Constraint Patterns for Security

### Business Rule Enforcement

```sql
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'paid', 'shipped', 'delivered', 'cancelled')),
    total REAL NOT NULL CHECK(total >= 0),
    paid_at TEXT,
    shipped_at TEXT,

    -- Business rules
    CHECK(
        (status = 'pending' AND paid_at IS NULL AND shipped_at IS NULL) OR
        (status = 'paid' AND paid_at IS NOT NULL AND shipped_at IS NULL) OR
        (status IN ('shipped', 'delivered') AND paid_at IS NOT NULL AND shipped_at IS NOT NULL) OR
        (status = 'cancelled')
    ),

    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Rate Limiting Data

```sql
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    window_start TEXT NOT NULL DEFAULT (datetime('now')),

    UNIQUE(user_id, action),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Check and update rate limit
-- INSERT INTO rate_limits (user_id, action, attempts, window_start)
-- VALUES (?, ?, 1, datetime('now'))
-- ON CONFLICT(user_id, action) DO UPDATE SET
--     attempts = CASE
--         WHEN window_start < datetime('now', '-1 hour')
--         THEN 1
--         ELSE attempts + 1
--     END,
--     window_start = CASE
--         WHEN window_start < datetime('now', '-1 hour')
--         THEN datetime('now')
--         ELSE window_start
--     END;
```
