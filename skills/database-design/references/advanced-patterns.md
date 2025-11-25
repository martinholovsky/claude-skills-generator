# Database Design Advanced Patterns

## Polymorphic Associations

### Single Table Inheritance (STI)

```sql
-- All types in one table
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('email', 'sms', 'push')),

    -- Common fields
    recipient_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    sent_at TEXT,

    -- Email-specific (NULL for other types)
    email_subject TEXT,
    email_html TEXT,

    -- SMS-specific
    phone_number TEXT,

    -- Push-specific
    device_token TEXT,
    badge_count INTEGER,

    FOREIGN KEY (recipient_id) REFERENCES users(id)
);

CREATE INDEX idx_notifications_type ON notifications(type);
CREATE INDEX idx_notifications_recipient ON notifications(recipient_id, sent_at DESC);
```

### Class Table Inheritance

```sql
-- Base table with common fields
CREATE TABLE vehicles (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('car', 'motorcycle', 'truck')),
    make TEXT NOT NULL,
    model TEXT NOT NULL,
    year INTEGER NOT NULL
);

-- Type-specific tables
CREATE TABLE cars (
    vehicle_id INTEGER PRIMARY KEY,
    doors INTEGER NOT NULL,
    trunk_size REAL,
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE motorcycles (
    vehicle_id INTEGER PRIMARY KEY,
    engine_cc INTEGER NOT NULL,
    has_sidecar INTEGER DEFAULT 0,
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

-- Query with type-specific data
SELECT v.*, c.doors, c.trunk_size
FROM vehicles v
JOIN cars c ON v.id = c.vehicle_id
WHERE v.type = 'car';
```

### Polymorphic via Separate Foreign Keys

```sql
-- Comments can belong to multiple entity types
CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),

    -- Only one will be non-NULL
    article_id INTEGER,
    photo_id INTEGER,
    video_id INTEGER,

    -- Ensure exactly one is set
    CHECK(
        (article_id IS NOT NULL AND photo_id IS NULL AND video_id IS NULL) OR
        (article_id IS NULL AND photo_id IS NOT NULL AND video_id IS NULL) OR
        (article_id IS NULL AND photo_id IS NULL AND video_id IS NOT NULL)
    ),

    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (photo_id) REFERENCES photos(id) ON DELETE CASCADE,
    FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE
);

-- Partial indexes for each type
CREATE INDEX idx_comments_article ON comments(article_id) WHERE article_id IS NOT NULL;
CREATE INDEX idx_comments_photo ON comments(photo_id) WHERE photo_id IS NOT NULL;
CREATE INDEX idx_comments_video ON comments(video_id) WHERE video_id IS NOT NULL;
```

---

## Hierarchical Data Patterns

### Adjacency List (Simple)

```sql
CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    name TEXT NOT NULL,

    FOREIGN KEY (parent_id) REFERENCES categories(id) ON DELETE CASCADE
);

-- Get tree with recursive CTE
WITH RECURSIVE tree AS (
    SELECT id, parent_id, name, 0 as depth, name as path
    FROM categories WHERE parent_id IS NULL

    UNION ALL

    SELECT c.id, c.parent_id, c.name, t.depth + 1, t.path || '/' || c.name
    FROM categories c
    JOIN tree t ON c.parent_id = t.id
)
SELECT * FROM tree ORDER BY path;
```

### Materialized Path

```sql
CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,  -- e.g., "/1/5/12/"

    -- Depth is easily calculated
    depth INTEGER GENERATED ALWAYS AS (length(path) - length(replace(path, '/', '')) - 1) STORED
);

CREATE INDEX idx_categories_path ON categories(path);

-- Get all descendants
SELECT * FROM categories WHERE path LIKE '/1/5/%';

-- Get ancestors
SELECT * FROM categories
WHERE '/1/5/12/' LIKE path || '%'
ORDER BY depth;
```

### Closure Table (Best for Complex Queries)

```sql
-- Main table
CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

-- Closure table stores all ancestor-descendant pairs
CREATE TABLE category_closure (
    ancestor_id INTEGER NOT NULL,
    descendant_id INTEGER NOT NULL,
    depth INTEGER NOT NULL,

    PRIMARY KEY (ancestor_id, descendant_id),
    FOREIGN KEY (ancestor_id) REFERENCES categories(id) ON DELETE CASCADE,
    FOREIGN KEY (descendant_id) REFERENCES categories(id) ON DELETE CASCADE
);

CREATE INDEX idx_closure_descendant ON category_closure(descendant_id);

-- Insert triggers to maintain closure
CREATE TRIGGER category_insert AFTER INSERT ON categories
BEGIN
    -- Self-reference
    INSERT INTO category_closure (ancestor_id, descendant_id, depth)
    VALUES (new.id, new.id, 0);
END;

-- Get all descendants of node 5
SELECT c.* FROM categories c
JOIN category_closure cc ON c.id = cc.descendant_id
WHERE cc.ancestor_id = 5 AND cc.depth > 0;

-- Get all ancestors of node 12
SELECT c.* FROM categories c
JOIN category_closure cc ON c.id = cc.ancestor_id
WHERE cc.descendant_id = 12 AND cc.depth > 0
ORDER BY cc.depth DESC;

-- Get subtree depth
SELECT MAX(depth) FROM category_closure WHERE ancestor_id = 5;
```

---

## Temporal Data Patterns

### Slowly Changing Dimension Type 2 (History)

```sql
-- Track all historical values
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL,  -- Business key
    name TEXT NOT NULL,
    price REAL NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,  -- NULL means current

    -- Only one current version per product
    UNIQUE(product_id, valid_to)
);

CREATE INDEX idx_products_current ON products(product_id) WHERE valid_to IS NULL;

-- Get current product
SELECT * FROM products WHERE product_id = 123 AND valid_to IS NULL;

-- Get product as of date
SELECT * FROM products
WHERE product_id = 123
  AND valid_from <= '2024-01-15'
  AND (valid_to IS NULL OR valid_to > '2024-01-15');
```

### Bitemporal Data

```sql
-- Track both valid time and transaction time
CREATE TABLE contracts (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER NOT NULL,
    amount REAL NOT NULL,

    -- Valid time (when the data is true in the real world)
    valid_from TEXT NOT NULL,
    valid_to TEXT,

    -- Transaction time (when recorded in database)
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    superseded_at TEXT  -- NULL means current record
);

-- Get current view
SELECT * FROM contracts
WHERE superseded_at IS NULL AND valid_to IS NULL;

-- Get historical view as recorded at specific time
SELECT * FROM contracts
WHERE recorded_at <= '2024-01-01' AND (superseded_at IS NULL OR superseded_at > '2024-01-01')
  AND valid_from <= '2024-01-01' AND (valid_to IS NULL OR valid_to > '2024-01-01');
```

---

## JSON Data Patterns

### Structured JSON Column

```sql
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',  -- JSON

    -- Validate JSON
    CHECK(json_valid(attributes))
);

-- Query JSON fields
SELECT * FROM products
WHERE json_extract(attributes, '$.color') = 'red';

-- Index on JSON field (expression index)
CREATE INDEX idx_products_color ON products(json_extract(attributes, '$.color'));

-- Aggregate JSON arrays
SELECT json_group_array(json_extract(attributes, '$.tags'))
FROM products;
```

### JSON for Flexible Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    data TEXT NOT NULL,  -- JSON payload varies by type

    CHECK(json_valid(data))
);

-- Type-specific queries
SELECT id, json_extract(data, '$.user_id') as user_id
FROM events
WHERE type = 'login';

SELECT id, json_extract(data, '$.amount') as amount
FROM events
WHERE type = 'purchase' AND json_extract(data, '$.amount') > 100;
```

---

## Performance Optimization Patterns

### Denormalization for Read Performance

```sql
-- Normalized: requires join
CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT);
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);

-- Denormalized: no join needed for common query
CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,  -- Denormalized
    content TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Trigger to keep denormalized data in sync
CREATE TRIGGER sync_user_name AFTER UPDATE ON users
BEGIN
    UPDATE posts SET user_name = new.name WHERE user_id = new.id;
END;
```

### Materialized Views (Manual)

```sql
-- Source tables
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    price REAL
);

-- Materialized aggregate
CREATE TABLE product_sales_summary (
    product_id INTEGER PRIMARY KEY,
    total_quantity INTEGER NOT NULL,
    total_revenue REAL NOT NULL,
    last_updated TEXT NOT NULL
);

-- Refresh procedure
CREATE TRIGGER refresh_summary AFTER INSERT ON order_items
BEGIN
    INSERT INTO product_sales_summary (product_id, total_quantity, total_revenue, last_updated)
    VALUES (new.product_id, new.quantity, new.quantity * new.price, datetime('now'))
    ON CONFLICT(product_id) DO UPDATE SET
        total_quantity = total_quantity + new.quantity,
        total_revenue = total_revenue + (new.quantity * new.price),
        last_updated = datetime('now');
END;
```

### Pagination Patterns

```sql
-- Offset pagination (simple but slow for large offsets)
SELECT * FROM posts
ORDER BY created_at DESC
LIMIT 20 OFFSET 100;

-- Keyset pagination (fast for any page)
SELECT * FROM posts
WHERE created_at < '2024-01-15T10:30:00'
ORDER BY created_at DESC
LIMIT 20;

-- With unique tie-breaker
SELECT * FROM posts
WHERE (created_at, id) < ('2024-01-15T10:30:00', 12345)
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Index for keyset pagination
CREATE INDEX idx_posts_pagination ON posts(created_at DESC, id DESC);
```

---

## Migration Patterns

### Safe Column Addition

```sql
-- Step 1: Add nullable column
ALTER TABLE users ADD COLUMN phone TEXT;

-- Step 2: Backfill data
UPDATE users SET phone = '' WHERE phone IS NULL;

-- Step 3: Add constraint (in separate migration)
-- SQLite doesn't support ADD CONSTRAINT, need to recreate table
CREATE TABLE users_new (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT ''
);
INSERT INTO users_new SELECT id, name, COALESCE(phone, '') FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
```

### Safe Table Rename

```sql
-- Step 1: Create new table
CREATE TABLE posts_new (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);

-- Step 2: Copy data
INSERT INTO posts_new SELECT id, title, content FROM articles;

-- Step 3: Drop old table
DROP TABLE articles;

-- Step 4: Rename new table
ALTER TABLE posts_new RENAME TO posts;
```
