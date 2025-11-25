# Graph Database Query Optimization

Comprehensive guide to optimizing graph database queries for performance, focusing on indexing strategies, query tuning, and performance analysis.

---

## Table of Contents

1. [Indexing Strategies](#indexing-strategies)
2. [Query Execution Plans](#query-execution-plans)
3. [Traversal Optimization](#traversal-optimization)
4. [Performance Patterns](#performance-patterns)
5. [Caching Strategies](#caching-strategies)
6. [Monitoring and Profiling](#monitoring-and-profiling)

---

## Indexing Strategies

### Node Property Indexes

**Purpose**: Speed up lookups by node properties (WHERE clauses)

```surreal
-- ✅ Create unique index for lookups
DEFINE INDEX user_email_idx ON TABLE user COLUMNS email UNIQUE;

-- ✅ Create regular index for filtering
DEFINE INDEX user_name_idx ON TABLE user COLUMNS name;
DEFINE INDEX post_created_idx ON TABLE post COLUMNS created_at;

-- ✅ Composite index for multi-column queries
DEFINE INDEX user_status_created ON TABLE user COLUMNS status, created_at;

-- Query that uses composite index
SELECT * FROM user WHERE status = 'active' ORDER BY created_at DESC;
```

**Index Types**:
- **Unique Index**: Ensures uniqueness, fastest for exact lookups
- **Regular Index**: Speeds up WHERE clauses and sorting
- **Composite Index**: Multiple columns, order matters
- **Full-Text Index**: Search capabilities for text fields

---

### Edge Relationship Indexes

**Purpose**: Speed up traversal filtering and edge property queries

```surreal
-- ✅ Index edge properties used in filters
DEFINE INDEX works_at_role_idx ON TABLE works_at COLUMNS role;
DEFINE INDEX works_at_start_idx ON TABLE works_at COLUMNS start_date;

-- ✅ Index edge endpoints for traversal optimization
DEFINE INDEX works_at_in_idx ON TABLE works_at COLUMNS in;
DEFINE INDEX works_at_out_idx ON TABLE works_at COLUMNS out;

-- Query that benefits from edge index
SELECT ->works_at[WHERE role = 'Engineer']->company.*
FROM person:alice;
```

**Best Practices**:
- Index properties used in WHERE clauses on edges
- Consider indexing edge endpoints (in/out) for bidirectional queries
- Index temporal fields (valid_from, valid_to) on temporal edges
- Index weight/score fields for weighted graph algorithms

---

### Full-Text Search Indexes

**Purpose**: Enable fast text search across content

```surreal
-- ✅ Full-text search index
DEFINE INDEX post_search_idx ON TABLE post
    COLUMNS title, content
    SEARCH ANALYZER simple BM25;

-- Use full-text search
SELECT * FROM post
WHERE title @@ 'database' OR content @@ 'optimization';

-- With ranking
SELECT *, search::score(1) AS relevance
FROM post
WHERE title @@ 'database'
ORDER BY relevance DESC;
```

**Full-Text Features**:
- **Analyzers**: simple, english, custom tokenization
- **BM25**: Best match ranking algorithm
- **Highlighting**: Show matched snippets
- **Phrase Search**: Exact phrase matching

---

### Index Maintenance

```surreal
-- View existing indexes
INFO FOR TABLE user;
INFO FOR TABLE works_at;

-- Remove unused indexes
REMOVE INDEX old_index ON TABLE user;

-- Rebuild index (if needed)
-- Database-specific, some auto-rebuild
```

**Index Guidelines**:
- Create indexes BEFORE loading large datasets
- Monitor index usage and remove unused ones
- Keep index count reasonable (too many slow writes)
- Update indexes when query patterns change
- Consider index size vs query performance trade-off

---

## Query Execution Plans

### Understanding Query Plans

**Purpose**: Identify performance bottlenecks in queries

```surreal
-- SurrealDB: Check query performance
-- (Exact syntax varies by version)

-- Neo4j: Use EXPLAIN and PROFILE
EXPLAIN
MATCH (p:Person {email: 'alice@example.com'})
RETURN p;

PROFILE
MATCH (p:Person)-[:FOLLOWS*1..3]->(friend:Person)
RETURN friend.name;
```

**What to Look For**:
- **Full Table Scans**: Missing indexes (NodeByLabelScan)
- **Index Usage**: Confirms index is used (NodeIndexSeek)
- **Expand Operations**: Graph traversals, check cardinality
- **Cartesian Products**: Join without relationships (very slow!)
- **Row Estimates**: Compare estimated vs actual rows

---

### Query Plan Example (Neo4j Cypher)

```cypher
// ❌ BAD: No index on email (full scan)
PROFILE
MATCH (p:Person)
WHERE p.email = 'alice@example.com'
RETURN p;
// Shows: NodeByLabelScan (slow!)

// Create index
CREATE INDEX person_email FOR (p:Person) ON (p.email);

// ✅ GOOD: Uses index
PROFILE
MATCH (p:Person)
WHERE p.email = 'alice@example.com'
RETURN p;
// Shows: NodeIndexSeek (fast!)
```

---

### Optimizing Based on Query Plans

**Patterns to Fix**:

1. **Full Table Scan** → Create index on filtered properties
2. **High DB Hits** → Reduce traversal depth or add LIMIT
3. **Cartesian Product** → Add relationship between entities
4. **Multiple Label Scans** → Use more specific labels
5. **Eager Operations** → Refactor to use lazy evaluation

---

## Traversal Optimization

### Depth Limiting

**Purpose**: Prevent exponential growth in graph traversals

```surreal
-- ❌ DANGEROUS: Unbounded traversal
SELECT ->follows->person.* FROM person:alice;
-- Could traverse millions of nodes!

-- ✅ SAFE: Limited depth
SELECT ->follows[..2]->person.* FROM person:alice;
-- Maximum 2 hops

-- ✅ SAFE: Range with limit
SELECT ->follows[1..3]->person.* FROM person:alice LIMIT 100;
-- 1-3 hops, max 100 results
```

**Depth Guidelines**:
- **Social networks**: 2-3 hops typical, 5 max
- **Hierarchies**: Match org depth (usually < 10)
- **Recommendations**: 2-4 hops sufficient
- **Fraud detection**: 3-5 hops for pattern matching

**Performance Impact**:
- Depth 1: O(n) - linear growth
- Depth 2: O(n²) - quadratic growth
- Depth 3: O(n³) - cubic growth
- Always use smallest depth needed for use case

---

### Directional Traversals

**Purpose**: Optimize by traversing in primary direction

```surreal
-- Schema design: Model relationships in query direction

-- ❌ SLOW: Traversing against primary direction
-- If most queries get posts by author
DEFINE TABLE authored SCHEMAFULL;
DEFINE FIELD in ON TABLE authored TYPE record<post>;   -- Wrong direction
DEFINE FIELD out ON TABLE authored TYPE record<person>;

SELECT <-authored<-post.* FROM person:alice;  -- Backward traversal

-- ✅ FAST: Primary direction matches query pattern
DEFINE TABLE authored SCHEMAFULL;
DEFINE FIELD in ON TABLE authored TYPE record<person>;  -- Correct
DEFINE FIELD out ON TABLE authored TYPE record<post>;

SELECT ->authored->post.* FROM person:alice;  -- Forward traversal
```

**Design Rule**: Model edge direction to match most common queries

---

### Filtering Early

**Purpose**: Reduce data volume before traversal

```surreal
-- ❌ SLOW: Filter after traversal
SELECT ->follows->person.*
FROM person
WHERE name = 'Alice';
-- Traverses from ALL persons first!

-- ✅ FAST: Filter before traversal
SELECT ->follows->person.*
FROM person
WHERE name = 'Alice';
-- Filters to one person first

-- ✅ FAST: Filter at each hop
SELECT ->follows[WHERE active = true]->person[WHERE verified = true].*
FROM person:alice;
-- Reduces data at each step
```

**Optimization Strategy**: Push filters as close to data source as possible

---

### Avoiding Cartesian Products

**Purpose**: Prevent exponential query expansion

```surreal
-- ❌ VERY SLOW: Cartesian product
SELECT * FROM person, company;
-- Creates person × company rows!

-- ✅ FAST: Relationship-based query
SELECT
    person.*,
    ->works_at->company.* AS employers
FROM person;

-- ❌ SLOW: Multiple unrelated traversals
SELECT
    ->follows->person.*,
    ->likes->post.*
FROM person:alice;
-- Can create Cartesian product

-- ✅ FAST: Separate queries or use proper joins
SELECT ->follows->person.* FROM person:alice;
SELECT ->likes->post.* FROM person:alice;
```

---

## Performance Patterns

### Pattern 1: Batch Operations

```surreal
-- ❌ SLOW: Individual creates
CREATE person SET name = 'Alice';
CREATE person SET name = 'Bob';
CREATE person SET name = 'Charlie';

-- ✅ FAST: Batch insert
INSERT INTO person [
    { name: 'Alice' },
    { name: 'Bob' },
    { name: 'Charlie' }
];

-- ✅ FAST: Bulk relationship creation
LET $users = (SELECT id FROM person WHERE status = 'active');
LET $group = group:premium;

FOR $user IN $users {
    RELATE $user->member_of->$group
};
```

---

### Pattern 2: Pagination and Cursors

```surreal
-- ✅ Offset-based pagination (works for small offsets)
SELECT * FROM post
ORDER BY created_at DESC
START 0 LIMIT 20;

-- Next page
SELECT * FROM post
ORDER BY created_at DESC
START 20 LIMIT 20;

-- ✅ Cursor-based pagination (better for large datasets)
-- First page
SELECT * FROM post
WHERE created_at < time::now()
ORDER BY created_at DESC
LIMIT 20;

-- Next page (use last created_at from previous page)
SELECT * FROM post
WHERE created_at < d'2024-01-01T12:00:00Z'
ORDER BY created_at DESC
LIMIT 20;
```

**Pagination Guidelines**:
- Use LIMIT always to cap result size
- Cursor-based better for deep pagination
- Include sorting for consistent results
- Consider total count separately if needed

---

### Pattern 3: Avoiding N+1 Queries

```surreal
-- ❌ N+1 ANTI-PATTERN
-- First query (1)
SELECT * FROM person;

-- Then for each person (N queries)
FOR person IN persons {
    SELECT * FROM post WHERE author = person.id;
}

-- ✅ SOLUTION: Graph traversal
SELECT
    *,
    ->authored->post.* AS posts
FROM person;

-- ✅ SOLUTION: Use FETCH
SELECT * FROM person FETCH ->authored->post;

-- ✅ For complex data
SELECT
    name,
    ->authored->post.title AS post_titles,
    ->follows->person.name AS following,
    <-follows<-person.name AS followers
FROM person;
```

---

### Pattern 4: Selective Property Loading

```surreal
-- ❌ Load all properties (wastes bandwidth)
SELECT * FROM person;

-- ✅ Select only needed properties
SELECT id, name, email FROM person;

-- ✅ For traversals, be selective
SELECT
    name,
    ->authored->post.{title, created_at} AS posts
FROM person;

-- ❌ DON'T load large fields unnecessarily
SELECT *, profile_image FROM person;  -- profile_image might be huge!

-- ✅ Load large fields only when needed
SELECT id, name FROM person;
-- Later, if needed:
SELECT profile_image FROM person:alice;
```

---

### Pattern 5: Query Result Caching

```javascript
// Application-level caching
import { Cache } from 'node-cache';

const cache = new Cache({ stdTTL: 300 }); // 5 min TTL

async function getPersonWithPosts(personId) {
    const cacheKey = `person:${personId}:posts`;

    // Check cache first
    let result = cache.get(cacheKey);
    if (result) {
        return result;
    }

    // Query database
    result = await db.query(
        'SELECT *, ->authored->post.* FROM $person',
        { person: personId }
    );

    // Cache result
    cache.set(cacheKey, result);
    return result;
}

// Invalidate on write
async function createPost(personId, postData) {
    await db.query('CREATE post CONTENT $data', { data: postData });

    // Invalidate cache
    cache.del(`person:${personId}:posts`);
}
```

**Caching Strategies**:
- **Application cache**: Redis, Memcached for frequent reads
- **Query result cache**: Cache expensive traversals
- **Materialized views**: Pre-compute common aggregations
- **Cache invalidation**: Invalidate on writes to related data

---

## Caching Strategies

### 1. Application-Level Caching

```javascript
// Redis caching for graph queries
import Redis from 'ioredis';

const redis = new Redis();

async function getRecommendations(userId) {
    const cacheKey = `recommendations:${userId}`;

    // Try cache
    const cached = await redis.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    // Expensive graph query
    const results = await db.query(`
        SELECT ->follows[..2]->person->likes->post.*
        FROM person:${userId}
    `);

    // Cache for 1 hour
    await redis.setex(cacheKey, 3600, JSON.stringify(results));
    return results;
}
```

---

### 2. Materialized Paths for Hierarchies

```surreal
-- Add materialized path to avoid recursive queries
DEFINE TABLE category SCHEMAFULL;
DEFINE FIELD name ON TABLE category TYPE string;
DEFINE FIELD path ON TABLE category TYPE string;
DEFINE FIELD depth ON TABLE category TYPE int;

-- Create with paths
CREATE category:electronics SET
    name = 'Electronics',
    path = '/electronics',
    depth = 1;

CREATE category:laptops SET
    name = 'Laptops',
    path = '/electronics/laptops',
    depth = 2;

CREATE category:gaming_laptops SET
    name = 'Gaming Laptops',
    path = '/electronics/laptops/gaming',
    depth = 3;

-- ✅ Fast ancestor query (no recursion!)
SELECT * FROM category
WHERE '/electronics/laptops/gaming' LIKE path + '%'
ORDER BY depth;

-- ✅ Fast descendant query
SELECT * FROM category
WHERE path LIKE '/electronics%';
```

---

### 3. Computed Properties

```surreal
-- Cache expensive computations
DEFINE FIELD follower_count ON TABLE person TYPE int;
DEFINE FIELD post_count ON TABLE person TYPE int;

-- Update counters instead of counting
-- Increment on follow
RELATE person:alice->follows->person:bob;
UPDATE person:bob SET follower_count += 1;

-- Query cached count (fast!)
SELECT name, follower_count FROM person ORDER BY follower_count DESC;

-- vs. expensive count query
SELECT name, count(<-follows<-person) AS followers
FROM person
GROUP BY name;
```

---

## Monitoring and Profiling

### 1. Query Performance Monitoring

```javascript
// Log slow queries
async function executeQuery(query, params) {
    const start = Date.now();
    const result = await db.query(query, params);
    const duration = Date.now() - start;

    // Alert on slow queries
    if (duration > 1000) {
        console.warn('Slow query detected:', {
            query,
            duration,
            timestamp: new Date()
        });
    }

    return result;
}
```

---

### 2. Database Metrics to Track

**Key Performance Indicators**:
- **Query latency**: p50, p95, p99 percentiles
- **Traversal depth**: Average and max hops per query
- **Index hit rate**: % of queries using indexes
- **Cache hit rate**: % of requests served from cache
- **Connection pool**: Active connections, wait time
- **Memory usage**: Graph in-memory size, GC pressure
- **Disk I/O**: Read/write operations for persistence

---

### 3. SurrealDB Performance Monitoring

```javascript
// Monitor with metrics
import { metrics } from 'surrealdb-metrics';

// Track query performance
const queryTimer = metrics.histogram('query_duration', {
    help: 'Query execution time',
    labelNames: ['query_type']
});

async function monitoredQuery(query, params, type) {
    const end = queryTimer.startTimer({ query_type: type });
    try {
        return await db.query(query, params);
    } finally {
        end();
    }
}
```

---

### 4. Performance Testing

```javascript
// Benchmark graph queries
import { performance } from 'perf_hooks';

async function benchmarkTraversal() {
    const depths = [1, 2, 3, 4, 5];

    for (const depth of depths) {
        const start = performance.now();

        await db.query(`
            SELECT ->follows[..${depth}]->person.*
            FROM person:alice
        `);

        const duration = performance.now() - start;
        console.log(`Depth ${depth}: ${duration.toFixed(2)}ms`);
    }
}

// Output example:
// Depth 1: 12.34ms
// Depth 2: 45.67ms
// Depth 3: 234.56ms  ← Watch for exponential growth
// Depth 4: 1234.56ms
```

---

## Performance Optimization Checklist

### Schema Design
- [ ] Indexes created on all WHERE clause properties
- [ ] Composite indexes for multi-column filters
- [ ] Edge indexes on relationship properties
- [ ] Full-text indexes for search features
- [ ] Relationship direction matches query patterns
- [ ] Materialized paths for deep hierarchies

### Query Design
- [ ] All traversals have depth limits
- [ ] Filters applied before traversals
- [ ] Selective property loading (not SELECT *)
- [ ] Pagination implemented for large results
- [ ] N+1 patterns eliminated with traversals
- [ ] Cartesian products avoided

### Performance Monitoring
- [ ] Query execution plans reviewed
- [ ] Slow query logging enabled
- [ ] Performance metrics tracked
- [ ] Cache hit rates monitored
- [ ] Index usage analyzed
- [ ] Alerts set for slow queries

### Caching
- [ ] Application-level cache for frequent queries
- [ ] Computed properties for expensive aggregations
- [ ] Query result caching with invalidation
- [ ] Connection pooling configured
- [ ] Cache expiration policies defined

---

## Common Performance Issues and Solutions

### Issue: Slow traversal queries

**Symptoms**: Graph queries taking > 1 second
**Solutions**:
1. Add depth limits: `->follows[..3]`
2. Create indexes on edge properties
3. Filter early in traversal chain
4. Add LIMIT to cap results
5. Cache frequent traversal results

---

### Issue: High memory usage

**Symptoms**: Database consuming excessive RAM
**Solutions**:
1. Reduce traversal depth limits
2. Implement pagination (LIMIT/OFFSET)
3. Use selective property loading
4. Clear unused indexes
5. Implement result streaming for large datasets

---

### Issue: Slow writes

**Symptoms**: INSERT/UPDATE operations slow
**Solutions**:
1. Reduce number of indexes (only index queried fields)
2. Batch operations instead of individual writes
3. Use async/background index building
4. Disable indexes during bulk loads, rebuild after
5. Check for write locks/contention

---

### Issue: Index not being used

**Symptoms**: Query plan shows full table scan
**Solutions**:
1. Check index exists: `INFO FOR TABLE`
2. Ensure query matches index definition
3. Use exact match on indexed column
4. Avoid functions on indexed columns in WHERE
5. Check composite index column order

---

## Best Practices Summary

1. **Index Wisely**: Index queried properties, but don't over-index
2. **Limit Depth**: Always bound graph traversals
3. **Filter Early**: Push WHERE clauses close to data source
4. **Avoid N+1**: Use graph traversal, not loops
5. **Monitor**: Track query performance and slow queries
6. **Cache**: Use application cache for expensive queries
7. **Paginate**: Never return unbounded result sets
8. **Profile**: Use explain plans to optimize queries
9. **Batch**: Bulk operations faster than individual writes
10. **Evolve**: Monitor and optimize as query patterns change

Graph query performance is about understanding your data's connections and optimizing the paths you traverse through them.
