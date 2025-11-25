# Graph Database Modeling Guide

Comprehensive guide to graph data modeling, covering entity-relationship mapping, schema design patterns, and best practices for designing effective graph schemas.

---

## Table of Contents

1. [Graph Modeling Fundamentals](#graph-modeling-fundamentals)
2. [Entity-Relationship Mapping](#entity-relationship-mapping)
3. [Schema Design Patterns](#schema-design-patterns)
4. [Relationship Patterns](#relationship-patterns)
5. [Denormalization Strategies](#denormalization-strategies)
6. [Advanced Patterns](#advanced-patterns)
7. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)

---

## Graph Modeling Fundamentals

### Core Concepts

**Nodes/Vertices**: Represent entities in your domain
- People, places, products, events
- Contains properties (attributes)
- Labeled by type/category

**Edges/Relationships**: Represent connections between entities
- Typed (FOLLOWS, WORKS_AT, LIKES)
- Directional (from → to)
- Can have properties (metadata)

**Properties**: Key-value pairs on nodes or edges
- Store entity attributes
- Enable filtering and sorting
- Can be simple values or complex structures

---

### Graph vs Relational Thinking

**Relational Mindset**:
```sql
-- Tables with foreign keys
CREATE TABLE person (id, name, email);
CREATE TABLE company (id, name, industry);
CREATE TABLE employment (
    person_id REFERENCES person(id),
    company_id REFERENCES company(id),
    role VARCHAR,
    start_date DATE
);

-- Requires JOINs to traverse
SELECT p.name, c.name, e.role
FROM person p
JOIN employment e ON p.id = e.person_id
JOIN company c ON c.id = e.company_id;
```

**Graph Mindset**:
```surreal
-- Entities as nodes, relationships as edges
DEFINE TABLE person SCHEMAFULL;
DEFINE TABLE company SCHEMAFULL;

DEFINE TABLE works_at SCHEMAFULL;
DEFINE FIELD in ON TABLE works_at TYPE record<person>;
DEFINE FIELD out ON TABLE works_at TYPE record<company>;
DEFINE FIELD role ON TABLE works_at TYPE string;
DEFINE FIELD start_date ON TABLE works_at TYPE datetime;

-- Natural traversal
SELECT
    name,
    ->works_at->company.name AS company_name,
    ->works_at.role AS role
FROM person:alice;
```

**Key Differences**:
- Relationships are first-class citizens in graphs
- Traversal is natural, not JOIN-based
- Schema evolves more easily
- Focus on connections, not tables

---

### Model Queries First

**Golden Rule**: Design your graph schema based on your queries, not your entities.

**Process**:
1. List your core queries (what questions will you ask?)
2. Identify entities and relationships in those queries
3. Design schema to optimize those traversal paths
4. Set relationship directions based on query patterns

**Example**:
```
Query 1: "Get all posts by a user"
Query 2: "Get all followers of a user"
Query 3: "Get posts liked by people I follow"

→ Design:
- person ->authored-> post (forward: user to posts)
- person ->follows-> person (forward: user to friends)
- person ->likes-> post (forward: user to likes)
```

---

## Entity-Relationship Mapping

### Mapping Entities to Nodes

**Rule**: Entities with independent lifecycle become nodes

```surreal
-- ✅ Independent entities → Nodes
DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD name ON TABLE person TYPE string;
DEFINE FIELD email ON TABLE person TYPE string;
DEFINE FIELD birth_date ON TABLE person TYPE datetime;

DEFINE TABLE company SCHEMAFULL;
DEFINE FIELD name ON TABLE company TYPE string;
DEFINE FIELD industry ON TABLE company TYPE string;
DEFINE FIELD founded ON TABLE company TYPE datetime;

DEFINE TABLE post SCHEMAFULL;
DEFINE FIELD title ON TABLE post TYPE string;
DEFINE FIELD content ON TABLE post TYPE string;
DEFINE FIELD published_at ON TABLE post TYPE datetime;
```

**When to use nodes**:
- Entity has independent existence
- Entity participates in multiple relationships
- Entity has many properties
- Entity is queried independently

---

### Mapping Relationships to Edges

**Rule**: Connections between entities become edges

```surreal
-- ✅ Person works at company
DEFINE TABLE works_at SCHEMAFULL;
DEFINE FIELD in ON TABLE works_at TYPE record<person>;
DEFINE FIELD out ON TABLE works_at TYPE record<company>;
DEFINE FIELD role ON TABLE works_at TYPE string;
DEFINE FIELD start_date ON TABLE works_at TYPE datetime;
DEFINE FIELD end_date ON TABLE works_at TYPE option<datetime>;

-- ✅ Person follows person
DEFINE TABLE follows SCHEMAFULL;
DEFINE FIELD in ON TABLE follows TYPE record<person>;
DEFINE FIELD out ON TABLE follows TYPE record<person>;
DEFINE FIELD since ON TABLE follows TYPE datetime;

-- ✅ Person authored post
DEFINE TABLE authored SCHEMAFULL;
DEFINE FIELD in ON TABLE authored TYPE record<person>;
DEFINE FIELD out ON TABLE authored TYPE record<post>;
DEFINE FIELD published_at ON TABLE authored TYPE datetime;
```

**When to use edges**:
- Represents connection between entities
- Connection has metadata (role, date, weight)
- Many-to-many relationships
- Needs to be traversed in queries

---

### Properties: Node vs Edge

**Node Properties**: Attributes of the entity itself

```surreal
-- ✅ Node properties: intrinsic to entity
DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD name ON TABLE person TYPE string;        -- Person's name
DEFINE FIELD email ON TABLE person TYPE string;       -- Person's email
DEFINE FIELD birth_date ON TABLE person TYPE datetime; -- Person's birth date
DEFINE FIELD bio ON TABLE person TYPE string;         -- Person's bio
```

**Edge Properties**: Attributes of the relationship

```surreal
-- ✅ Edge properties: describe the relationship
DEFINE TABLE works_at SCHEMAFULL;
DEFINE FIELD in ON TABLE works_at TYPE record<person>;
DEFINE FIELD out ON TABLE works_at TYPE record<company>;
DEFINE FIELD role ON TABLE works_at TYPE string;          -- Role in relationship
DEFINE FIELD start_date ON TABLE works_at TYPE datetime;  -- When relationship started
DEFINE FIELD is_current ON TABLE works_at TYPE bool;      -- Relationship status
```

**Decision Rule**:
- If property describes the entity → Node property
- If property describes the connection → Edge property
- If property only exists in context of relationship → Edge property

---

## Schema Design Patterns

### Pattern 1: One-to-Many Relationships

**Example**: Author writes many posts

```surreal
-- Option A: Direct reference (embedded)
DEFINE TABLE post SCHEMAFULL;
DEFINE FIELD title ON TABLE post TYPE string;
DEFINE FIELD content ON TABLE post TYPE string;
DEFINE FIELD author ON TABLE post TYPE record<person>;

-- Query posts by author
SELECT * FROM post WHERE author = person:alice;

-- Option B: Edge relationship (traversable)
DEFINE TABLE authored SCHEMAFULL;
DEFINE FIELD in ON TABLE authored TYPE record<person>;
DEFINE FIELD out ON TABLE authored TYPE record<post>;

-- Query posts by author
SELECT ->authored->post.* FROM person:alice;
```

**When to use each**:
- **Direct reference**: Simple lookup, one direction only
- **Edge relationship**: Need bidirectional queries, metadata on relationship

---

### Pattern 2: Many-to-Many Relationships

**Example**: Users follow users, tags on posts

```surreal
-- ✅ Always use edge relationship for many-to-many
DEFINE TABLE follows SCHEMAFULL;
DEFINE FIELD in ON TABLE follows TYPE record<person>;
DEFINE FIELD out ON TABLE follows TYPE record<person>;
DEFINE FIELD created_at ON TABLE follows TYPE datetime;

-- Create relationships
RELATE person:alice->follows->person:bob;
RELATE person:alice->follows->person:charlie;
RELATE person:bob->follows->person:alice;

-- Query: Who does Alice follow?
SELECT ->follows->person.* FROM person:alice;

-- Query: Who follows Alice?
SELECT <-follows<-person.* FROM person:alice;

-- ❌ DON'T: Embed arrays for many-to-many
DEFINE FIELD followers ON TABLE person TYPE array<record<person>>;
-- Hard to query, maintain, and inefficient
```

**Many-to-Many Best Practices**:
- Always use edge relationships
- Add properties to edge (timestamp, metadata)
- Consider bidirectional queries in design
- Index edge properties used in filters

---

### Pattern 3: Hierarchical Data

**Example**: Organization structure, category trees

```surreal
-- Tree structure: Each node has one parent
DEFINE TABLE org_unit SCHEMAFULL;
DEFINE FIELD name ON TABLE org_unit TYPE string;
DEFINE FIELD level ON TABLE org_unit TYPE int;

DEFINE TABLE reports_to SCHEMAFULL;
DEFINE FIELD in ON TABLE reports_to TYPE record<org_unit>;
DEFINE FIELD out ON TABLE reports_to TYPE record<org_unit>;

-- Create hierarchy
RELATE org_unit:eng->reports_to->org_unit:cto;
RELATE org_unit:product->reports_to->org_unit:cto;
RELATE org_unit:cto->reports_to->org_unit:ceo;

-- ✅ Add materialized path for performance
DEFINE FIELD path ON TABLE org_unit TYPE string;
DEFINE FIELD depth ON TABLE org_unit TYPE int;

UPDATE org_unit:eng SET path = '/ceo/cto/eng', depth = 3;
UPDATE org_unit:cto SET path = '/ceo/cto', depth = 2;

-- Fast ancestor query
SELECT * FROM org_unit WHERE '/ceo/cto/eng' LIKE path + '%';

-- Fast descendant query
SELECT * FROM org_unit WHERE path LIKE '/ceo%';
```

**Hierarchy Strategies**:
- **Graph edges**: Natural, flexible, requires traversal
- **Materialized path**: Fast queries, requires maintenance
- **Nested sets**: Complex updates, fast tree operations
- **Closure table**: Flexible, more storage

---

### Pattern 4: Temporal Relationships

**Example**: Employment history, relationship validity

```surreal
-- Time-based relationships
DEFINE TABLE employment SCHEMAFULL;
DEFINE FIELD in ON TABLE employment TYPE record<person>;
DEFINE FIELD out ON TABLE employment TYPE record<company>;
DEFINE FIELD role ON TABLE employment TYPE string;
DEFINE FIELD valid_from ON TABLE employment TYPE datetime;
DEFINE FIELD valid_to ON TABLE employment TYPE option<datetime>;
DEFINE FIELD is_current ON TABLE employment TYPE bool;

-- Create temporal relationship
RELATE person:alice->employment->company:acme SET
    role = 'Engineer',
    valid_from = d'2020-01-01',
    valid_to = d'2023-12-31',
    is_current = false;

RELATE person:alice->employment->company:techcorp SET
    role = 'Senior Engineer',
    valid_from = d'2024-01-01',
    valid_to = NONE,
    is_current = true;

-- Query current employment
SELECT ->employment[WHERE is_current = true]->company.*
FROM person:alice;

-- Query employment at specific time
LET $date = d'2022-06-01';
SELECT ->employment[
    WHERE valid_from <= $date
    AND (valid_to = NONE OR valid_to >= $date)
]->company.*
FROM person:alice;

-- ✅ Index temporal fields
DEFINE INDEX emp_valid_from ON TABLE employment COLUMNS valid_from;
DEFINE INDEX emp_valid_to ON TABLE employment COLUMNS valid_to;
DEFINE INDEX emp_current ON TABLE employment COLUMNS is_current;
```

**Temporal Pattern Benefits**:
- Track history and changes over time
- Query state at any point in time
- Audit trails and compliance
- Trend analysis

---

### Pattern 5: Weighted Relationships

**Example**: Social strength, recommendation scores

```surreal
-- Weighted edges for algorithms
DEFINE TABLE friendship SCHEMAFULL;
DEFINE FIELD in ON TABLE friendship TYPE record<person>;
DEFINE FIELD out ON TABLE friendship TYPE record<person>;
DEFINE FIELD strength ON TABLE friendship TYPE float;
DEFINE FIELD interaction_count ON TABLE friendship TYPE int;
DEFINE FIELD last_interaction ON TABLE friendship TYPE datetime;

-- Create weighted relationships
RELATE person:alice->friendship->person:bob SET
    strength = 0.85,
    interaction_count = 127,
    last_interaction = time::now();

-- Update weights based on interactions
UPDATE friendship
SET
    interaction_count += 1,
    strength = strength * 0.9 + 0.1,  -- Decay + boost
    last_interaction = time::now()
WHERE in = person:alice AND out = person:bob;

-- Query strong relationships
SELECT ->friendship[WHERE strength > 0.7]->person.*
FROM person:alice
ORDER BY ->friendship.strength DESC;
```

**Weight Use Cases**:
- Social network strength
- Recommendation scoring
- Shortest weighted path
- PageRank-style algorithms
- Fraud detection patterns

---

## Relationship Patterns

### Bidirectional vs Unidirectional

**Unidirectional** (one direction only):
```surreal
-- User follows another user (not necessarily mutual)
DEFINE TABLE follows SCHEMAFULL;
DEFINE FIELD in ON TABLE follows TYPE record<person>;
DEFINE FIELD out ON TABLE follows TYPE record<person>;

RELATE person:alice->follows->person:bob;
-- Alice follows Bob, but Bob might not follow Alice

-- Forward query
SELECT ->follows->person.* FROM person:alice;

-- Reverse query (slower if not indexed)
SELECT <-follows<-person.* FROM person:bob;
```

**Bidirectional** (symmetric relationship):
```surreal
-- Friendship (mutual relationship)
-- Option 1: Create both directions
RELATE person:alice->friendship->person:bob;
RELATE person:bob->friendship->person:alice;

-- Option 2: Query in both directions
SELECT ->friendship->person.*, <-friendship<-person.*
FROM person:alice;

-- Option 3: Undirected edge flag (database-specific)
DEFINE FIELD undirected ON TABLE friendship TYPE bool DEFAULT true;
```

**When to use**:
- **Unidirectional**: Twitter follows, likes, authored
- **Bidirectional**: Facebook friends, collaborators, siblings

---

### Self-Referencing Relationships

**Example**: Person follows person, category contains category

```surreal
-- Self-referencing: same entity type on both sides
DEFINE TABLE follows SCHEMAFULL;
DEFINE FIELD in ON TABLE follows TYPE record<person>;
DEFINE FIELD out ON TABLE follows TYPE record<person>;

-- Person follows person
RELATE person:alice->follows->person:bob;
RELATE person:bob->follows->person:charlie;
RELATE person:charlie->follows->person:alice;

-- ✅ Handle cycles with depth limits
SELECT ->follows[..3]->person.* FROM person:alice;

-- ❌ DANGEROUS: Unlimited traversal can loop forever
-- SELECT ->follows->person.* FROM person:alice;
```

**Self-Reference Guidelines**:
- Always set depth limits to prevent infinite loops
- Consider cycle detection in application logic
- Use breadth-first search for shortest paths
- Monitor query performance carefully

---

### Typed Relationships

**Example**: Different relationship types between same entities

```surreal
-- Multiple relationship types
DEFINE TABLE follows SCHEMAFULL;
DEFINE TABLE blocked SCHEMAFULL;
DEFINE TABLE muted SCHEMAFULL;

-- Person can have different relationships with another person
RELATE person:alice->follows->person:bob;
RELATE person:alice->muted->person:charlie;
RELATE person:alice->blocked->person:dave;

-- Query specific relationship type
SELECT ->follows->person.* FROM person:alice;
SELECT ->blocked->person.* FROM person:alice;

-- Query multiple types
SELECT
    ->follows->person.* AS following,
    ->blocked->person.* AS blocked,
    ->muted->person.* AS muted
FROM person:alice;
```

**Typed Relationship Benefits**:
- Clear semantics
- Different properties per type
- Easier to query and maintain
- Better than generic "related_to" edge

---

## Denormalization Strategies

### When to Embed vs Link

**Embed (denormalize)**: Copy data into node
```surreal
-- ✅ Embed when:
-- - Data is small
-- - Rarely changes
-- - Always queried together
-- - One-to-one or simple one-to-many

DEFINE TABLE post SCHEMAFULL;
DEFINE FIELD title ON TABLE post TYPE string;
DEFINE FIELD content ON TABLE post TYPE string;
DEFINE FIELD author_name ON TABLE post TYPE string;    -- Embedded
DEFINE FIELD author_email ON TABLE post TYPE string;   -- Embedded
DEFINE FIELD tags ON TABLE post TYPE array<string>;    -- Embedded array

-- Fast query: No traversal needed
SELECT * FROM post WHERE author_email = 'alice@example.com';
```

**Link (normalize)**: Reference via relationship
```surreal
-- ✅ Link when:
-- - Entity has independent lifecycle
-- - Data changes frequently
-- - Many-to-many relationships
-- - Need bidirectional queries

DEFINE TABLE post SCHEMAFULL;
DEFINE FIELD title ON TABLE post TYPE string;
DEFINE FIELD content ON TABLE post TYPE string;
-- Link to author
DEFINE TABLE authored SCHEMAFULL;
DEFINE FIELD in ON TABLE authored TYPE record<person>;
DEFINE FIELD out ON TABLE authored TYPE record<post>;

-- Query requires traversal
SELECT
    title,
    <-authored<-person.name AS author_name
FROM post:123;
```

---

### Embedding Complex Data

**Example**: Document-style data within nodes

```surreal
-- ✅ Embed complex objects for cohesive data
DEFINE TABLE product SCHEMAFULL;
DEFINE FIELD name ON TABLE product TYPE string;
DEFINE FIELD price ON TABLE product TYPE decimal;

-- Embed structured data
DEFINE FIELD specifications ON TABLE product TYPE object;
DEFINE FIELD specifications.dimensions ON TABLE product TYPE object;
DEFINE FIELD specifications.dimensions.width ON TABLE product TYPE float;
DEFINE FIELD specifications.dimensions.height ON TABLE product TYPE float;
DEFINE FIELD specifications.dimensions.depth ON TABLE product TYPE float;

DEFINE FIELD specifications.weight ON TABLE product TYPE float;

DEFINE FIELD images ON TABLE product TYPE array<object>;

CREATE product:laptop CONTENT {
    name: "Gaming Laptop",
    price: 1299.99,
    specifications: {
        dimensions: {
            width: 15.6,
            height: 0.9,
            depth: 10.5
        },
        weight: 4.5,
        cpu: "Intel i7",
        ram: "32GB"
    },
    images: [
        { url: "image1.jpg", alt: "Front view" },
        { url: "image2.jpg", alt: "Side view" }
    ]
};
```

**Embedding Guidelines**:
- Embed when data is cohesive unit
- Limit nesting depth (2-3 levels max)
- Avoid embedding large arrays
- Don't embed frequently updated data

---

### Caching Computed Values

**Example**: Denormalize counts and aggregations

```surreal
-- ✅ Cache expensive computations
DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD name ON TABLE person TYPE string;
DEFINE FIELD follower_count ON TABLE person TYPE int DEFAULT 0;
DEFINE FIELD following_count ON TABLE person TYPE int DEFAULT 0;
DEFINE FIELD post_count ON TABLE person TYPE int DEFAULT 0;

-- Update denormalized counts on writes
-- When someone follows Alice
RELATE person:bob->follows->person:alice;
UPDATE person:alice SET follower_count += 1;
UPDATE person:bob SET following_count += 1;

-- Fast query: No counting needed!
SELECT name, follower_count, following_count FROM person
ORDER BY follower_count DESC LIMIT 10;

-- ❌ SLOW: Count on every query
SELECT name, count(<-follows) AS followers
FROM person
ORDER BY followers DESC;
```

**Caching Trade-offs**:
- **Pro**: Much faster queries
- **Pro**: Reduced computational load
- **Con**: Must maintain consistency
- **Con**: Writes are more complex

---

## Advanced Patterns

### Pattern 1: Super Nodes (High-Degree Nodes)

**Problem**: Nodes with thousands of relationships (celebrities, popular tags)

```surreal
-- ✅ Solutions for super nodes:

-- 1. Pagination
SELECT ->follows[..1]->person.*
FROM person:celebrity
LIMIT 100;

-- 2. Sampling
SELECT ->follows->person.* FROM person:celebrity
ORDER BY rand() LIMIT 20;

-- 3. Separate node types
DEFINE TABLE celebrity SCHEMAFULL;
DEFINE TABLE regular_person SCHEMAFULL;
-- Different query patterns for each

-- 4. Fan-out prevention
DEFINE FIELD follower_count ON TABLE person TYPE int;
-- Block follows if follower_count > 10000

-- 5. Intermediate nodes
DEFINE TABLE follower_batch SCHEMAFULL;
-- person -> follower_batch -> [100 persons]
```

---

### Pattern 2: Multi-Tenant Graphs

**Pattern**: Separate data by tenant/organization

```surreal
-- Add tenant/org to every node
DEFINE TABLE person SCHEMAFULL;
DEFINE FIELD name ON TABLE person TYPE string;
DEFINE FIELD org_id ON TABLE person TYPE record<organization>;

DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD name ON TABLE organization TYPE string;

-- ✅ Index tenant field
DEFINE INDEX person_org_idx ON TABLE person COLUMNS org_id;

-- Always filter by tenant
SELECT * FROM person WHERE org_id = organization:acme;

-- ✅ Row-level security
DEFINE TABLE person SCHEMAFULL
    PERMISSIONS
        FOR select WHERE org_id = $auth.org_id;
```

---

### Pattern 3: Versioned Graphs

**Pattern**: Track changes and history

```surreal
-- Version tracking
DEFINE TABLE document SCHEMAFULL;
DEFINE FIELD title ON TABLE document TYPE string;
DEFINE FIELD content ON TABLE document TYPE string;
DEFINE FIELD version ON TABLE document TYPE int;
DEFINE FIELD is_current ON TABLE document TYPE bool;

DEFINE TABLE version_of SCHEMAFULL;
DEFINE FIELD in ON TABLE version_of TYPE record<document>;
DEFINE FIELD out ON TABLE version_of TYPE record<document>;
DEFINE FIELD changed_at ON TABLE version_of TYPE datetime;
DEFINE FIELD changed_by ON TABLE version_of TYPE record<person>;

-- Create new version
CREATE document:doc123_v2 CONTENT {
    title: "Updated Title",
    content: "New content",
    version: 2,
    is_current: true
};

UPDATE document:doc123_v1 SET is_current = false;

RELATE document:doc123_v2->version_of->document:doc123_v1;

-- Query current version
SELECT * FROM document WHERE id = 'doc123' AND is_current = true;

-- Query version history
SELECT <-version_of<-document.* FROM document:doc123_v1;
```

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Using Nodes as Properties

❌ **DON'T**:
```surreal
-- Creating a node for every property value
CREATE email:alice@example.com;
RELATE person:alice->has_email->email:alice@example.com;
```

✅ **DO**:
```surreal
-- Email is a property, not an entity
DEFINE FIELD email ON TABLE person TYPE string;
UPDATE person:alice SET email = 'alice@example.com';
```

**Rule**: Only create nodes for entities with independent lifecycle.

---

### Anti-Pattern 2: Dense Arrays in Nodes

❌ **DON'T**:
```surreal
-- Storing thousands of IDs in array
DEFINE FIELD followers ON TABLE person TYPE array<record<person>>;
UPDATE person:celebrity SET followers += person:bob;
-- Array grows to thousands of items!
```

✅ **DO**:
```surreal
-- Use relationships for collections
DEFINE TABLE follows SCHEMAFULL;
RELATE person:bob->follows->person:celebrity;
```

---

### Anti-Pattern 3: Generic Relationships

❌ **DON'T**:
```surreal
-- Generic "related_to" edge
DEFINE TABLE related_to SCHEMAFULL;
DEFINE FIELD in ON TABLE related_to TYPE record;
DEFINE FIELD out ON TABLE related_to TYPE record;
DEFINE FIELD type ON TABLE related_to TYPE string;
```

✅ **DO**:
```surreal
-- Specific relationship types
DEFINE TABLE follows SCHEMAFULL;
DEFINE TABLE works_at SCHEMAFULL;
DEFINE TABLE authored SCHEMAFULL;
```

**Reason**: Typed relationships are clearer, faster, and easier to query.

---

### Anti-Pattern 4: Deep Nesting

❌ **DON'T**:
```surreal
-- Too many nesting levels
DEFINE FIELD data.level1.level2.level3.level4.value ON TABLE node TYPE string;
```

✅ **DO**:
```surreal
-- Flatten or use separate nodes
DEFINE FIELD value ON TABLE node TYPE string;
-- Or create intermediate nodes if truly hierarchical
```

---

## Schema Evolution

### Adding New Relationships

```surreal
-- ✅ Adding new edge type (non-breaking)
DEFINE TABLE likes SCHEMAFULL;
DEFINE FIELD in ON TABLE likes TYPE record<person>;
DEFINE FIELD out ON TABLE likes TYPE record<post>;
DEFINE FIELD created_at ON TABLE likes TYPE datetime DEFAULT time::now();

-- Existing queries unaffected
-- New queries can use new relationship
```

### Changing Relationship Direction

```surreal
-- Changing direction requires migration

-- Old: person -> authored -> post
-- New: post -> written_by -> person

-- Migration process:
-- 1. Create new relationship type
DEFINE TABLE written_by SCHEMAFULL;

-- 2. Copy data in new direction
FOR $rel IN (SELECT * FROM authored) {
    RELATE $rel.out->written_by->$rel.in;
};

-- 3. Update application code
-- 4. Remove old relationship (when safe)
-- REMOVE TABLE authored;
```

---

## Best Practices Summary

### Schema Design
1. **Model queries first**: Design based on access patterns
2. **Typed relationships**: Use specific edge types, not generic
3. **Direction matters**: Set based on most common queries
4. **Properties on edges**: Put relationship metadata on edges
5. **Embed sparingly**: Link for many-to-many and independent entities

### Relationships
1. **Bidirectional awareness**: Plan for reverse queries
2. **Depth limits**: Always bound traversals
3. **Weighted edges**: Add weight for algorithms
4. **Temporal tracking**: Use valid_from/valid_to for history
5. **Index edge properties**: Index fields used in filters

### Performance
1. **Materialized paths**: For deep hierarchies
2. **Cached computations**: Denormalize counts and aggregations
3. **Avoid super nodes**: Handle high-degree nodes specially
4. **Selective loading**: Don't always SELECT *
5. **Monitor patterns**: Track actual query patterns

### Evolution
1. **Plan for change**: Schemas will evolve
2. **Non-breaking additions**: Add new edges/properties
3. **Migration strategy**: For structural changes
4. **Version tracking**: Consider versioning critical data
5. **Document schema**: Keep graph model documented

Graph modeling is an iterative process. Start simple, optimize based on actual usage patterns, and evolve your schema as your application grows.
