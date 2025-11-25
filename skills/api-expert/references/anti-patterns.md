# API Anti-Patterns and Common Mistakes

A comprehensive guide to common API design mistakes and how to avoid them.

## Table of Contents
- [URL Design Anti-Patterns](#url-design-anti-patterns)
- [HTTP Status Code Misuse](#http-status-code-misuse)
- [Rate Limiting Neglect](#rate-limiting-neglect)
- [Data Exposure Issues](#data-exposure-issues)
- [Input Validation Failures](#input-validation-failures)
- [Versioning Mistakes](#versioning-mistakes)
- [Pagination Problems](#pagination-problems)
- [Authentication/Authorization Flaws](#authenticationauthorization-flaws)
- [Error Handling Anti-Patterns](#error-handling-anti-patterns)
- [Performance Anti-Patterns](#performance-anti-patterns)

---

## URL Design Anti-Patterns

### Mistake 1: Using Verbs in REST URLs

```http
# ❌ DON'T: Verbs in URLs
POST /createUser
GET /getUser/123
POST /updateUser/123
POST /deleteUser/123
GET /getUserOrders/123
POST /sendEmail

# ✅ DO: Use nouns and HTTP methods
POST /users
GET /users/123
PUT /users/123
PATCH /users/123
DELETE /users/123
GET /users/123/orders
POST /emails
```

**Why it's wrong**: REST is resource-oriented. URLs should represent resources (nouns), and HTTP methods represent actions (verbs).

### Mistake 2: Deep Nesting

```http
# ❌ DON'T: Deep nesting
GET /organizations/{id}/departments/{id}/teams/{id}/members/{id}/tasks/{id}

# ✅ DO: Keep nesting shallow (max 2-3 levels)
GET /tasks/{id}
GET /teams/{id}/members
GET /members/{id}/tasks

# Alternative: Use query parameters
GET /tasks?member_id=123&team_id=456
```

### Mistake 3: Inconsistent Naming

```http
# ❌ DON'T: Inconsistent naming
GET /user          # singular
GET /orders        # plural
GET /product-list  # kebab-case with suffix
GET /cartItems     # camelCase

# ✅ DO: Use consistent plural nouns
GET /users
GET /orders
GET /products
GET /cart-items
```

### Mistake 4: Query Parameters in POST Body

```http
# ❌ DON'T: Mix query params and body
POST /users?role=admin
{
  "name": "John",
  "email": "john@example.com"
}

# ✅ DO: Everything in body for POST
POST /users
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin"
}

# ✅ Query params OK for filters on GET
GET /users?role=admin&status=active
```

---

## HTTP Status Code Misuse

### Mistake 1: Always Returning 200

```javascript
// ❌ DON'T: Always return 200
app.get('/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  if (!user) {
    return res.status(200).json({ error: "User not found" });
  }
  res.status(200).json(user);
});

// ✅ DO: Use proper status codes
app.get('/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  if (!user) {
    return res.status(404).json({
      type: "https://api.example.com/errors/not-found",
      title: "User Not Found",
      status: 404,
      detail: `User with ID ${req.params.id} does not exist`
    });
  }
  res.status(200).json(user);
});
```

### Mistake 2: Wrong Success Codes

```javascript
// ❌ DON'T: Wrong success codes
app.post('/users', async (req, res) => {
  const user = await createUser(req.body);
  res.status(200).json(user); // Should be 201
});

app.delete('/users/:id', async (req, res) => {
  await deleteUser(req.params.id);
  res.status(200).json({ message: "Deleted" }); // Should be 204
});

// ✅ DO: Use correct success codes
app.post('/users', async (req, res) => {
  const user = await createUser(req.body);
  res.status(201)
     .header('Location', `/users/${user.id}`)
     .json(user);
});

app.delete('/users/:id', async (req, res) => {
  await deleteUser(req.params.id);
  res.status(204).send(); // No content
});
```

### Mistake 3: Confusing 401 and 403

```javascript
// ❌ DON'T: Confuse authentication and authorization
app.get('/admin/users', (req, res) => {
  if (!req.user) {
    return res.status(403).json({ error: "Forbidden" }); // Wrong!
  }
  if (!req.user.isAdmin) {
    return res.status(401).json({ error: "Unauthorized" }); // Wrong!
  }
  // ...
});

// ✅ DO: Use correct codes
app.get('/admin/users', (req, res) => {
  // 401: Not authenticated (missing/invalid token)
  if (!req.user) {
    return res.status(401).json({
      type: "https://api.example.com/errors/unauthorized",
      title: "Authentication Required",
      status: 401,
      detail: "Valid authentication credentials are required"
    });
  }

  // 403: Authenticated but not authorized (insufficient permissions)
  if (!req.user.isAdmin) {
    return res.status(403).json({
      type: "https://api.example.com/errors/forbidden",
      title: "Forbidden",
      status: 403,
      detail: "You do not have permission to access this resource"
    });
  }
  // ...
});
```

### Status Code Quick Reference

| Code | Use Case | Example |
|------|----------|---------|
| 200 | Success with body | GET, PUT, PATCH with response |
| 201 | Resource created | POST creating new resource |
| 204 | Success, no body | DELETE, PUT/PATCH with no response |
| 400 | Invalid input | Malformed JSON, invalid params |
| 401 | Not authenticated | Missing/invalid token |
| 403 | Not authorized | Valid token, insufficient permissions |
| 404 | Not found | Resource doesn't exist |
| 409 | Conflict | Duplicate resource, version mismatch |
| 422 | Validation failed | Valid JSON, fails business rules |
| 429 | Rate limited | Too many requests |
| 500 | Server error | Unexpected error |

---

## Rate Limiting Neglect

### Mistake: No Rate Limiting

```javascript
// ❌ DON'T: Unprotected endpoints
app.post('/auth/login', login);
app.post('/auth/register', register);
app.post('/api/search', search);

// Vulnerable to:
// - Brute force attacks
// - Credential stuffing
// - API abuse
// - DoS attacks

// ✅ DO: Rate limit all endpoints
const rateLimit = require('express-rate-limit');

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: "Too many requests, please try again later"
});

// Strict limiter for authentication
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
});

// Moderate limiter for expensive operations
const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10
});

app.use('/api/', apiLimiter);
app.post('/auth/login', authLimiter, login);
app.post('/auth/register', authLimiter, register);
app.post('/api/search', searchLimiter, search);
```

### Missing Rate Limit Headers

```javascript
// ❌ DON'T: No rate limit information
app.get('/api/data', (req, res) => {
  res.json({ data: "..." });
});

// ✅ DO: Include rate limit headers
app.get('/api/data', rateLimiter, (req, res) => {
  res.set({
    'X-RateLimit-Limit': '100',
    'X-RateLimit-Remaining': '95',
    'X-RateLimit-Reset': '1640000000'
  });
  res.json({ data: "..." });
});
```

---

## Data Exposure Issues

### Mistake 1: Exposing Sensitive Fields

```javascript
// ❌ DON'T: Return all database fields
app.get('/users/:id', async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user);
  // Exposes: password_hash, ssn, api_key, internal_notes, etc.
});

// ✅ DO: Filter sensitive fields
const sanitizeUser = (user, isOwner = false) => {
  const safe = {
    id: user.id,
    username: user.username,
    name: user.name,
    avatar_url: user.avatar_url,
    created_at: user.created_at
  };

  // Only include email/phone for the owner
  if (isOwner) {
    safe.email = user.email;
    safe.phone = user.phone;
  }

  // Never expose: password_hash, ssn, api_key, internal_notes, reset_token
  return safe;
};

app.get('/users/:id', validateJWT, async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  const isOwner = req.user.sub === req.params.id;
  res.json(sanitizeUser(user, isOwner));
});
```

### Mistake 2: Exposing Stack Traces

```javascript
// ❌ DON'T: Expose error details in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,  // Exposes file paths, code structure
    query: req.query   // May contain sensitive data
  });
});

// ✅ DO: Generic errors in production
app.use((err, req, res, next) => {
  // Log full error server-side
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    user: req.user?.sub
  });

  // Return generic error to client
  res.status(500).json({
    type: "https://api.example.com/errors/internal-error",
    title: "Internal Server Error",
    status: 500,
    detail: "An unexpected error occurred",
    correlation_id: req.correlationId
  });
});
```

### Mistake 3: Exposing Internal IDs

```javascript
// ❌ DON'T: Expose auto-increment IDs
{
  "id": 12345,  // Easy to enumerate
  "user_id": 67890,
  "order_id": 54321
}

// ✅ DO: Use UUIDs or opaque identifiers
{
  "id": "usr_2nQxQzRkJ8N5qZpW",
  "user_id": "usr_7pMxKfVbT3L9sWnE",
  "order_id": "ord_4hRyPqXnG6K2fMdC"
}
```

---

## Input Validation Failures

### Mistake: Trusting User Input

```javascript
// ❌ DON'T: Trust user input
app.post('/users', async (req, res) => {
  // No validation!
  const user = await db.query('INSERT INTO users SET ?', [req.body]);
  res.json(user);
});

// Vulnerable to:
// - SQL injection
// - Mass assignment (is_admin: true)
// - Invalid data types
// - XSS in stored data

// ✅ DO: Validate all inputs
const { body, validationResult } = require('express-validator');

app.post('/users', [
  // Required fields
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Must be a valid email'),

  body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),

  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .escape()
    .withMessage('Name is required'),

  // Optional fields
  body('age')
    .optional()
    .isInt({ min: 0, max: 150 })
    .withMessage('Age must be between 0 and 150'),

  body('website')
    .optional()
    .isURL()
    .withMessage('Must be a valid URL'),

  // Prevent mass assignment
  body('is_admin').not().exists().withMessage('Cannot set admin flag'),
  body('role').not().exists().withMessage('Cannot set role directly')
], async (req, res) => {
  // Check validation results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      type: "https://api.example.com/errors/validation-failed",
      title: "Validation Failed",
      status: 422,
      detail: "The request contains invalid fields",
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }

  // Only insert validated fields
  const user = await db.query(
    'INSERT INTO users (email, password_hash, name, age, website) VALUES (?, ?, ?, ?, ?)',
    [
      req.body.email,
      await hashPassword(req.body.password),
      req.body.name,
      req.body.age,
      req.body.website
    ]
  );

  res.status(201).json(sanitizeUser(user));
});
```

### Missing Content-Type Validation

```javascript
// ❌ DON'T: Accept any content type
app.post('/users', async (req, res) => {
  // Could be JSON, XML, form data, or malicious content
  await processUser(req.body);
});

// ✅ DO: Validate content type
app.post('/users',
  (req, res, next) => {
    if (req.get('Content-Type') !== 'application/json') {
      return res.status(415).json({
        type: "https://api.example.com/errors/unsupported-media-type",
        title: "Unsupported Media Type",
        status: 415,
        detail: "Content-Type must be application/json"
      });
    }
    next();
  },
  async (req, res) => {
    await processUser(req.body);
    res.status(201).json({ success: true });
  }
);
```

---

## Versioning Mistakes

### Mistake 1: No Versioning

```javascript
// ❌ DON'T: No versioning
app.get('/users', getUsersV1);

// Later, you need breaking changes...
app.get('/users', getUsersV2); // Breaks existing clients!

// ✅ DO: Version from day one
app.get('/v1/users', getUsersV1);

// Later, add new version
app.get('/v2/users', getUsersV2);
app.get('/v1/users', getUsersV1); // Old version still works
```

### Mistake 2: Breaking Changes Without Version Bump

```javascript
// ❌ DON'T: Breaking changes in same version
// v1 response:
{
  "id": 123,
  "name": "John"
}

// Later (still v1):
{
  "id": 123,
  "full_name": "John",  // Renamed field - BREAKING!
  "age": 30             // New required field - BREAKING!
}

// ✅ DO: Non-breaking changes only, or bump version
// v1 (keep compatible):
{
  "id": 123,
  "name": "John",
  "full_name": "John Doe",  // Add new field (non-breaking)
  "age": 30                 // Add new field (non-breaking)
}

// v2 (breaking changes):
{
  "id": 123,
  "full_name": "John Doe",  // Renamed field in new version
  "age": 30
}
```

### Missing Deprecation Warnings

```javascript
// ❌ DON'T: Shut down old versions without warning
app.get('/v1/users', (req, res) => {
  res.status(410).json({ error: "This API version is no longer supported" });
});

// ✅ DO: Deprecate gracefully
app.get('/v1/users', (req, res) => {
  // Warn clients about upcoming deprecation
  res.set({
    'Deprecation': 'true',
    'Sunset': 'Sat, 31 Dec 2024 23:59:59 GMT',
    'Link': '</v2/users>; rel="successor-version"'
  });

  // Still return data
  res.json(getUsersV1());
});

// After sunset date, return 410 Gone
```

---

## Pagination Problems

### Mistake 1: No Pagination

```javascript
// ❌ DON'T: Return all results
app.get('/users', async (req, res) => {
  const users = await db.query('SELECT * FROM users');
  res.json(users); // Could be millions of records!
});

// Causes:
// - Memory exhaustion
// - Slow response times
// - Database overload
// - Client crashes

// ✅ DO: Always paginate
app.get('/users', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = parseInt(req.query.offset) || 0;

  const users = await db.query(
    'SELECT * FROM users LIMIT ? OFFSET ?',
    [limit, offset]
  );

  const total = await db.query('SELECT COUNT(*) as count FROM users');

  res.json({
    data: users,
    pagination: {
      limit,
      offset,
      total: total[0].count,
      has_more: offset + limit < total[0].count
    }
  });
});
```

### Mistake 2: No Pagination Limits

```javascript
// ❌ DON'T: Allow unlimited page size
app.get('/users', async (req, res) => {
  const limit = parseInt(req.query.limit) || 20; // No maximum!
  // User can request ?limit=999999999
});

// ✅ DO: Enforce maximum page size
app.get('/users', async (req, res) => {
  const limit = Math.min(
    parseInt(req.query.limit) || 20,
    100  // Maximum 100 items per page
  );
  // ...
});
```

### Mistake 3: Inconsistent Pagination

```javascript
// ❌ DON'T: Different pagination for each endpoint
GET /users?page=1&size=20
GET /orders?offset=0&limit=10
GET /products?skip=5&take=15

// ✅ DO: Consistent pagination across all endpoints
GET /users?limit=20&cursor=abc123
GET /orders?limit=20&cursor=def456
GET /products?limit=20&cursor=ghi789
```

---

## Authentication/Authorization Flaws

### Mistake 1: Weak Token Generation

```javascript
// ❌ DON'T: Predictable tokens
const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');
// Easily guessable!

const token = Math.random().toString(36);
// Not cryptographically secure!

// ✅ DO: Cryptographically secure tokens
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

### Mistake 2: No Token Expiration

```javascript
// ❌ DON'T: Tokens that never expire
const token = jwt.sign({ sub: user.id }, secret);
// Valid forever!

// ✅ DO: Short-lived tokens
const accessToken = jwt.sign(
  { sub: user.id },
  secret,
  { expiresIn: '15m' }  // 15 minutes
);

const refreshToken = crypto.randomBytes(32).toString('hex');
// Store with expiration in database
```

### Mistake 3: Tokens in URLs

```javascript
// ❌ DON'T: Tokens in URLs
GET /api/users?token=abc123def456
GET /api/data/secret_token_here/resource

// Problems:
// - Logged in server logs
// - Stored in browser history
// - Shared in referrer headers
// - Visible in network monitoring

// ✅ DO: Tokens in Authorization header
GET /api/users
Authorization: Bearer abc123def456

// Or in httpOnly cookies
Cookie: session=abc123def456; HttpOnly; Secure; SameSite=Strict
```

### Mistake 4: Missing Authorization Checks

```javascript
// ❌ DON'T: Assume authentication = authorization
app.get('/users/:id/orders', validateJWT, async (req, res) => {
  // User is authenticated, but can they access THIS user's orders?
  const orders = await getOrders(req.params.id);
  res.json(orders); // BOLA vulnerability!
});

// ✅ DO: Check authorization
app.get('/users/:id/orders', validateJWT, async (req, res) => {
  // Verify user owns the resource or is admin
  if (req.user.sub !== req.params.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const orders = await getOrders(req.params.id);
  res.json(orders);
});
```

---

## Error Handling Anti-Patterns

### Mistake 1: Inconsistent Error Format

```javascript
// ❌ DON'T: Different error formats
res.status(400).json({ error: "Invalid input" });
res.status(404).json({ message: "Not found" });
res.status(500).json({ err: "Server error", code: 500 });

// ✅ DO: Consistent error format (RFC 7807)
const errorResponse = (type, title, status, detail) => ({
  type: `https://api.example.com/errors/${type}`,
  title,
  status,
  detail,
  correlation_id: generateId()
});

res.status(400).json(errorResponse('bad-request', 'Bad Request', 400, 'Invalid input'));
res.status(404).json(errorResponse('not-found', 'Not Found', 404, 'Resource not found'));
res.status(500).json(errorResponse('internal-error', 'Internal Error', 500, 'An error occurred'));
```

### Mistake 2: Missing Correlation IDs

```javascript
// ❌ DON'T: No way to trace errors
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal error" });
  // How does support find this log entry?
});

// ✅ DO: Use correlation IDs
const { v4: uuidv4 } = require('uuid');

app.use((req, res, next) => {
  req.correlationId = uuidv4();
  next();
});

app.use((err, req, res, next) => {
  logger.error({
    correlation_id: req.correlationId,
    error: err.message,
    stack: err.stack,
    url: req.url
  });

  res.status(500).json({
    type: "https://api.example.com/errors/internal-error",
    title: "Internal Server Error",
    status: 500,
    detail: "An unexpected error occurred",
    correlation_id: req.correlationId  // Client can provide this to support
  });
});
```

---

## Performance Anti-Patterns

### Mistake 1: N+1 Queries

```javascript
// ❌ DON'T: N+1 queries
app.get('/users', async (req, res) => {
  const users = await db.query('SELECT * FROM users LIMIT 100');

  // This executes 100 additional queries!
  for (const user of users) {
    user.orders = await db.query('SELECT * FROM orders WHERE user_id = ?', [user.id]);
  }

  res.json(users);
});

// ✅ DO: Use joins or batch loading
app.get('/users', async (req, res) => {
  const users = await db.query('SELECT * FROM users LIMIT 100');
  const userIds = users.map(u => u.id);

  // Single query for all orders
  const orders = await db.query(
    'SELECT * FROM orders WHERE user_id IN (?)',
    [userIds]
  );

  // Group orders by user
  const ordersByUser = orders.reduce((acc, order) => {
    if (!acc[order.user_id]) acc[order.user_id] = [];
    acc[order.user_id].push(order);
    return acc;
  }, {});

  users.forEach(user => {
    user.orders = ordersByUser[user.id] || [];
  });

  res.json(users);
});
```

### Mistake 2: No Caching

```javascript
// ❌ DON'T: No caching for expensive operations
app.get('/statistics', async (req, res) => {
  // This takes 5 seconds to compute!
  const stats = await computeExpensiveStatistics();
  res.json(stats);
});

// ✅ DO: Cache expensive operations
const cache = new Map();

app.get('/statistics', async (req, res) => {
  const cacheKey = 'statistics';
  const cached = cache.get(cacheKey);

  if (cached && Date.now() - cached.timestamp < 60000) {
    res.set('X-Cache', 'HIT');
    return res.json(cached.data);
  }

  const stats = await computeExpensiveStatistics();
  cache.set(cacheKey, {
    data: stats,
    timestamp: Date.now()
  });

  res.set('X-Cache', 'MISS');
  res.json(stats);
});
```

### Mistake 3: Blocking Operations

```javascript
// ❌ DON'T: Synchronous operations
const fs = require('fs');

app.get('/file/:name', (req, res) => {
  // Blocks the event loop!
  const content = fs.readFileSync(`./files/${req.params.name}`);
  res.send(content);
});

// ✅ DO: Asynchronous operations
const fs = require('fs').promises;

app.get('/file/:name', async (req, res) => {
  try {
    const content = await fs.readFile(`./files/${req.params.name}`);
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});
```

---

## Summary

**Top 10 API Mistakes to Avoid**:

1. Using verbs in REST URLs
2. Always returning 200 status codes
3. No rate limiting
4. Exposing sensitive data
5. Missing input validation
6. No API versioning
7. Missing or broken pagination
8. Weak authentication/authorization
9. Inconsistent error handling
10. Performance issues (N+1 queries, no caching)

**Remember**: These mistakes are common, but they're all preventable with proper planning and implementation!
