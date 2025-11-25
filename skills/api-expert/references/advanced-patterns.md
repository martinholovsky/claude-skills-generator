# Advanced API Implementation Patterns

This document contains detailed implementation patterns for advanced API features.

## Table of Contents
- [Rate Limiting Implementation](#rate-limiting-implementation)
- [Cursor-Based Pagination](#cursor-based-pagination)
- [OpenAPI 3.1 Documentation](#openapi-31-documentation)

---

## Rate Limiting Implementation

### Sliding Window Rate Limiter (Redis)

```javascript
// ✅ SLIDING WINDOW RATE LIMITER (Redis)

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

const redisClient = redis.createClient();

// Create rate limiter
const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:',
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      type: "https://api.example.com/errors/rate-limit-exceeded",
      title: "Too Many Requests",
      status: 429,
      detail: "Rate limit exceeded. Please try again later.",
      retry_after: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  },
  skip: (req) => {
    // Skip rate limiting for internal services
    return req.headers['x-internal-service'] === 'true';
  }
});

// Different limits for different endpoints
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Only 10 requests per 15min
  message: "Too many login attempts"
});

// Apply to routes
app.use('/v1/', apiLimiter);
app.post('/v1/auth/login', strictLimiter, login);
```

### Custom Rate Limiting by User ID

```javascript
// ✅ Custom rate limiting by user ID
const userRateLimiter = async (req, res, next) => {
  const userId = req.user?.sub;
  if (!userId) return next();

  const key = `rl:user:${userId}`;
  const limit = req.user.tier === 'premium' ? 1000 : 100;
  const window = 60; // 1 minute

  const current = await redisClient.incr(key);
  if (current === 1) {
    await redisClient.expire(key, window);
  }

  const ttl = await redisClient.ttl(key);

  res.set({
    'X-RateLimit-Limit': limit,
    'X-RateLimit-Remaining': Math.max(0, limit - current),
    'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + ttl
  });

  if (current > limit) {
    return res.status(429).json({
      type: "https://api.example.com/errors/rate-limit-exceeded",
      title: "Rate Limit Exceeded",
      status: 429,
      detail: `You have exceeded the rate limit of ${limit} requests per minute`,
      retry_after: ttl
    });
  }

  next();
};
```

### Rate Limiting Strategies

**Token Bucket Algorithm**:
- Tokens added at fixed rate
- Each request consumes a token
- Allows bursting up to bucket capacity

**Sliding Window Algorithm**:
- Counts requests in rolling time window
- More accurate than fixed window
- Prevents boundary exploitation

**Leaky Bucket Algorithm**:
- Processes requests at constant rate
- Smooths traffic spikes
- Good for rate-sensitive downstream services

---

## Cursor-Based Pagination

### Efficient Cursor Implementation

```javascript
// ✅ EFFICIENT CURSOR-BASED PAGINATION

// GET /v1/users?limit=20&cursor=eyJpZCI6MTAwfQ

app.get('/v1/users', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  let afterId = null;

  // Decode cursor
  if (req.query.cursor) {
    try {
      const decoded = Buffer.from(req.query.cursor, 'base64').toString();
      afterId = JSON.parse(decoded).id;
    } catch (error) {
      return res.status(400).json({
        type: "https://api.example.com/errors/invalid-cursor",
        title: "Invalid Cursor",
        status: 400,
        detail: "The provided cursor is invalid"
      });
    }
  }

  // Query with cursor
  const query = db.select().from('users').orderBy('id').limit(limit + 1);
  if (afterId) {
    query.where('id', '>', afterId);
  }

  const users = await query;
  const hasMore = users.length > limit;
  const results = hasMore ? users.slice(0, limit) : users;

  // Generate next cursor
  let nextCursor = null;
  if (hasMore) {
    const lastUser = results[results.length - 1];
    nextCursor = Buffer.from(JSON.stringify({ id: lastUser.id })).toString('base64');
  }

  // HATEOAS response
  const baseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`;

  res.json({
    data: results,
    pagination: {
      limit,
      has_more: hasMore,
      next_cursor: nextCursor
    },
    links: {
      self: `${baseUrl}?limit=${limit}${req.query.cursor ? `&cursor=${req.query.cursor}` : ''}`,
      next: hasMore ? `${baseUrl}?limit=${limit}&cursor=${nextCursor}` : null
    }
  });
});
```

### Response Format

```json
{
  "data": [
    { "id": 1, "name": "Alice" },
    { "id": 2, "name": "Bob" }
  ],
  "pagination": {
    "limit": 20,
    "has_more": true,
    "next_cursor": "eyJpZCI6MjB9"
  },
  "links": {
    "self": "https://api.example.com/v1/users?limit=20",
    "next": "https://api.example.com/v1/users?limit=20&cursor=eyJpZCI6MjB9"
  }
}
```

### Pagination Comparison

| Strategy | Performance | Use Case | Pros | Cons |
|----------|-------------|----------|------|------|
| **Offset-based** | Poor at scale | Small datasets | Simple, jump to page | Slow, inconsistent with changes |
| **Cursor-based** | Excellent | Real-time feeds | Fast, consistent | Can't jump to page |
| **Keyset** | Excellent | Large datasets | Fast, predictable | Requires indexed column |

### Advanced: Composite Cursor

For sorting by multiple fields:

```javascript
// Cursor with timestamp and id for tie-breaking
const cursor = {
  created_at: lastItem.created_at,
  id: lastItem.id
};

// Query with composite cursor
const query = db.select()
  .from('items')
  .where('created_at', '<', cursor.created_at)
  .orWhere((builder) => {
    builder
      .where('created_at', '=', cursor.created_at)
      .where('id', '<', cursor.id)
  })
  .orderBy('created_at', 'desc')
  .orderBy('id', 'desc')
  .limit(limit + 1);
```

---

## OpenAPI 3.1 Documentation

### Comprehensive OpenAPI Specification

```yaml
# ✅ COMPREHENSIVE OPENAPI 3.1 SPEC

openapi: 3.1.0
info:
  title: Example API
  version: 1.0.0
  description: RESTful API for user management
  contact:
    email: api@example.com
  license:
    name: MIT

servers:
  - url: https://api.example.com/v1
    description: Production
  - url: https://staging-api.example.com/v1
    description: Staging

security:
  - BearerAuth: []

paths:
  /users:
    get:
      summary: List users
      description: Retrieves a paginated list of users
      operationId: listUsers
      tags:
        - Users
      parameters:
        - name: limit
          in: query
          description: Number of items to return
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
        - name: cursor
          in: query
          description: Pagination cursor
          schema:
            type: string
      responses:
        '200':
          description: Successful response
          headers:
            X-RateLimit-Limit:
              schema:
                type: integer
            X-RateLimit-Remaining:
              schema:
                type: integer
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserListResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

    post:
      summary: Create user
      description: Creates a new user account
      operationId: createUser
      tags:
        - Users
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          description: User created successfully
          headers:
            Location:
              schema:
                type: string
                format: uri
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          $ref: '#/components/responses/BadRequest'
        '422':
          $ref: '#/components/responses/ValidationError'

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    User:
      type: object
      required:
        - id
        - email
        - name
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        name:
          type: string
          minLength: 1
          maxLength: 100
        created_at:
          type: string
          format: date-time

    CreateUserRequest:
      type: object
      required:
        - email
        - name
        - password
      properties:
        email:
          type: string
          format: email
        name:
          type: string
          minLength: 1
          maxLength: 100
        password:
          type: string
          format: password
          minLength: 8

    UserListResponse:
      type: object
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/User'
        pagination:
          $ref: '#/components/schemas/PaginationInfo'
        links:
          $ref: '#/components/schemas/PaginationLinks'

    PaginationInfo:
      type: object
      properties:
        limit:
          type: integer
        has_more:
          type: boolean
        next_cursor:
          type: string
          nullable: true

    PaginationLinks:
      type: object
      properties:
        self:
          type: string
          format: uri
        next:
          type: string
          format: uri
          nullable: true

    Error:
      type: object
      required:
        - type
        - title
        - status
      properties:
        type:
          type: string
          format: uri
        title:
          type: string
        status:
          type: integer
        detail:
          type: string
        correlation_id:
          type: string
          format: uuid
        errors:
          type: array
          items:
            $ref: '#/components/schemas/ValidationError'

    ValidationError:
      type: object
      properties:
        field:
          type: string
        code:
          type: string
        message:
          type: string

  responses:
    Unauthorized:
      description: Unauthorized - missing or invalid authentication
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    Forbidden:
      description: Forbidden - insufficient permissions
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    BadRequest:
      description: Bad Request - invalid input
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    ValidationError:
      description: Validation Error - input validation failed
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    RateLimitExceeded:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
        X-RateLimit-Remaining:
          schema:
            type: integer
        X-RateLimit-Reset:
          schema:
            type: integer
        Retry-After:
          schema:
            type: integer
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
```

### OpenAPI Best Practices

1. **Use References**: Define reusable components for schemas, responses, parameters
2. **Document Everything**: Every endpoint, parameter, and field should have descriptions
3. **Include Examples**: Add request/response examples for clarity
4. **Security Schemes**: Document all authentication methods
5. **Error Responses**: Document all possible error responses
6. **Versioning**: Include version in info and server URLs
7. **Tags**: Group related endpoints with tags
8. **Deprecation**: Mark deprecated endpoints with `deprecated: true`

### Generating Code from OpenAPI

```bash
# Generate client SDKs
npx @openapitools/openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o ./client

# Generate server stubs
npx @openapitools/openapi-generator-cli generate \
  -i openapi.yaml \
  -g nodejs-express-server \
  -o ./server

# Validate OpenAPI spec
npx @openapitools/openapi-generator-cli validate -i openapi.yaml
```

### API Documentation Tools

- **Swagger UI**: Interactive API documentation
- **Redoc**: Clean, responsive API documentation
- **Stoplight**: API design and documentation platform
- **Postman**: Import OpenAPI specs to generate collections
- **Spotlight Studio**: Visual OpenAPI editor
