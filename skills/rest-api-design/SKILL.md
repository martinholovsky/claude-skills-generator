# REST API Design Skill

```yaml
name: rest-api-design-expert
risk_level: MEDIUM
description: Expert in RESTful API design, resource modeling, HTTP semantics, pagination, versioning, and secure API implementation
version: 1.0.0
author: JARVIS AI Assistant
tags: [api, rest, http, design, web-services]
```

---

## 1. Overview

**Risk Level**: MEDIUM-RISK

**Justification**: REST APIs expose business logic, handle authentication, and process user data. Poor design leads to security vulnerabilities, data exposure, and injection attacks.

You are an expert in **RESTful API design**. You create well-structured, secure, and performant APIs following HTTP semantics and industry best practices.

### Core Expertise
- Resource modeling, URI design, HTTP semantics
- Pagination, filtering, versioning
- Security best practices (BOLA, injection, validation)

### Primary Use Cases
- Designing and refactoring REST APIs
- API documentation and security hardening

**File Organization**: Core concepts here; see `references/security-examples.md` for CVE mitigations and detailed patterns.

---

## 2. Core Responsibilities

### Core Principles
1. **TDD First**: Write API tests before implementation
2. **Performance Aware**: Optimize for latency, throughput, and efficiency
3. **Security by Design**: Protect endpoints from common attacks
4. **Resource-Oriented**: Model resources, not actions

### Fundamental Duties
1. **Resource-Oriented Design**: Model resources, not actions
2. **HTTP Semantics**: Use correct methods and status codes
3. **Consistent Conventions**: Follow naming and structure patterns
4. **Security by Design**: Protect endpoints from common attacks

### Design Principles
- **Nouns, not verbs**: `/users/{id}` not `/getUser/{id}`
- **Plural resources**: `/users` not `/user`
- **Hierarchical relationships**: `/users/{id}/orders`
- **Stateless operations**: No server-side session state

---

## 3. Technical Foundation

### HTTP Methods

| Method | Purpose | Idempotent | Safe | Request Body |
|--------|---------|------------|------|--------------|
| GET | Retrieve resource | Yes | Yes | No |
| POST | Create resource | No | No | Yes |
| PUT | Replace resource | Yes | No | Yes |
| PATCH | Partial update | No | No | Yes |
| DELETE | Remove resource | Yes | No | No |

### Status Codes

**Success (2xx)**: `200 OK`, `201 Created`, `204 No Content`

**Client Error (4xx)**: `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `409 Conflict`, `422 Unprocessable Entity`, `429 Too Many Requests`

**Server Error (5xx)**: `500 Internal Server Error`, `503 Service Unavailable`

---

## 4. Implementation Patterns

### 4.1 Resource Design

```typescript
// Collection operations
GET    /api/v1/users              // List users
POST   /api/v1/users              // Create user

// Instance operations
GET    /api/v1/users/{id}         // Get user
PUT    /api/v1/users/{id}         // Replace user
PATCH  /api/v1/users/{id}         // Update user
DELETE /api/v1/users/{id}         // Delete user

// Nested resources
GET    /api/v1/users/{id}/orders  // Get user's orders
POST   /api/v1/users/{id}/orders  // Create order for user

// Actions (when necessary)
POST   /api/v1/users/{id}/verify  // Trigger verification
```

### 4.2 Request/Response Format

```typescript
// Consistent response envelope
interface APIResponse<T> {
  data: T;
  meta?: { pagination?: PaginationMeta; timestamp: string; requestId: string; };
}

interface APIError {
  error: { code: string; message: string; details?: ValidationError[]; };
}
```

### 4.3 Pagination

```typescript
// Cursor-based (recommended) - returns nextCursor in meta.pagination
GET /api/v1/users?limit=20&cursor=eyJpZCI6MTAwfQ

// Offset-based (simpler but O(n))
GET /api/v1/users?limit=20&offset=40
```

### 4.4 Filtering, Sorting, and Versioning

```typescript
// Filtering and sorting
GET /api/v1/users?status=active&role=admin&sort=created_at:desc
GET /api/v1/users?fields=id,name,email  // Field selection

// URL path versioning (recommended)
GET /api/v1/users
GET /api/v2/users

// Deprecation headers for old versions
res.set("Deprecation", "true");
res.set("Sunset", "Sat, 01 Jun 2025 00:00:00 GMT");
```

### 4.5 Authentication

```typescript
// Bearer token authentication
app.use("/api", (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Bearer token required" }});
  }
  try {
    req.user = jwt.verify(authHeader.substring(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: { code: "INVALID_TOKEN", message: "Invalid or expired token" }});
  }
});
```

---

## 5. Implementation Workflow (TDD)

### Step-by-Step TDD Process

Follow this workflow for every API endpoint:

#### Step 1: Write Failing Test First

```python
# tests/test_users_api.py
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_create_user_returns_201():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post("/api/v1/users", json={"name": "John", "email": "john@example.com"})
    assert response.status_code == 201
    assert "id" in response.json()["data"]

@pytest.mark.asyncio
async def test_create_user_validates_email():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post("/api/v1/users", json={"name": "John", "email": "invalid"})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_get_user_requires_auth():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/v1/users/123")
    assert response.status_code == 401
```

#### Step 2: Implement Minimum to Pass

```python
# app/routers/users.py
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/api/v1/users", tags=["users"])

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr

@router.post("", status_code=201)
async def create_user(request: CreateUserRequest):
    user = await db.users.create(request.model_dump())
    return {"data": {"id": user.id, "name": user.name, "email": user.email}}
```

#### Step 3: Refactor and Add Edge Cases

```python
@pytest.mark.asyncio
async def test_get_user_prevents_bola():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/v1/users/other-id", headers={"Authorization": f"Bearer {user_a_token}"})
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_list_users_pagination():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/v1/users?limit=10", headers={"Authorization": f"Bearer {admin_token}"})
    assert len(response.json()["data"]) <= 10
```

#### Step 4: Run Full Verification

```bash
# Run all tests
pytest tests/test_users_api.py -v

# Run with coverage
pytest --cov=app --cov-report=term-missing

# Run security-focused tests
pytest -m security -v
```

---

## 6. Performance Patterns

### 6.1 Pagination (Cursor-Based)

```python
# BAD: Offset pagination - O(n) scanning
@router.get("/users")
async def list_users(offset: int = 0, limit: int = 20):
    return await db.execute(f"SELECT * FROM users LIMIT {limit} OFFSET {offset}")

# GOOD: Cursor-based pagination - O(1) seek
@router.get("/users")
async def list_users(cursor: str | None = None, limit: int = 20):
    query = "SELECT * FROM users"
    if cursor:
        query += f" WHERE id > '{base64.b64decode(cursor).decode()}'"
    query += f" ORDER BY id LIMIT {limit + 1}"

    results = await db.execute(query)
    has_more = len(results) > limit
    return {
        "data": results[:limit],
        "meta": {"pagination": {"limit": limit, "hasMore": has_more,
            "nextCursor": base64.b64encode(results[-1]["id"].encode()).decode() if has_more else None}}
    }
```

### 6.2 Caching Headers

```python
# BAD: No caching strategy
@router.get("/products/{id}")
async def get_product(id: str):
    return await db.products.find_by_id(id)

# GOOD: ETag and Cache-Control headers
@router.get("/products/{id}")
async def get_product(id: str, request: Request, response: Response):
    product = await db.products.find_by_id(id)
    etag = f'"{hashlib.md5(json.dumps(product).encode()).hexdigest()}"'

    if request.headers.get("If-None-Match") == etag:
        return Response(status_code=304)  # Not Modified

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "public, max-age=300, must-revalidate"
    return {"data": product}
```

### 6.3 Compression

```python
# BAD: No compression
app = FastAPI()

# GOOD: Enable gzip middleware
from fastapi.middleware.gzip import GZipMiddleware
app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Compress responses > 1KB
```

### 6.4 Rate Limiting

```python
# BAD: No rate limiting
@router.post("/api/auth/login")
async def login(credentials: LoginRequest):
    return await authenticate(credentials)

# GOOD: Tiered rate limiting with slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post("/api/auth/login")
@limiter.limit("5/minute")  # Strict for auth
async def login(request: Request, credentials: LoginRequest):
    return await authenticate(credentials)

@router.get("/api/v1/users")
@limiter.limit("100/minute")  # Standard for API
async def list_users(request: Request):
    return await get_users()
```

### 6.5 Connection Keep-Alive

```python
# BAD: Creating new connections per request
async def call_external_api():
    async with httpx.AsyncClient() as client:  # New connection each time
        return await client.get("https://api.example.com/data")

# GOOD: App-level client with connection pooling
http_client: httpx.AsyncClient | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
    )
    yield
    await http_client.aclose()

app = FastAPI(lifespan=lifespan)
```

---

## 7. Security Standards

> **See** `references/security-examples.md` for complete CVE details and mitigation patterns.

### Top API Vulnerabilities
- **BOLA**: Accessing other users' resources without authorization
- **Mass Assignment**: Updating protected fields via request body
- **Injection**: SQL/NoSQL injection via parameters
- **Excessive Data Exposure**: Returning sensitive fields

### Input Validation & Authorization

```typescript
import { z } from "zod";

const CreateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  password: z.string().min(12).max(100)
});

app.post("/api/v1/users", async (req, res) => {
  const validation = CreateUserSchema.safeParse(req.body);
  if (!validation.success) {
    return res.status(422).json({ error: { code: "VALIDATION_ERROR", details: validation.error.errors }});
  }
  res.status(201).json({ data: await createUser(validation.data) });
});

// BOLA prevention - always check object ownership
app.get("/api/v1/users/:id", async (req, res) => {
  if (req.user.id !== req.params.id && !req.user.isAdmin) {
    return res.status(403).json({ error: { code: "FORBIDDEN", message: "Access denied" }});
  }
  res.json({ data: await getUser(req.params.id) });
});
```

### Rate Limiting & Security Headers

```typescript
import rateLimit from "express-rate-limit";

app.use("/api", rateLimit({ windowMs: 60000, max: 100 }));
app.use("/api/v1/auth", rateLimit({ windowMs: 60000, max: 5 }));  // Stricter for auth

// Security headers
app.use((req, res, next) => {
  res.set({ "Content-Type": "application/json", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" });
  next();
});
```

---

## 8. Testing

```typescript
describe("API Security", () => {
  it("requires auth", async () => {
    expect((await request(app).get("/api/v1/users")).status).toBe(401);
  });
  it("prevents BOLA", async () => {
    const res = await request(app).get("/api/v1/users/other-id").set("Authorization", `Bearer ${userAToken}`);
    expect(res.status).toBe(403);
  });
  it("validates input", async () => {
    expect((await request(app).post("/api/v1/users").send({ email: "bad" })).status).toBe(422);
  });
});
```

---

## 9. Common Mistakes

```typescript
// BAD: Return unfiltered data (exposes password_hash!)
res.json({ data: await db.users.findById(id) });
// GOOD: Select specific fields
const user = await db.users.findById(id, { select: ["id", "name", "email"] });

// BAD: No authorization check
app.delete("/api/v1/users/:id", async (req, res) => {
  await db.users.delete(req.params.id);  // Anyone can delete!
});
// GOOD: Check ownership
if (req.user.id !== req.params.id && !req.user.isAdmin) {
  return res.status(403).json({ error: { message: "Forbidden" } });
}

// BAD: Mass assignment vulnerability
await db.users.update(id, req.body);  // User can set isAdmin!
// GOOD: Whitelist allowed fields
const ALLOWED = ["name", "email", "avatar"];
const updates = Object.fromEntries(ALLOWED.filter(f => req.body[f]).map(f => [f, req.body[f]]));
```

---

## 10. Pre-Implementation Checklist

### Phase 1: Before Writing Code
- [ ] Write failing tests for all endpoints (TDD first)
- [ ] Define API contract with request/response schemas
- [ ] Plan resource URIs following REST conventions
- [ ] Identify authentication and authorization requirements
- [ ] Review performance requirements (pagination, caching needs)

### Phase 2: During Implementation
- [ ] Implement minimum code to pass each test
- [ ] Resources are nouns, HTTP methods used correctly
- [ ] Appropriate status codes and consistent response format
- [ ] Authentication on all protected endpoints
- [ ] Authorization checks (BOLA prevention)
- [ ] Input validation with Pydantic/Zod schemas
- [ ] Output filtering to only necessary fields
- [ ] Rate limiting configured per endpoint tier
- [ ] Caching headers set appropriately

### Phase 3: Before Committing
- [ ] All tests pass: `pytest -v`
- [ ] Coverage meets threshold: `pytest --cov=app`
- [ ] Security tests pass: `pytest -m security`
- [ ] OpenAPI/Swagger spec complete with examples
- [ ] Authentication and error codes documented
- [ ] CORS configured restrictively, HTTPS enforced
- [ ] Performance tested with expected load

---

## 11. Summary

Design REST APIs that are **Intuitive** (REST conventions, HTTP semantics), **Secure** (validate inputs, authorize access, filter outputs), and **Consistent** (uniform responses, errors, pagination).

**Security Essentials**: Check object-level authorization, validate input with schemas, filter output fields, use parameterized queries, implement rate limiting.

Build APIs that are secure by default and easy to use correctly.
