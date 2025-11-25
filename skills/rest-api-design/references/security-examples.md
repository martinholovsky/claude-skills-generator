# REST API Security Examples & CVE Mitigations

## OWASP API Security Top 10 (2023)

### API1:2023 - Broken Object Level Authorization (BOLA)

**Severity**: CRITICAL
**CWE**: CWE-639

**Mitigation**:
```typescript
// ✅ Complete BOLA prevention
async function authorizeResourceAccess(
  user: User,
  resourceType: string,
  resourceId: string,
  action: string
): Promise<void> {
  // Get resource
  const resource = await getResource(resourceType, resourceId);
  if (!resource) {
    throw new NotFoundError("Resource not found");
  }

  // Check ownership or role-based access
  const hasAccess =
    resource.ownerId === user.id ||
    user.roles.includes("admin") ||
    await checkPermission(user.id, resourceType, action);

  if (!hasAccess) {
    throw new ForbiddenError("Access denied");
  }
}

// Apply to all resource endpoints
app.get("/api/v1/:resource/:id", async (req, res) => {
  await authorizeResourceAccess(req.user, req.params.resource, req.params.id, "read");
  // ... fetch and return resource
});
```

### API2:2023 - Broken Authentication

**Mitigation**:
```typescript
// ✅ Secure JWT implementation
import jwt from "jsonwebtoken";

function generateTokens(user: User) {
  const accessToken = jwt.sign(
    { userId: user.id, type: "access" },
    process.env.JWT_SECRET!,
    { expiresIn: "15m" }
  );

  const refreshToken = jwt.sign(
    { userId: user.id, type: "refresh" },
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
}

// Token refresh with rotation
app.post("/api/v1/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as JWTPayload;

    // Check if token is blacklisted
    if (await isTokenBlacklisted(refreshToken)) {
      return res.status(401).json({ error: { message: "Token revoked" } });
    }

    // Blacklist old refresh token
    await blacklistToken(refreshToken);

    // Issue new tokens
    const user = await getUserById(payload.userId);
    const tokens = generateTokens(user);

    res.json({ data: tokens });
  } catch {
    res.status(401).json({ error: { message: "Invalid token" } });
  }
});
```

### API3:2023 - Broken Object Property Level Authorization

**Mitigation**:
```typescript
// ✅ Field-level authorization
const fieldPermissions: Record<string, Record<string, string[]>> = {
  user: {
    public: ["id", "name", "avatar"],
    owner: ["id", "name", "email", "avatar", "preferences"],
    admin: ["id", "name", "email", "avatar", "preferences", "role", "created_at"]
  }
};

function filterFields(data: unknown, resourceType: string, accessLevel: string): unknown {
  const allowedFields = fieldPermissions[resourceType]?.[accessLevel] || [];

  if (Array.isArray(data)) {
    return data.map(item => filterObject(item, allowedFields));
  }

  return filterObject(data, allowedFields);
}

function filterObject(obj: Record<string, unknown>, allowedFields: string[]): Record<string, unknown> {
  const filtered: Record<string, unknown> = {};
  for (const field of allowedFields) {
    if (obj[field] !== undefined) {
      filtered[field] = obj[field];
    }
  }
  return filtered;
}
```

### API4:2023 - Unrestricted Resource Consumption

**Mitigation**:
```typescript
// ✅ Comprehensive rate limiting
import { RateLimiterRedis } from "rate-limiter-flexible";

const rateLimiters = {
  general: new RateLimiterRedis({
    storeClient: redis,
    keyPrefix: "rl_general",
    points: 100,
    duration: 60
  }),
  auth: new RateLimiterRedis({
    storeClient: redis,
    keyPrefix: "rl_auth",
    points: 5,
    duration: 60
  }),
  expensive: new RateLimiterRedis({
    storeClient: redis,
    keyPrefix: "rl_expensive",
    points: 10,
    duration: 60
  })
};

// Request size limits
app.use(express.json({ limit: "100kb" }));

// Pagination limits
const MAX_PAGE_SIZE = 100;
function getPaginationParams(query: any) {
  return {
    limit: Math.min(parseInt(query.limit) || 20, MAX_PAGE_SIZE),
    offset: parseInt(query.offset) || 0
  };
}
```

## Complete Audit Logging

```typescript
interface APIAuditLog {
  timestamp: string;
  requestId: string;
  method: string;
  path: string;
  userId?: string;
  ip: string;
  userAgent: string;
  statusCode: number;
  duration_ms: number;
  error?: string;
}

app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomUUID();

  req.requestId = requestId;
  res.set("X-Request-ID", requestId);

  res.on("finish", async () => {
    await auditLogger.log({
      timestamp: new Date().toISOString(),
      requestId,
      method: req.method,
      path: req.path,
      userId: req.user?.id,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "unknown",
      statusCode: res.statusCode,
      duration_ms: Date.now() - startTime
    });
  });

  next();
});
```

## SQL Injection Prevention

```typescript
// ✅ Parameterized queries only
async function searchUsers(filters: UserFilters): Promise<User[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filters.name) {
    conditions.push("name ILIKE $" + (params.length + 1));
    params.push(`%${filters.name}%`);
  }

  if (filters.status) {
    conditions.push("status = $" + (params.length + 1));
    params.push(filters.status);
  }

  const where = conditions.length ? "WHERE " + conditions.join(" AND ") : "";
  const query = `SELECT id, name, email FROM users ${where}`;

  return await db.query(query, params);
}
```
