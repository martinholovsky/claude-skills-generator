# API Security Examples

Detailed examples and mitigations for the OWASP API Security Top 10 2023.

## Table of Contents
- [API1:2023 - Broken Object Level Authorization (BOLA)](#api12023---broken-object-level-authorization-bola)
- [API2:2023 - Broken Authentication](#api22023---broken-authentication)
- [API3:2023 - Broken Object Property Level Authorization](#api32023---broken-object-property-level-authorization)
- [API4:2023 - Unrestricted Resource Consumption](#api42023---unrestricted-resource-consumption)
- [API5:2023 - Broken Function Level Authorization](#api52023---broken-function-level-authorization)
- [API6:2023 - Unrestricted Access to Sensitive Business Flows](#api62023---unrestricted-access-to-sensitive-business-flows)
- [API7:2023 - Server Side Request Forgery (SSRF)](#api72023---server-side-request-forgery-ssrf)
- [API8:2023 - Security Misconfiguration](#api82023---security-misconfiguration)
- [API9:2023 - Improper Inventory Management](#api92023---improper-inventory-management)
- [API10:2023 - Unsafe Consumption of APIs](#api102023---unsafe-consumption-of-apis)

---

## API1:2023 - Broken Object Level Authorization (BOLA)

**Also known as**: Insecure Direct Object Reference (IDOR)

**Description**: APIs expose endpoints that handle object identifiers, creating a wide attack surface. Without proper authorization checks, attackers can access or modify objects belonging to other users.

### Vulnerable Example

```javascript
// ❌ VULNERABLE: No authorization check
app.get('/v1/users/:id/orders', async (req, res) => {
  const orders = await db.query(
    'SELECT * FROM orders WHERE user_id = ?',
    [req.params.id]
  );
  res.json(orders);
});

// Attack: User A can access User B's orders
// GET /v1/users/12345/orders (User B's ID)
```

### Secure Implementation

```javascript
// ✅ SECURE: Verify user owns the resource
app.get('/v1/users/:id/orders', validateJWT, async (req, res) => {
  // Check if authenticated user matches resource owner
  if (req.user.sub !== req.params.id && !req.user.scope.includes('admin')) {
    return res.status(403).json({
      type: "https://api.example.com/errors/forbidden",
      title: "Forbidden",
      status: 403,
      detail: "You can only access your own orders"
    });
  }

  const orders = await db.query(
    'SELECT * FROM orders WHERE user_id = ?',
    [req.params.id]
  );
  res.json(orders);
});

// Alternative: Use authenticated user's ID from token
app.get('/v1/me/orders', validateJWT, async (req, res) => {
  // Always use the ID from the verified token
  const orders = await db.query(
    'SELECT * FROM orders WHERE user_id = ?',
    [req.user.sub] // From JWT, not URL parameter
  );
  res.json(orders);
});
```

### Additional Mitigations

```javascript
// ✅ Database-level authorization
const getOrders = async (userId, requesterId) => {
  return db.query(
    `SELECT * FROM orders
     WHERE user_id = ?
     AND (user_id = ? OR EXISTS (
       SELECT 1 FROM user_permissions
       WHERE user_id = ? AND permission = 'admin'
     ))`,
    [userId, requesterId, requesterId]
  );
};
```

---

## API2:2023 - Broken Authentication

**Description**: Poorly implemented authentication mechanisms allow attackers to compromise tokens, passwords, or session identifiers.

### Vulnerable Examples

```javascript
// ❌ VULNERABLE: Weak token generation
const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');

// ❌ VULNERABLE: No token expiration
const token = jwt.sign({ sub: user.id }, secret);

// ❌ VULNERABLE: Passwords in URLs or logs
app.post('/login?password=secret123', login);

// ❌ VULNERABLE: No rate limiting on authentication
app.post('/v1/auth/login', login);
```

### Secure Implementation

```javascript
// ✅ SECURE: Cryptographically secure tokens
const crypto = require('crypto');
const apiToken = crypto.randomBytes(32).toString('hex');

// ✅ SECURE: JWT with proper configuration
const accessToken = jwt.sign(
  {
    sub: user.id,
    scope: user.permissions.join(' ')
  },
  privateKey,
  {
    algorithm: 'RS256',      // Asymmetric signing
    expiresIn: '15m',        // Short-lived
    issuer: 'https://api.example.com',
    audience: 'https://api.example.com',
    jwtid: crypto.randomUUID() // For revocation tracking
  }
);

// ✅ SECURE: Refresh token with rotation
const refreshToken = crypto.randomBytes(32).toString('hex');
await db.query(
  'INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
  [refreshToken, user.id, Date.now() + 7 * 24 * 60 * 60 * 1000]
);

// ✅ SECURE: Rate limiting on authentication endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true // Only count failed attempts
});

app.post('/v1/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Account lockout after multiple failures
  const failedAttempts = await getFailedAttempts(email);
  if (failedAttempts >= 5) {
    return res.status(429).json({
      type: "https://api.example.com/errors/account-locked",
      title: "Account Locked",
      status: 429,
      detail: "Account locked due to multiple failed login attempts"
    });
  }

  const user = await validateCredentials(email, password);
  if (!user) {
    await recordFailedAttempt(email);
    return res.status(401).json({
      type: "https://api.example.com/errors/invalid-credentials",
      title: "Invalid Credentials",
      status: 401,
      detail: "Email or password is incorrect"
    });
  }

  await clearFailedAttempts(email);
  // Issue tokens...
});
```

### Token Refresh Pattern

```javascript
// ✅ SECURE: Token refresh with rotation
app.post('/v1/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  // Validate refresh token
  const tokenData = await db.query(
    'SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > ?',
    [refresh_token, Date.now()]
  );

  if (!tokenData) {
    return res.status(401).json({
      type: "https://api.example.com/errors/invalid-refresh-token",
      title: "Invalid Refresh Token",
      status: 401,
      detail: "The refresh token is invalid or expired"
    });
  }

  // Revoke old refresh token (rotation)
  await db.query('DELETE FROM refresh_tokens WHERE token = ?', [refresh_token]);

  // Issue new tokens
  const newAccessToken = generateAccessToken(tokenData.user_id);
  const newRefreshToken = crypto.randomBytes(32).toString('hex');

  await db.query(
    'INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
    [newRefreshToken, tokenData.user_id, Date.now() + 7 * 24 * 60 * 60 * 1000]
  );

  res.json({
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    token_type: 'Bearer',
    expires_in: 900
  });
});
```

---

## API3:2023 - Broken Object Property Level Authorization

**Description**: APIs expose more object properties than necessary, leading to information disclosure or mass assignment vulnerabilities.

### Vulnerable Examples

```javascript
// ❌ VULNERABLE: Exposing all fields
app.get('/v1/users/:id', async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user); // Exposes password_hash, ssn, internal_notes, etc.
});

// ❌ VULNERABLE: Mass assignment
app.patch('/v1/users/:id', async (req, res) => {
  await db.query('UPDATE users SET ? WHERE id = ?', [req.body, req.params.id]);
  // Attacker can set is_admin=true, balance=1000000, etc.
});
```

### Secure Implementation

```javascript
// ✅ SECURE: Whitelist output fields
const sanitizeUser = (user, role) => {
  const safe = {
    id: user.id,
    name: user.name,
    email: user.email,
    created_at: user.created_at
  };

  // Additional fields based on role
  if (role === 'owner') {
    safe.phone = user.phone;
    safe.address = user.address;
  }

  if (role === 'admin') {
    safe.last_login = user.last_login;
    safe.is_verified = user.is_verified;
  }

  // NEVER expose: password_hash, ssn, api_secret, internal_notes
  return safe;
};

app.get('/v1/users/:id', validateJWT, async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);

  const role = req.user.sub === req.params.id ? 'owner' :
               req.user.scope.includes('admin') ? 'admin' : 'public';

  res.json(sanitizeUser(user, role));
});

// ✅ SECURE: Whitelist input fields
const ALLOWED_UPDATE_FIELDS = ['name', 'email', 'phone', 'address'];

app.patch('/v1/users/:id', validateJWT, async (req, res) => {
  if (req.user.sub !== req.params.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Only allow specific fields to be updated
  const updates = {};
  for (const field of ALLOWED_UPDATE_FIELDS) {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  }

  await db.query('UPDATE users SET ? WHERE id = ?', [updates, req.params.id]);
  res.status(204).send();
});
```

### Using DTOs (Data Transfer Objects)

```javascript
// ✅ SECURE: Define explicit DTOs
class UserPublicDTO {
  constructor(user) {
    this.id = user.id;
    this.name = user.name;
    this.avatar_url = user.avatar_url;
  }
}

class UserPrivateDTO extends UserPublicDTO {
  constructor(user) {
    super(user);
    this.email = user.email;
    this.phone = user.phone;
    this.created_at = user.created_at;
  }
}

class UpdateUserDTO {
  constructor(data) {
    if (data.name) this.name = data.name;
    if (data.email) this.email = data.email;
    if (data.phone) this.phone = data.phone;
    // is_admin, balance, etc. are NOT copied
  }
}
```

---

## API4:2023 - Unrestricted Resource Consumption

**Description**: APIs without proper resource limits can be abused, leading to DoS or high costs.

### Mitigations

```javascript
// ✅ 1. Request body size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));

// ✅ 2. Pagination limits
app.get('/v1/users', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100); // Max 100
  const offset = parseInt(req.query.offset) || 0;
  // Query with limits...
});

// ✅ 3. Request timeouts
const timeout = require('connect-timeout');
app.use(timeout('30s'));
app.use((req, res, next) => {
  if (!req.timedout) next();
});

// ✅ 4. Rate limiting (see advanced-patterns.md)

// ✅ 5. GraphQL query complexity limits
const depthLimit = require('graphql-depth-limit');
const queryComplexity = require('graphql-query-complexity');

const server = new ApolloServer({
  schema,
  validationRules: [
    depthLimit(10),
    queryComplexity({
      maximumComplexity: 1000,
      variables: {},
      estimators: [
        simpleEstimator({ defaultComplexity: 1 })
      ]
    })
  ]
});

// ✅ 6. File upload limits
const multer = require('multer');
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5
  }
});

// ✅ 7. Concurrent request limits per user
const limitConcurrentRequests = (maxConcurrent) => {
  const activeRequests = new Map();

  return async (req, res, next) => {
    const userId = req.user?.sub;
    if (!userId) return next();

    const current = activeRequests.get(userId) || 0;
    if (current >= maxConcurrent) {
      return res.status(429).json({
        error: 'Too many concurrent requests'
      });
    }

    activeRequests.set(userId, current + 1);
    res.on('finish', () => {
      activeRequests.set(userId, activeRequests.get(userId) - 1);
    });

    next();
  };
};

app.use(limitConcurrentRequests(10));
```

---

## API5:2023 - Broken Function Level Authorization

**Description**: APIs expose administrative or privileged functions without proper role checks.

### Vulnerable Example

```javascript
// ❌ VULNERABLE: No role check
app.delete('/v1/users/:id', validateJWT, async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});
// Any authenticated user can delete any user!
```

### Secure Implementation

```javascript
// ✅ SECURE: Role-based access control
const requireScope = (...requiredScopes) => {
  return (req, res, next) => {
    if (!req.user || !req.user.scope) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userScopes = req.user.scope.split(' ');
    const hasScope = requiredScopes.some(scope => userScopes.includes(scope));

    if (!hasScope) {
      return res.status(403).json({
        type: "https://api.example.com/errors/forbidden",
        title: "Insufficient Permissions",
        status: 403,
        detail: `Required scopes: ${requiredScopes.join(', ')}`
      });
    }

    next();
  };
};

// Only admins can delete users
app.delete('/v1/users/:id', validateJWT, requireScope('admin'), async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});

// Only users with specific permissions can access reports
app.get('/v1/reports/financial',
  validateJWT,
  requireScope('read:financial_reports'),
  getFinancialReports
);
```

### Advanced: Attribute-Based Access Control (ABAC)

```javascript
// ✅ More granular control
const checkPermission = (resource, action) => {
  return async (req, res, next) => {
    const user = req.user;
    const resourceId = req.params.id;

    // Check if user has permission for this specific resource
    const hasPermission = await db.query(
      `SELECT 1 FROM permissions
       WHERE user_id = ?
       AND resource_type = ?
       AND resource_id = ?
       AND action = ?`,
      [user.sub, resource, resourceId, action]
    );

    if (!hasPermission) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  };
};

app.patch('/v1/projects/:id',
  validateJWT,
  checkPermission('project', 'update'),
  updateProject
);
```

---

## API6:2023 - Unrestricted Access to Sensitive Business Flows

**Description**: APIs expose business flows that can be abused if not properly protected.

### Mitigations

```javascript
// ✅ 1. CAPTCHA for sensitive operations
const verifyCaptcha = async (token) => {
  const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: `secret=${RECAPTCHA_SECRET}&response=${token}`
  });
  const data = await response.json();
  return data.success;
};

app.post('/v1/auth/register', async (req, res) => {
  const { captcha_token } = req.body;

  if (!await verifyCaptcha(captcha_token)) {
    return res.status(400).json({ error: 'Invalid captcha' });
  }

  // Process registration...
});

// ✅ 2. Transaction limits
app.post('/v1/transfers', validateJWT, async (req, res) => {
  const { amount } = req.body;

  // Daily transfer limit
  const todayTotal = await getTodayTransferTotal(req.user.sub);
  if (todayTotal + amount > 10000) {
    return res.status(429).json({
      error: 'Daily transfer limit exceeded'
    });
  }

  // Process transfer...
});

// ✅ 3. Step-up authentication for critical actions
app.delete('/v1/account', validateJWT, async (req, res) => {
  const { confirmation_token } = req.body;

  // Require recent re-authentication
  if (!await verifyRecentAuth(req.user.sub, confirmation_token)) {
    return res.status(403).json({
      error: 'Recent authentication required'
    });
  }

  // Delete account...
});

// ✅ 4. Anomaly detection
const detectAnomaly = async (userId, action) => {
  const recentActions = await getRecentActions(userId, action);

  // Check for unusual patterns
  if (recentActions.length > 50) {
    await flagSuspiciousActivity(userId);
    return true;
  }

  return false;
};
```

---

## API7:2023 - Server Side Request Forgery (SSRF)

**Description**: APIs accept URLs from users without proper validation, allowing attackers to make requests to internal services.

### Vulnerable Example

```javascript
// ❌ VULNERABLE: User-controlled URL
app.post('/v1/fetch', async (req, res) => {
  const { url } = req.body;
  const response = await fetch(url); // Can target internal services!
  res.json(await response.json());
});

// Attack examples:
// http://localhost:9200/_cluster/health (Elasticsearch)
// http://169.254.169.254/latest/meta-data/ (AWS metadata)
// http://internal-admin.company.local/
```

### Secure Implementation

```javascript
// ✅ SECURE: Whitelist allowed hosts
const ALLOWED_HOSTS = ['api.trusted.com', 'cdn.example.com'];

const isPrivateIP = (ip) => {
  // Check for private IP ranges
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(ip);
};

app.post('/v1/fetch', async (req, res) => {
  let url;
  try {
    url = new URL(req.body.url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Check protocol
  if (!['http:', 'https:'].includes(url.protocol)) {
    return res.status(400).json({ error: 'Invalid protocol' });
  }

  // Check hostname whitelist
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    return res.status(400).json({
      error: 'Host not allowed',
      allowed_hosts: ALLOWED_HOSTS
    });
  }

  // Resolve DNS and check for private IPs
  const dns = require('dns').promises;
  const addresses = await dns.resolve4(url.hostname);
  if (addresses.some(isPrivateIP)) {
    return res.status(400).json({ error: 'Private IPs not allowed' });
  }

  // Make request with timeout
  const response = await fetch(url.toString(), { timeout: 5000 });
  res.json(await response.json());
});
```

---

## API8:2023 - Security Misconfiguration

**Description**: APIs with improper security configurations are vulnerable to attacks.

### Security Headers

```javascript
// ✅ Configure security headers
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:']
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Additional headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
```

### CORS Configuration

```javascript
// ❌ VULNERABLE: Permissive CORS
app.use(cors({ origin: '*' }));

// ✅ SECURE: Restrictive CORS
const cors = require('cors');

const corsOptions = {
  origin: (origin, callback) => {
    const whitelist = ['https://app.example.com', 'https://www.example.com'];
    if (!origin || whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
```

### Environment Configuration

```javascript
// ✅ Secure configuration
if (process.env.NODE_ENV === 'production') {
  // Disable debug mode
  app.set('x-powered-by', false);
  app.disable('x-powered-by');

  // Force HTTPS
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.hostname + req.url);
    }
    next();
  });

  // Strict error handling (no stack traces)
  app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
  });
}
```

---

## API9:2023 - Improper Inventory Management

**Description**: Organizations lack visibility into all their APIs, leading to unpatched vulnerabilities.

### Best Practices

1. **API Gateway**: Centralize API management
2. **API Catalog**: Maintain inventory of all endpoints
3. **Version Management**: Track and retire old versions
4. **Documentation**: Keep OpenAPI specs up-to-date
5. **Monitoring**: Track usage of all endpoints

```javascript
// ✅ API versioning with sunset dates
app.use('/v1', (req, res, next) => {
  res.setHeader('Sunset', 'Sat, 31 Dec 2024 23:59:59 GMT');
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', '</v2>; rel="successor-version"');
  next();
});

// ✅ Log all API usage for inventory
app.use((req, res, next) => {
  logger.info({
    method: req.method,
    path: req.path,
    version: req.headers['api-version'],
    user: req.user?.sub
  });
  next();
});
```

---

## API10:2023 - Unsafe Consumption of APIs

**Description**: APIs integrate with third-party services without proper validation.

### Secure Integration

```javascript
// ✅ Validate external API responses
const fetchUserFromExternalAPI = async (userId) => {
  try {
    const response = await fetch(
      `https://external-api.com/users/${userId}`,
      {
        timeout: 5000,
        headers: { 'Authorization': `Bearer ${API_KEY}` }
      }
    );

    if (!response.ok) {
      throw new Error(`External API error: ${response.status}`);
    }

    const data = await response.json();

    // Validate response structure
    if (!data.id || !data.email) {
      throw new Error('Invalid response structure');
    }

    // Sanitize data before using
    return {
      id: String(data.id),
      email: validator.normalizeEmail(data.email),
      name: validator.escape(data.name)
    };
  } catch (error) {
    logger.error('External API error', error);
    throw new Error('Failed to fetch user data');
  }
};

// ✅ Use circuit breaker pattern
const CircuitBreaker = require('opossum');

const breaker = new CircuitBreaker(fetchUserFromExternalAPI, {
  timeout: 5000,
  errorThresholdPercentage: 50,
  resetTimeout: 30000
});

breaker.fallback(() => {
  return { error: 'External service unavailable' };
});
```
