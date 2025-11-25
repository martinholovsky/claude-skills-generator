# GraphQL Security Examples & Vulnerabilities

## Critical Security Vulnerabilities

### 1. Unbounded Query Attacks

**Attack Example:**
```graphql
# ❌ Malicious query - can crash server
query {
  posts(first: 999999) {
    author {
      posts(first: 999999) {
        author {
          posts(first: 999999) {
            author {
              posts(first: 999999) {
                # Exponential data explosion
                # Can request millions of records
              }
            }
          }
        }
      }
    }
  }
}
```

**Impact:**
- Server memory exhaustion
- Database overload
- Service denial for legitimate users
- Potential server crash

**Mitigation:**

```typescript
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(7), // Max query depth
    createComplexityLimitRule(1000), // Max complexity score
  ],
});

// Also limit pagination arguments
const resolvers = {
  Query: {
    posts: async (_, { first }) => {
      if (first > 100) {
        throw new GraphQLError('Maximum limit is 100');
      }
      return Post.findMany({ first });
    },
  },
};
```

---

### 2. Introspection Exposure

**Attack:**
```graphql
# Attacker discovers your entire schema
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

**Risk:**
- Exposes internal API structure
- Reveals hidden fields and types
- Helps attackers find vulnerabilities
- Leaks business logic

**Mitigation:**

```typescript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Disable in production
  introspection: process.env.NODE_ENV !== 'production',

  // Or use conditional introspection
  plugins: [
    {
      async requestDidStart({ request, contextValue }) {
        // Only allow introspection for admins
        if (request.operationName === 'IntrospectionQuery') {
          if (!contextValue.user?.isAdmin) {
            throw new GraphQLError('Introspection disabled');
          }
        }
      },
    },
  ],
});
```

---

### 3. Field-Level Authorization Bypass

**Attack:**
```graphql
# Attacker requests sensitive fields
query {
  user(id: "123") {
    email              # Should be private
    socialSecurityNumber  # Admin-only field
    password           # Should never be exposed
    creditCard         # Sensitive data
  }
}
```

**Risk:**
- Unauthorized data access
- Privacy violations
- Compliance issues (GDPR, HIPAA)
- Data leaks

**Mitigation with graphql-shield:**

```typescript
import { shield, rule, and, or } from 'graphql-shield';

const isAuthenticated = rule()(
  async (parent, args, ctx) => ctx.user !== null
);

const isAdmin = rule()(
  async (parent, args, ctx) => ctx.user?.role === 'ADMIN'
);

const isOwner = rule()(
  async (parent, args, ctx) => parent.id === ctx.user?.id
);

const permissions = shield({
  Query: {
    user: isAuthenticated,
  },
  User: {
    email: or(isOwner, isAdmin),
    socialSecurityNumber: isAdmin,
    // Never expose password field
    password: () => false,
  },
});
```

---

### 4. Batch Query Attacks

**Attack:**
```graphql
# Send 1000+ queries in a single request
query {
  q1: user(id: "1") { email }
  q2: user(id: "2") { email }
  q3: user(id: "3") { email }
  # ... repeated 1000+ times
}
```

**Mitigation:**

```typescript
import { ApolloServerPluginInlineTrace } from '@apollo/server/plugin/inlineTrace';

const queryLimitPlugin = {
  async requestDidStart({ request }) {
    // Count operation aliases
    const operationCount = Object.keys(request.query.match(/\w+:/g) || []).length;

    if (operationCount > 10) {
      throw new GraphQLError('Too many operations in single request');
    }
  },
};
```

---

### 5. SQL Injection via Resolvers

**Vulnerable Code:**
```typescript
// ❌ NEVER DO THIS
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      // Direct string interpolation - VULNERABLE!
      const query = `SELECT * FROM users WHERE id = '${id}'`;
      return db.raw(query);
    },
  },
};
```

**Attack:**
```graphql
query {
  user(id: "1' OR '1'='1") {
    email
  }
}
```

**Mitigation:**

```typescript
// ✅ Use parameterized queries
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      // Parameterized query - SAFE
      return db.user.findUnique({
        where: { id }, // ORM handles sanitization
      });
    },
  },
};
```

---

### 6. Information Disclosure via Error Messages

**Vulnerable:**
```typescript
// ❌ Exposes internal details
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      try {
        return await db.query('SELECT * FROM users WHERE id = $1', [id]);
      } catch (error) {
        // Exposes database structure!
        throw new Error(`Database error: ${error.message}`);
      }
    },
  },
};
```

**Mitigation:**

```typescript
// ✅ Sanitize error messages
const formatError = (error) => {
  // Log full error internally
  console.error('Internal error:', error);

  // Return sanitized error to client
  if (process.env.NODE_ENV === 'production') {
    return {
      message: 'An error occurred',
      extensions: {
        code: error.extensions?.code || 'INTERNAL_SERVER_ERROR',
      },
    };
  }

  // Development: show details
  return error;
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  formatError,
});
```

---

### 7. Denial of Service via Circular Queries

**Attack:**
```graphql
query {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            # Circular reference explosion
          }
        }
      }
    }
  }
}
```

**Mitigation:**

```typescript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5), // Prevent deep nesting
  ],
});
```

---

## OWASP Top 10 2025 - GraphQL Specific Mitigations

### A01:2025 - Broken Access Control

**Implement Field-Level Authorization:**

```typescript
import { shield, rule } from 'graphql-shield';

const canAccessField = rule()(
  async (parent, args, ctx, info) => {
    const fieldName = info.fieldName;
    const userId = ctx.user?.id;

    // Check permissions in database
    const hasAccess = await PermissionService.canAccess(
      userId,
      parent.__typename,
      fieldName
    );

    return hasAccess;
  }
);

const permissions = shield({
  User: {
    '*': canAccessField, // Apply to all fields
  },
});
```

### A04:2025 - Insecure Design

**Implement Rate Limiting:**

```typescript
import rateLimit from 'graphql-rate-limit';

const rateLimitDirective = rateLimit({
  identifyContext: (ctx) => ctx.user?.id || ctx.ip,
  formatError: () => new GraphQLError('Rate limit exceeded'),
});

const typeDefs = gql`
  directive @rateLimit(
    max: Int = 10
    window: String = "1m"
  ) on FIELD_DEFINITION

  type Query {
    expensiveQuery: [Result!]! @rateLimit(max: 5, window: "1m")
  }
`;
```

### A05:2025 - Security Misconfiguration

**Secure Production Configuration:**

```typescript
const server = new ApolloServer({
  typeDefs,
  resolvers,

  // Production security settings
  introspection: false,
  playground: false,
  debug: false,

  validationRules: [
    depthLimit(7),
    complexityLimit(1000),
  ],

  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],

  formatError: sanitizeError,
});
```

---

## Security Checklist

- [ ] Query depth limiting (≤7 levels)
- [ ] Query complexity analysis
- [ ] Introspection disabled in production
- [ ] Field-level authorization
- [ ] Input validation on all mutations
- [ ] Rate limiting per user/IP
- [ ] Parameterized database queries
- [ ] Error message sanitization
- [ ] No sensitive data in schema
- [ ] Authentication on all protected fields
- [ ] HTTPS only in production
- [ ] CORS properly configured
- [ ] No password fields in types
- [ ] Audit logging for sensitive operations
- [ ] Regular security audits
