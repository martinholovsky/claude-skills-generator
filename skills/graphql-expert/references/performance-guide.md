# GraphQL Performance Optimization Guide

## Query Complexity & Depth Limiting

### Complexity Analysis Configuration

```typescript
import { ApolloServer } from '@apollo/server';
import { createComplexityLimitRule } from 'graphql-validation-complexity';
import depthLimit from 'graphql-depth-limit';

// ✅ Complexity analysis
const complexityLimit = createComplexityLimitRule(1000, {
  // Custom complexity per field
  scalarCost: 1,
  objectCost: 2,
  listFactor: 10,

  // Field-specific costs
  formatCosts: (cost, args, ctx, field) => {
    // Lists with arguments (pagination) cost more
    if (field.type.toString().includes('[') && args.first) {
      return cost * Math.min(args.first, 100);
    }
    return cost;
  },

  onCost: (cost) => {
    console.log('Query cost:', cost);
  },
});
```

### Apollo Server Configuration with Limits

```typescript
// ✅ Apollo Server configuration
const server = new ApolloServer({
  typeDefs,
  resolvers,

  validationRules: [
    depthLimit(7), // Max query depth
    complexityLimit,
  ],

  plugins: [
    {
      async requestDidStart() {
        return {
          async didResolveOperation({ request, document }) {
            // Log query complexity
            const complexity = calculateComplexity({
              schema,
              query: document,
              variables: request.variables,
            });

            if (complexity > 1000) {
              throw new GraphQLError('Query is too complex', {
                extensions: {
                  code: 'COMPLEXITY_LIMIT_EXCEEDED',
                  complexity,
                },
              });
            }
          },

          async executionDidStart() {
            const startTime = Date.now();

            return {
              async executionDidEnd() {
                const duration = Date.now() - startTime;

                // Timeout protection
                if (duration > 10000) {
                  console.warn('Slow query detected:', duration);
                }
              },
            };
          },
        };
      },
    },
  ],
});
```

### Query Timeout Implementation

```typescript
// ✅ Query timeout
const resolvers = {
  Query: {
    posts: async (_, args, ctx) => {
      // Limit expensive queries
      if (args.first > 100) {
        throw new GraphQLError('Maximum limit is 100', {
          extensions: { code: 'BAD_USER_INPUT' },
        });
      }

      // Set query timeout
      return Promise.race([
        Post.findMany(args),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Query timeout')), 5000)
        ),
      ]);
    },
  },
};
```

---

## Advanced DataLoader Patterns

### Multi-Key DataLoader

```typescript
import DataLoader from 'dataloader';

class DataLoaders {
  // Composite key loader
  postsByAuthorAndStatusLoader = new DataLoader<
    { authorId: string; status: string },
    Post[]
  >(
    async (keys) => {
      // Extract unique author IDs and statuses
      const authorIds = [...new Set(keys.map(k => k.authorId))];
      const statuses = [...new Set(keys.map(k => k.status))];

      // Single query with all combinations
      const posts = await Post.findMany({
        where: {
          authorId: { in: authorIds },
          status: { in: statuses },
        },
      });

      // Group by composite key
      const postsByKey = new Map<string, Post[]>();
      keys.forEach(key => {
        const mapKey = `${key.authorId}:${key.status}`;
        postsByKey.set(mapKey, []);
      });

      posts.forEach(post => {
        const mapKey = `${post.authorId}:${post.status}`;
        const existingPosts = postsByKey.get(mapKey) || [];
        existingPosts.push(post);
        postsByKey.set(mapKey, existingPosts);
      });

      return keys.map(key => {
        const mapKey = `${key.authorId}:${key.status}`;
        return postsByKey.get(mapKey) || [];
      });
    },
    {
      // Custom cache key function
      cacheKeyFn: (key) => `${key.authorId}:${key.status}`,
    }
  );
}
```

### Primed DataLoader Cache

```typescript
// Pre-populate DataLoader cache
const resolvers = {
  Query: {
    posts: async (_, { first, after }, { loaders }) => {
      const posts = await Post.findMany({ first, after });

      // Prime the cache with fetched posts
      posts.forEach(post => {
        loaders.postLoader.prime(post.id, post);
        // Also prime related data
        if (post.author) {
          loaders.userLoader.prime(post.authorId, post.author);
        }
      });

      return posts;
    },
  },
};
```

---

## Caching Strategies

### Field-Level Caching

```typescript
import { InMemoryLRUCache } from '@apollo/utils.keyvaluecache';

const cache = new InMemoryLRUCache({
  maxSize: Math.pow(2, 20) * 100, // 100 MB
  ttl: 300, // 5 minutes
});

const resolvers = {
  Query: {
    popularPosts: async (_, __, { cache }) => {
      const cacheKey = 'popular_posts';

      // Check cache first
      const cached = await cache.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }

      // Compute expensive query
      const posts = await Post.findPopular();

      // Store in cache
      await cache.set(cacheKey, JSON.stringify(posts), { ttl: 300 });

      return posts;
    },
  },
};
```

### Persisted Queries

```typescript
import { ApolloServer } from '@apollo/server';
import { createPersistedQueryLink } from '@apollo/client/link/persisted-queries';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  persistedQueries: {
    cache: new InMemoryLRUCache(),
    ttl: 900, // 15 minutes
  },
});

// Client-side configuration
const link = createPersistedQueryLink({
  sha256,
  useGETForHashedQueries: true,
});
```

---

## Database Query Optimization

### Projection/Selection Optimization

```typescript
import { parseResolveInfo, simplifyParsedResolveInfoFragmentWithType } from 'graphql-parse-resolve-info';

const resolvers = {
  Query: {
    user: async (_, { id }, ctx, info) => {
      // Parse requested fields from GraphQL query
      const parsedInfo = parseResolveInfo(info);
      const { fields } = simplifyParsedResolveInfoFragmentWithType(parsedInfo, info.returnType);

      // Only select requested fields from database
      const select = {};
      if (fields.email) select.email = true;
      if (fields.profile) select.profile = true;

      return db.user.findUnique({
        where: { id },
        select,
      });
    },
  },
};
```

### Batched Database Writes

```typescript
const resolvers = {
  Mutation: {
    createPosts: async (_, { inputs }, { user }) => {
      // Batch insert instead of individual inserts
      const posts = await db.$transaction(
        inputs.map(input =>
          db.post.create({
            data: {
              ...input,
              authorId: user.id,
            },
          })
        )
      );

      return { posts, errors: [] };
    },
  },
};
```

---

## Performance Monitoring

### Query Performance Plugin

```typescript
const performanceMonitoringPlugin = {
  async requestDidStart() {
    const start = Date.now();

    return {
      async willSendResponse({ response, queryHash }) {
        const duration = Date.now() - start;

        // Log slow queries
        if (duration > 1000) {
          console.warn('Slow query detected:', {
            queryHash,
            duration,
            response: response.body,
          });
        }

        // Send to monitoring service
        metrics.recordQueryDuration(queryHash, duration);
      },
    };
  },
};
```

### Resolver-Level Tracing

```typescript
import { wrapResolver } from '@apollo/server';

const tracingPlugin = {
  async requestDidStart() {
    return {
      async executionDidStart() {
        return {
          willResolveField({ info }) {
            const start = Date.now();

            return () => {
              const duration = Date.now() - start;
              console.log(`${info.parentType.name}.${info.fieldName}: ${duration}ms`);
            };
          },
        };
      },
    };
  },
};
```
