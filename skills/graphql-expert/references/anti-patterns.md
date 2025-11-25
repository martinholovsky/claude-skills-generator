# GraphQL Anti-Patterns & Common Mistakes

## Performance Anti-Patterns

### Mistake 1: N+1 Query Problem

**Problem:**
```typescript
// ❌ DON'T - Causes N+1 queries
const resolvers = {
  Query: {
    posts: async () => {
      return await Post.findMany(); // 1 query
    },
  },

  Post: {
    author: async (post) => {
      // This runs a separate query for EACH post
      // If you have 100 posts, this runs 100 queries!
      return await User.findById(post.authorId); // N queries
    },

    comments: async (post) => {
      // Another N queries!
      return await Comment.findByPostId(post.id);
    },
  },
};

// Query that triggers N+1:
// query {
//   posts {        # 1 query
//     author {     # 100 queries (if 100 posts)
//       name
//     }
//     comments {   # 100 more queries
//       text
//     }
//   }
// }
// Total: 201 database queries!
```

**Solution:**
```typescript
// ✅ DO - Use DataLoader for batching
import DataLoader from 'dataloader';

class DataLoaders {
  userLoader = new DataLoader<string, User>(
    async (userIds) => {
      // Single batched query
      const users = await User.findMany({
        where: { id: { in: [...userIds] } },
      });

      const userMap = new Map(users.map(u => [u.id, u]));
      return userIds.map(id => userMap.get(id) || null);
    }
  );

  commentsByPostLoader = new DataLoader<string, Comment[]>(
    async (postIds) => {
      // Single batched query
      const comments = await Comment.findMany({
        where: { postId: { in: [...postIds] } },
      });

      const commentsByPost = new Map<string, Comment[]>();
      postIds.forEach(id => commentsByPost.set(id, []));
      comments.forEach(c => {
        const postComments = commentsByPost.get(c.postId) || [];
        postComments.push(c);
        commentsByPost.set(c.postId, postComments);
      });

      return postIds.map(id => commentsByPost.get(id) || []);
    }
  );
}

const resolvers = {
  Post: {
    author: (post, _, { loaders }) => loaders.userLoader.load(post.authorId),
    comments: (post, _, { loaders }) => loaders.commentsByPostLoader.load(post.id),
  },
};

// Same query now runs only 3 queries total!
// 1. Fetch posts
// 2. Batch fetch all authors
// 3. Batch fetch all comments
```

---

### Mistake 2: No Query Complexity Limits

**Problem:**
```typescript
// ❌ DON'T - Allow unlimited query complexity
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // No protection against expensive queries!
});

// Attacker can send this:
// query {
//   posts(first: 10000) {
//     author {
//       posts(first: 10000) {
//         author {
//           posts(first: 10000) {
//             # This could fetch 1 trillion records!
//           }
//         }
//       }
//     }
//   }
// }
```

**Solution:**
```typescript
// ✅ DO - Add complexity and depth limits
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(7), // Max nesting depth
    createComplexityLimitRule(1000), // Max complexity score
  ],
});

// Also limit pagination
const resolvers = {
  Query: {
    posts: async (_, { first }) => {
      const limit = Math.min(first || 10, 100); // Max 100
      return Post.findMany({ first: limit });
    },
  },
};
```

---

### Mistake 3: Not Using Pagination

**Problem:**
```typescript
// ❌ DON'T - Return unbounded lists
type Query {
  posts: [Post!]!  # Could return millions of records
  users: [User!]!
}

const resolvers = {
  Query: {
    posts: () => Post.findAll(), // Returns ALL posts!
  },
};
```

**Solution:**
```typescript
// ✅ DO - Implement cursor-based pagination
type Query {
  posts(first: Int = 10, after: String): PostConnection!
}

type PostConnection {
  edges: [PostEdge!]!
  pageInfo: PageInfo!
}

type PostEdge {
  node: Post!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  endCursor: String
}

const resolvers = {
  Query: {
    posts: async (_, { first = 10, after }) => {
      const limit = Math.min(first, 100);
      const posts = await Post.findMany({
        take: limit + 1, // Fetch one extra to check hasNextPage
        cursor: after ? { id: after } : undefined,
      });

      const hasNextPage = posts.length > limit;
      const edges = posts.slice(0, limit).map(post => ({
        node: post,
        cursor: post.id,
      }));

      return {
        edges,
        pageInfo: {
          hasNextPage,
          endCursor: edges[edges.length - 1]?.cursor,
        },
      };
    },
  },
};
```

---

## Security Anti-Patterns

### Mistake 4: Missing Field-Level Authorization

**Problem:**
```typescript
// ❌ DON'T - No authorization on sensitive fields
type User {
  id: ID!
  email: String!              # Anyone can see any user's email!
  socialSecurityNumber: String!  # Exposed to everyone!
  salary: Float!              # Private data exposed!
}

const resolvers = {
  Query: {
    user: (_, { id }) => User.findById(id), // No auth check!
  },
};
```

**Solution:**
```typescript
// ✅ DO - Implement field-level authorization
import { shield, rule, and, or } from 'graphql-shield';

const isAuthenticated = rule()(
  (parent, args, ctx) => ctx.user !== null
);

const isOwner = rule()(
  (parent, args, ctx) => parent.id === ctx.user?.id
);

const isAdmin = rule()(
  (parent, args, ctx) => ctx.user?.role === 'ADMIN'
);

const permissions = shield({
  Query: {
    user: isAuthenticated,
  },
  User: {
    email: or(isOwner, isAdmin),
    socialSecurityNumber: and(isOwner, isAdmin),
    salary: or(isOwner, isAdmin),
  },
});

// Or use directives
type User {
  id: ID!
  email: String! @auth
  socialSecurityNumber: String! @auth(requires: ADMIN)
  salary: Float! @auth
}
```

---

### Mistake 5: Not Validating Input

**Problem:**
```typescript
// ❌ DON'T - Trust user input
const resolvers = {
  Mutation: {
    createPost: async (_, { input }) => {
      // No validation!
      return db.insert('posts', input);
    },

    updateUser: async (_, { id, email }) => {
      // No email validation!
      return User.update(id, { email });
    },
  },
};

// Attacker can send:
// mutation {
//   createPost(input: {
//     title: "A".repeat(1000000)  # 1 million characters
//     content: "<script>alert('xss')</script>"
//   })
// }
```

**Solution:**
```typescript
// ✅ DO - Validate all inputs
import { z } from 'zod';

const CreatePostInputSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(10000),
  tags: z.array(z.string()).max(10).optional(),
});

const EmailSchema = z.string().email();

const resolvers = {
  Mutation: {
    createPost: async (_, { input }, { user }) => {
      // Validate input
      const validation = CreatePostInputSchema.safeParse(input);
      if (!validation.success) {
        return {
          post: null,
          errors: validation.error.errors.map(err => ({
            message: err.message,
            field: err.path.join('.'),
            code: 'VALIDATION_ERROR',
          })),
        };
      }

      return PostService.create({
        ...validation.data,
        authorId: user.id,
      });
    },

    updateUser: async (_, { id, email }, { user }) => {
      // Validate email
      if (!EmailSchema.safeParse(email).success) {
        throw new GraphQLError('Invalid email format');
      }

      return User.update(id, { email });
    },
  },
};
```

---

### Mistake 6: Exposing Internal Errors

**Problem:**
```typescript
// ❌ DON'T - Expose internal error details
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      try {
        return await db.query(
          'SELECT * FROM users WHERE id = $1',
          [id]
        );
      } catch (error) {
        // Exposes database structure and internals!
        throw new Error(`Database error: ${error.message}\n${error.stack}`);
      }
    },
  },
};

// Error response exposes:
// {
//   "errors": [{
//     "message": "Database error: relation 'users_internal_v2' does not exist",
//     "extensions": {
//       "stacktrace": [
//         "at Object.query (/app/db/index.js:42:15)",
//         "at /app/src/database/postgres.ts:123:45"
//       ]
//     }
//   }]
// }
```

**Solution:**
```typescript
// ✅ DO - Sanitize error messages
const formatError = (error) => {
  // Log full error internally
  console.error('GraphQL Error:', {
    message: error.message,
    stack: error.stack,
    path: error.path,
  });

  // Production: sanitize errors
  if (process.env.NODE_ENV === 'production') {
    return {
      message: 'An error occurred',
      extensions: {
        code: error.extensions?.code || 'INTERNAL_ERROR',
      },
    };
  }

  // Development: show details (but still remove stack)
  return {
    message: error.message,
    extensions: {
      code: error.extensions?.code,
    },
  };
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  formatError,
});
```

---

### Mistake 7: Introspection Enabled in Production

**Problem:**
```typescript
// ❌ DON'T - Leave introspection enabled
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Exposes entire schema!
});

// Attacker can discover your entire API:
// query {
//   __schema {
//     types {
//       name
//       fields {
//         name
//       }
//     }
//   }
// }
```

**Solution:**
```typescript
// ✅ DO - Disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',

  // Or conditional introspection for admins only
  plugins: [{
    async requestDidStart({ request, contextValue }) {
      if (request.operationName === 'IntrospectionQuery') {
        if (!contextValue.user?.isAdmin) {
          throw new GraphQLError('Forbidden');
        }
      }
    },
  }],
});
```

---

## Schema Design Anti-Patterns

### Mistake 8: Poor Nullability Design

**Problem:**
```typescript
// ❌ DON'T - Everything nullable or everything non-null
type User {
  id: ID            # Could be null?
  email: String     # Should this ever be null?
  name: String!     # What if user hasn't set a name?
  posts: [Post]!    # Array can't be null but items can?
}
```

**Solution:**
```typescript
// ✅ DO - Thoughtful nullability
type User {
  id: ID!              # ID is always required
  email: String!       # Email is always present
  displayName: String  # Optional: user may not have set it
  bio: String          # Optional: user may not have bio
  posts: [Post!]!      # Array never null, items never null
  avatar: URL          # Optional: user may not have avatar
}
```

---

### Mistake 9: Not Using Proper Error Types

**Problem:**
```typescript
// ❌ DON'T - Throw errors for expected conditions
type Mutation {
  createPost(input: CreatePostInput!): Post!
}

const resolvers = {
  Mutation: {
    createPost: async (_, { input }) => {
      if (!input.title) {
        throw new Error('Title is required'); // Forces client to parse errors
      }

      return Post.create(input);
    },
  },
};
```

**Solution:**
```typescript
// ✅ DO - Use union types or error fields
type Mutation {
  createPost(input: CreatePostInput!): CreatePostPayload!
}

type CreatePostPayload {
  post: Post
  errors: [UserError!]
}

type UserError {
  message: String!
  field: String
  code: ErrorCode!
}

enum ErrorCode {
  VALIDATION_ERROR
  UNAUTHORIZED
  NOT_FOUND
}

const resolvers = {
  Mutation: {
    createPost: async (_, { input }) => {
      if (!input.title) {
        return {
          post: null,
          errors: [{
            message: 'Title is required',
            field: 'title',
            code: 'VALIDATION_ERROR',
          }],
        };
      }

      const post = await Post.create(input);
      return { post, errors: [] };
    },
  },
};
```

---

### Mistake 10: Blocking Operations in Resolvers

**Problem:**
```typescript
// ❌ DON'T - Use synchronous/blocking operations
const resolvers = {
  Query: {
    user: (_, { id }) => {
      // Blocks the event loop!
      const data = fs.readFileSync(`/users/${id}.json`);
      return JSON.parse(data);
    },

    processData: () => {
      // CPU-intensive blocking operation
      let result = 0;
      for (let i = 0; i < 1000000000; i++) {
        result += Math.sqrt(i);
      }
      return result;
    },
  },
};
```

**Solution:**
```typescript
// ✅ DO - Use async operations
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      // Non-blocking I/O
      const data = await fs.promises.readFile(`/users/${id}.json`);
      return JSON.parse(data);
    },

    processData: async () => {
      // Offload to worker thread
      return new Promise((resolve) => {
        const worker = new Worker('./worker.js');
        worker.on('message', resolve);
        worker.postMessage({ type: 'process' });
      });
    },
  },
};
```

---

## Testing Anti-Patterns

### Mistake 11: Not Testing Resolvers

**Problem:**
```typescript
// ❌ DON'T - Skip resolver tests
// No tests for business logic
```

**Solution:**
```typescript
// ✅ DO - Test resolvers thoroughly
import { expect, test } from 'vitest';

test('createPost resolver validates input', async () => {
  const result = await resolvers.Mutation.createPost(
    null,
    { input: { title: '', content: 'test' } },
    { user: { id: '1' } }
  );

  expect(result.errors).toHaveLength(1);
  expect(result.errors[0].code).toBe('VALIDATION_ERROR');
});

test('createPost requires authentication', async () => {
  await expect(
    resolvers.Mutation.createPost(
      null,
      { input: { title: 'test', content: 'test' } },
      { user: null }
    )
  ).rejects.toThrow('Authentication required');
});
```
