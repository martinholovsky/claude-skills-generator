# Advanced GraphQL Patterns

## Apollo Federation

### User Service

```typescript
// ---- User Service ----
import { buildSubgraphSchema } from '@apollo/subgraph';

const typeDefs = gql`
  extend schema
    @link(url: "https://specs.apollo.dev/federation/v2.3",
          import: ["@key", "@shareable"])

  type User @key(fields: "id") {
    id: ID!
    email: String!
    profile: Profile
  }

  type Profile {
    displayName: String!
    bio: String
  }

  type Query {
    me: User
    user(id: ID!): User
  }
`;

const resolvers = {
  Query: {
    me: (_, __, { user }) => user,
    user: (_, { id }) => UserService.findById(id),
  },

  User: {
    // Reference resolver for federation
    __resolveReference: async (reference) => {
      return UserService.findById(reference.id);
    },

    profile: (user) => ProfileService.findByUserId(user.id),
  },
};

const userSubgraph = buildSubgraphSchema({ typeDefs, resolvers });
```

### Posts Service

```typescript
// ---- Posts Service ----
const postTypeDefs = gql`
  extend schema
    @link(url: "https://specs.apollo.dev/federation/v2.3",
          import: ["@key", "@external"])

  # Extend User from user service
  type User @key(fields: "id") {
    id: ID! @external
    posts(first: Int = 10): [Post!]!
  }

  type Post @key(fields: "id") {
    id: ID!
    title: String!
    content: String!
    author: User!
    publishedAt: DateTime
  }

  type Query {
    post(id: ID!): Post
    posts(first: Int = 10): [Post!]!
  }
`;

const postResolvers = {
  Query: {
    post: (_, { id }) => PostService.findById(id),
    posts: (_, { first }) => PostService.findMany({ first }),
  },

  Post: {
    __resolveReference: (reference) => PostService.findById(reference.id),
    author: (post) => ({ __typename: 'User', id: post.authorId }),
  },

  User: {
    // Extend User type with posts field
    posts: (user, { first }) => {
      return PostService.findByAuthorId(user.id, first);
    },
  },
};

const postSubgraph = buildSubgraphSchema({
  typeDefs: postTypeDefs,
  resolvers: postResolvers,
});
```

### Gateway Configuration

```typescript
// ---- Gateway ----
import { ApolloGateway, IntrospectAndCompose } from '@apollo/gateway';

const gateway = new ApolloGateway({
  supergraphSdl: new IntrospectAndCompose({
    subgraphs: [
      { name: 'users', url: 'http://localhost:4001' },
      { name: 'posts', url: 'http://localhost:4002' },
    ],
    pollIntervalInMs: 10000, // Poll for schema changes
  }),

  buildService({ url }) {
    return new RemoteGraphQLDataSource({
      url,
      willSendRequest({ request, context }) {
        // Forward auth headers to subgraphs
        request.http.headers.set('authorization', context.token);
      },
    });
  },
});

const gatewayServer = new ApolloServer({
  gateway,
  subscriptions: false,
});
```

---

## GraphQL Subscriptions

### Real-Time Updates with PubSub

```typescript
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/lib/use/ws';
import { PubSub } from 'graphql-subscriptions';

const pubsub = new PubSub();

const typeDefs = gql`
  type Subscription {
    postCreated: Post!
    postUpdated(id: ID!): Post!
    commentAdded(postId: ID!): Comment!
  }
`;

const resolvers = {
  Mutation: {
    createPost: async (_, { input }, { user }) => {
      const post = await PostService.create({
        ...input,
        authorId: user.id,
      });

      // Publish to subscribers
      await pubsub.publish('POST_CREATED', { postCreated: post });

      return { post, errors: [] };
    },
  },

  Subscription: {
    postCreated: {
      subscribe: () => pubsub.asyncIterator(['POST_CREATED']),
    },

    postUpdated: {
      subscribe: (_, { id }) => {
        return pubsub.asyncIterator([`POST_UPDATED_${id}`]);
      },
    },

    commentAdded: {
      // Filter by postId
      subscribe: withFilter(
        () => pubsub.asyncIterator(['COMMENT_ADDED']),
        (payload, variables) => {
          return payload.commentAdded.postId === variables.postId;
        }
      ),
    },
  },
};
```

### WebSocket Server Setup

```typescript
// WebSocket server setup
const wsServer = new WebSocketServer({
  server: httpServer,
  path: '/graphql',
});

useServer(
  {
    schema,
    context: async (ctx) => {
      // Authenticate WebSocket connections
      const token = ctx.connectionParams?.authorization;
      const user = await authenticateToken(token);
      return { user };
    },
    onConnect: async (ctx) => {
      console.log('Client connected');
    },
    onDisconnect: () => {
      console.log('Client disconnected');
    },
  },
  wsServer
);
```

---

## Advanced Error Handling

### Custom Error Types

```typescript
import { GraphQLError } from 'graphql';
import { ApolloServerErrorCode } from '@apollo/server/errors';

// ✅ Custom error types
class ValidationError extends GraphQLError {
  constructor(message: string, field?: string) {
    super(message, {
      extensions: {
        code: 'VALIDATION_ERROR',
        field,
      },
    });
  }
}

class NotFoundError extends GraphQLError {
  constructor(resource: string, id: string) {
    super(`${resource} not found`, {
      extensions: {
        code: 'NOT_FOUND',
        resource,
        id,
      },
    });
  }
}
```

### Input Validation with Zod

```typescript
import { z } from 'zod';

const CreatePostInputSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(10000),
  status: z.enum(['DRAFT', 'PUBLISHED']).default('DRAFT'),
});

const resolvers = {
  Mutation: {
    createPost: async (_, { input }, { user, loaders }) => {
      // Authentication check
      if (!user) {
        throw new GraphQLError('Authentication required', {
          extensions: { code: 'UNAUTHENTICATED' },
        });
      }

      // Input validation
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

      try {
        const post = await PostService.create({
          ...validation.data,
          authorId: user.id,
        });

        return { post, errors: [] };
      } catch (error) {
        // Don't expose internal errors
        console.error('Failed to create post:', error);

        return {
          post: null,
          errors: [{
            message: 'Failed to create post',
            code: 'INTERNAL_ERROR',
          }],
        };
      }
    },
  },
};
```

### Error Formatting Plugin

```typescript
// ✅ Error formatting plugin
const errorFormattingPlugin = {
  async requestDidStart() {
    return {
      async didEncounterErrors({ errors }) {
        errors.forEach(error => {
          // Log internal errors
          console.error('GraphQL Error:', {
            message: error.message,
            path: error.path,
            extensions: error.extensions,
          });

          // Remove stack traces in production
          if (process.env.NODE_ENV === 'production') {
            delete error.extensions?.stacktrace;
          }
        });
      },
    };
  },
};
```

---

## Custom Authorization Directives

### Directive Transformer

```typescript
import { mapSchema, getDirective, MapperKind } from '@graphql-tools/utils';

function authDirective(directiveName: string) {
  return (schema) => {
    return mapSchema(schema, {
      [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
        const authDirective = getDirective(schema, fieldConfig, directiveName)?.[0];

        if (authDirective) {
          const { resolve = defaultFieldResolver } = fieldConfig;
          const { requires } = authDirective;

          fieldConfig.resolve = async function (source, args, context, info) {
            if (requires === 'ADMIN' && context.user?.role !== 'ADMIN') {
              throw new GraphQLError('Admin access required');
            }

            return resolve(source, args, context, info);
          };
        }

        return fieldConfig;
      },
    });
  };
}
```

### Schema with Custom Directives

```typescript
// Schema with directive
const typeDefs = `
  directive @auth(requires: Role = USER) on FIELD_DEFINITION

  enum Role {
    USER
    ADMIN
  }

  type User {
    id: ID!
    email: String! @auth
    role: Role! @auth(requires: ADMIN)
  }
`;
```
