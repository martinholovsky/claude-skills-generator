# JSON-RPC Advanced Patterns

## WebSocket Transport

```typescript
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", (ws) => {
  ws.on("message", async (data) => {
    try {
      const request = JSON.parse(data.toString());
      const response = await server.handleRequest(request);

      if (response) {
        ws.send(JSON.stringify(response));
      }
    } catch (error) {
      ws.send(JSON.stringify({
        jsonrpc: "2.0",
        error: { code: -32700, message: "Parse error" },
        id: null
      }));
    }
  });
});
```

## Request Context

```typescript
// Pass context through request chain
interface RequestContext {
  requestId: string;
  userId?: string;
  ip: string;
  startTime: number;
}

class ContextualJSONRPCServer {
  async handleRequest(request: unknown, context: RequestContext) {
    // Context available to all method handlers
    return this.handleSingleRequest(request, context);
  }
}
```

## Method Namespacing

```typescript
// Organize methods by namespace
server.registerNamespace("user", {
  "get": getUserHandler,
  "create": createUserHandler,
  "delete": deleteUserHandler
});

server.registerNamespace("admin", {
  "stats": getStatsHandler,
  "config": getConfigHandler
});

// Access as user.get, admin.stats
```

## Middleware Chain

```typescript
type Middleware = (ctx: Context, next: () => Promise<void>) => Promise<void>;

class MiddlewareJSONRPCServer {
  private middlewares: Middleware[] = [];

  use(middleware: Middleware): void {
    this.middlewares.push(middleware);
  }

  async executeWithMiddleware(ctx: Context): Promise<void> {
    let index = 0;

    const next = async (): Promise<void> => {
      if (index < this.middlewares.length) {
        const middleware = this.middlewares[index++];
        await middleware(ctx, next);
      }
    };

    await next();
  }
}

// Usage
server.use(authMiddleware);
server.use(rateLimitMiddleware);
server.use(loggingMiddleware);
```
