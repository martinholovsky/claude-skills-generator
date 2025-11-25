# MCP Advanced Implementation Patterns

## Multi-Server Architecture

```typescript
// Hub server that routes to specialized servers
class MCPRouter {
  private servers: Map<string, MCPClient> = new Map();

  async routeToolCall(toolName: string, args: unknown): Promise<ToolResult> {
    // Determine target server based on tool prefix
    const serverName = this.getServerForTool(toolName);
    const client = this.servers.get(serverName);

    if (!client) {
      throw new Error(`No server registered for tool: ${toolName}`);
    }

    return await client.callTool(toolName, args);
  }

  private getServerForTool(toolName: string): string {
    if (toolName.startsWith("db_")) return "database-server";
    if (toolName.startsWith("file_")) return "filesystem-server";
    if (toolName.startsWith("web_")) return "web-server";
    return "default-server";
  }
}
```

## Streaming Tool Results

```typescript
// Stream large tool results
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "stream_logs") {
    // Return streaming response
    const stream = createLogStream(args.filter);

    const chunks: TextContent[] = [];
    for await (const chunk of stream) {
      chunks.push({ type: "text", text: chunk });
    }

    return { content: chunks, isStreaming: true };
  }
});
```

## Dynamic Tool Registration

```typescript
// Register tools dynamically based on user capabilities
class DynamicToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  async getToolsForUser(userId: string): Promise<Tool[]> {
    const userCaps = await getUserCapabilities(userId);

    return Array.from(this.tools.values())
      .filter(tool => this.userCanAccessTool(userCaps, tool))
      .map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema
      }));
  }

  private userCanAccessTool(caps: UserCapabilities, tool: ToolDefinition): boolean {
    return tool.requiredCapabilities.every(cap => caps.has(cap));
  }
}
```

## Caching Tool Results

```typescript
// Cache expensive tool results
import { createHash } from "crypto";

class ToolResultCache {
  private cache: Map<string, CachedResult> = new Map();

  async getCachedOrExecute(
    toolName: string,
    args: unknown,
    executor: () => Promise<ToolResult>
  ): Promise<ToolResult> {
    const cacheKey = this.createCacheKey(toolName, args);
    const cached = this.cache.get(cacheKey);

    if (cached && Date.now() < cached.expiresAt) {
      return cached.result;
    }

    const result = await executor();

    this.cache.set(cacheKey, {
      result,
      expiresAt: Date.now() + this.getTTL(toolName)
    });

    return result;
  }

  private createCacheKey(toolName: string, args: unknown): string {
    const hash = createHash("sha256");
    hash.update(toolName);
    hash.update(JSON.stringify(args));
    return hash.digest("hex");
  }

  private getTTL(toolName: string): number {
    // Different TTLs for different tools
    const ttls: Record<string, number> = {
      "get_weather": 5 * 60 * 1000, // 5 minutes
      "list_files": 30 * 1000, // 30 seconds
      "search_database": 60 * 1000 // 1 minute
    };
    return ttls[toolName] || 60 * 1000;
  }
}
```

## WebSocket Transport

```typescript
// WebSocket transport for real-time communication
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", async (ws, req) => {
  // Authenticate connection
  const token = new URL(req.url!, `ws://${req.headers.host}`).searchParams.get("token");
  const user = await verifyToken(token);

  if (!user) {
    ws.close(1008, "Unauthorized");
    return;
  }

  // Create MCP transport
  const transport = new WebSocketServerTransport(ws);

  // Connect server with user context
  const serverInstance = createServerForUser(user);
  await serverInstance.connect(transport);

  ws.on("close", () => {
    serverInstance.close();
  });
});
```

## Prompt Templates

```typescript
// Expose prompt templates via MCP
server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: [
      {
        name: "code_review",
        description: "Review code for security issues",
        arguments: [
          { name: "language", description: "Programming language", required: true },
          { name: "focus", description: "Review focus area", required: false }
        ]
      }
    ]
  };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "code_review") {
    return {
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Review the following ${args.language} code for ${args.focus || "general"} issues:\n\n{{code}}`
          }
        }
      ]
    };
  }

  throw new Error("Unknown prompt");
});
```

## Health Checks

```typescript
// Implement health check endpoint
server.setRequestHandler(PingRequestSchema, async () => {
  // Check dependencies
  const dbHealthy = await checkDatabaseConnection();
  const cacheHealthy = await checkCacheConnection();

  if (!dbHealthy || !cacheHealthy) {
    throw new Error("Service unhealthy");
  }

  return {};
});

// External health check endpoint for HTTP transport
app.get("/health", async (req, res) => {
  const checks = {
    server: server.isConnected(),
    database: await checkDatabaseConnection(),
    cache: await checkCacheConnection()
  };

  const healthy = Object.values(checks).every(Boolean);

  res.status(healthy ? 200 : 503).json({
    status: healthy ? "healthy" : "unhealthy",
    checks
  });
});
```
