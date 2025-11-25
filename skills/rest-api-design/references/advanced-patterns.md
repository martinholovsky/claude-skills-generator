# REST API Advanced Patterns

## HATEOAS (Hypermedia)

```typescript
// Include links in responses
interface UserResponse {
  data: User;
  links: {
    self: string;
    orders: string;
    update: string;
    delete: string;
  };
}

app.get("/api/v1/users/:id", async (req, res) => {
  const user = await getUser(req.params.id);

  res.json({
    data: user,
    links: {
      self: `/api/v1/users/${user.id}`,
      orders: `/api/v1/users/${user.id}/orders`,
      update: `/api/v1/users/${user.id}`,
      delete: `/api/v1/users/${user.id}`
    }
  });
});
```

## Conditional Requests

```typescript
// ETag support
app.get("/api/v1/resources/:id", async (req, res) => {
  const resource = await getResource(req.params.id);
  const etag = generateETag(resource);

  // Check If-None-Match
  if (req.headers["if-none-match"] === etag) {
    return res.status(304).end();
  }

  res.set("ETag", etag);
  res.json({ data: resource });
});

// Optimistic locking
app.put("/api/v1/resources/:id", async (req, res) => {
  const currentEtag = req.headers["if-match"];
  if (!currentEtag) {
    return res.status(428).json({ error: { message: "If-Match header required" } });
  }

  const resource = await getResource(req.params.id);
  if (generateETag(resource) !== currentEtag) {
    return res.status(412).json({ error: { message: "Resource modified" } });
  }

  // Update resource
});
```

## Bulk Operations

```typescript
// Batch create
app.post("/api/v1/users/batch", async (req, res) => {
  const { items } = req.body;

  if (items.length > 100) {
    return res.status(400).json({ error: { message: "Max 100 items" } });
  }

  const results = await Promise.allSettled(
    items.map(item => createUser(item))
  );

  const response = results.map((result, index) => ({
    index,
    success: result.status === "fulfilled",
    data: result.status === "fulfilled" ? result.value : undefined,
    error: result.status === "rejected" ? result.reason.message : undefined
  }));

  res.status(207).json({ data: response });
});
```

## Webhooks

```typescript
// Register webhook
app.post("/api/v1/webhooks", async (req, res) => {
  const webhook = await createWebhook({
    url: req.body.url,
    events: req.body.events,
    secret: crypto.randomBytes(32).toString("hex")
  });

  res.status(201).json({ data: webhook });
});

// Deliver webhook
async function deliverWebhook(webhook: Webhook, event: string, payload: unknown) {
  const timestamp = Date.now().toString();
  const signature = crypto
    .createHmac("sha256", webhook.secret)
    .update(`${timestamp}.${JSON.stringify(payload)}`)
    .digest("hex");

  await fetch(webhook.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Webhook-Signature": `t=${timestamp},v1=${signature}`
    },
    body: JSON.stringify({ event, data: payload })
  });
}
```

## GraphQL Gateway

```typescript
// REST to GraphQL adapter
app.use("/graphql", graphqlHTTP({
  schema: buildSchema(`
    type User {
      id: ID!
      name: String!
      email: String!
    }

    type Query {
      user(id: ID!): User
      users(limit: Int, offset: Int): [User]
    }
  `),
  rootValue: {
    user: ({ id }) => getUser(id),
    users: ({ limit, offset }) => getUsers({ limit, offset })
  }
}));
```
