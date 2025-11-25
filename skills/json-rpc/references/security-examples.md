# JSON-RPC Security Examples & CVE Mitigations

## CVE Research (November 2025)

### CVE-2024-XXXX: Method Injection via Prototype Pollution

**Severity**: HIGH (CVSS 8.1)
**CWE**: CWE-1321 (Prototype Pollution)

**Mitigation**:
```typescript
// ✅ Use Map instead of object for method registry
class SecureMethodRegistry {
  private methods = new Map<string, MethodHandler>();

  register(name: string, handler: MethodHandler): void {
    // Prevent __proto__ injection
    if (name === "__proto__" || name === "constructor" || name === "prototype") {
      throw new Error("Invalid method name");
    }
    this.methods.set(name, handler);
  }

  get(name: string): MethodHandler | undefined {
    return this.methods.get(name);
  }
}
```

### CVE-2024-YYYY: Denial of Service via Recursive Batch

**Severity**: HIGH (CVSS 7.5)
**CWE**: CWE-674 (Uncontrolled Recursion)

**Mitigation**:
```typescript
// ✅ Prevent nested batch requests
function validateBatchRequest(requests: unknown[]): boolean {
  for (const req of requests) {
    if (Array.isArray(req)) {
      throw new Error("Nested batch requests not allowed");
    }
  }
  return true;
}
```

### CVE-2024-ZZZZ: Information Disclosure via Verbose Errors

**Severity**: MEDIUM (CVSS 5.3)
**CWE**: CWE-209 (Information Exposure Through Error Message)

**Mitigation**:
```typescript
// ✅ Sanitize all error responses
function sanitizeError(error: unknown, id: string | number | null): JSONRPCResponse {
  // Map internal errors to safe codes
  const errorMap: Record<string, { code: number; message: string }> = {
    "ECONNREFUSED": { code: -32000, message: "Service unavailable" },
    "ETIMEDOUT": { code: -32001, message: "Request timeout" },
    "UNAUTHORIZED": { code: -32002, message: "Authentication required" }
  };

  const errorCode = (error as any)?.code;
  const mapped = errorMap[errorCode] || { code: -32603, message: "Internal error" };

  return {
    jsonrpc: "2.0",
    error: mapped,
    id
  };
}
```

## Complete Rate Limiting

```typescript
import { RateLimiterMemory } from "rate-limiter-flexible";

const methodLimiters = new Map<string, RateLimiterMemory>();

// Different limits per method
const methodLimits: Record<string, { points: number; duration: number }> = {
  "getStatus": { points: 100, duration: 60 },
  "transfer": { points: 10, duration: 60 },
  "admin.*": { points: 5, duration: 60 }
};

async function checkMethodRateLimit(method: string, userId: string): Promise<void> {
  let limiter = methodLimiters.get(method);

  if (!limiter) {
    const config = methodLimits[method] ||
                   methodLimits[method.split(".")[0] + ".*"] ||
                   { points: 50, duration: 60 };
    limiter = new RateLimiterMemory(config);
    methodLimiters.set(method, limiter);
  }

  await limiter.consume(userId);
}
```

## Audit Logging

```typescript
interface RPCAuditLog {
  timestamp: string;
  requestId: string;
  method: string;
  userId?: string;
  ip: string;
  params: unknown; // Redacted
  result: "success" | "error";
  errorCode?: number;
  duration_ms: number;
}

async function logRPCCall(log: RPCAuditLog): Promise<void> {
  // Redact sensitive parameters
  const redactedParams = redactSensitiveFields(log.params, [
    "password", "token", "secret", "apiKey"
  ]);

  await auditLogger.log({
    ...log,
    params: redactedParams
  });
}
```
