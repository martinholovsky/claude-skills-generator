# WebSocket Threat Model

## Threat Model Overview

**Domain Risk Level**: HIGH

### Assets to Protect
1. **User Sessions** - Authentication tokens, session state - **Sensitivity**: CRITICAL
2. **Real-time Data** - Messages, notifications - **Sensitivity**: HIGH
3. **Command Execution** - Server-side actions - **Sensitivity**: CRITICAL
4. **Server Resources** - Memory, connections - **Sensitivity**: MEDIUM

### Attack Surface
- WebSocket handshake (Origin header)
- Authentication mechanism
- Message handlers
- Connection lifecycle
- Resource consumption

---

## Attack Scenario 1: Cross-Site WebSocket Hijacking (CSWSH)

**Threat Category**: OWASP A01:2025 - Broken Access Control / CWE-346

**Threat Level**: CRITICAL

**Attack Flow**:
```
1. Victim is logged into target application
2. Attacker creates malicious webpage with JavaScript
3. Victim visits attacker's page
4. JavaScript creates WebSocket to target server
5. Browser sends victim's cookies automatically
6. Server accepts connection (no origin check)
7. Attacker executes commands as victim
```

**Mitigation**:
```python
# Primary: Origin validation
async def secure_handler(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin not in ["https://app.example.com"]:
        await websocket.close(code=4003)
        return

# Secondary: Token authentication
token = websocket.query_params.get("token")
user = await validate_token(token)

# Tertiary: SameSite cookies
response.set_cookie("session", value, samesite="strict")
```

**Real CVEs**:
- CVE-2024-23898: Jenkins CLI WebSocket hijacking
- CVE-2024-26135: MeshCentral control hijacking
- CVE-2023-0957: Gitpod account takeover

---

## Attack Scenario 2: Message Injection

**Threat Category**: OWASP A03:2025 - Injection / CWE-94

**Threat Level**: HIGH

**Attack Flow**:
```
1. Attacker establishes WebSocket connection
2. Sends malicious message: {"action": "query", "sql": "'; DROP TABLE--"}
3. Server doesn't validate message content
4. SQL injection executes
```

**Mitigation**:
```python
from pydantic import BaseModel

class QueryMessage(BaseModel):
    table: Literal["users", "orders"]  # Allowlist
    filters: dict

async def handle_query(message: QueryMessage):
    # ORM with parameterized query
    stmt = select(models[message.table]).filter_by(**message.filters)
    return await db.execute(stmt)
```

---

## Attack Scenario 3: Connection Flooding (DoS)

**Threat Category**: OWASP A10:2025 / CWE-400

**Threat Level**: MEDIUM

**Attack Flow**:
```
1. Attacker opens many WebSocket connections
2. Server resources exhausted
3. Legitimate users can't connect
```

**Mitigation**:
```python
class ConnectionManager:
    def __init__(self):
        self.connections_per_ip = defaultdict(int)
        self.max_per_ip = 10

    async def connect(self, ws, ip):
        if self.connections_per_ip[ip] >= self.max_per_ip:
            await ws.close(code=4029)
            return False
        self.connections_per_ip[ip] += 1
        return True
```

---

## Attack Scenario 4: Message Flooding

**Threat Category**: OWASP A10:2025 / CWE-770

**Threat Level**: MEDIUM

**Attack Flow**:
```
1. Attacker establishes single connection
2. Floods with thousands of messages per second
3. Server overwhelmed processing messages
```

**Mitigation**:
```python
def check_rate_limit(user_id: str) -> bool:
    now = time()
    window = self.message_times[user_id]
    window = [t for t in window if t > now - 60]

    if len(window) >= 60:  # 60 per minute
        return False

    window.append(now)
    return True
```

---

## Attack Scenario 5: Session Fixation

**Threat Category**: OWASP A07:2025 / CWE-384

**Threat Level**: HIGH

**Attack Flow**:
```
1. Attacker gets valid session token
2. Tricks victim into using that token
3. Victim authenticates with attacker's token
4. Attacker hijacks authenticated session
```

**Mitigation**:
```python
async def authenticate(websocket, token):
    user = await validate_token(token)

    # Rotate token after authentication
    new_token = create_token(user)
    await websocket.send_json({"new_token": new_token})

    # Invalidate old token
    await invalidate_token(token)

    return user
```

---

## STRIDE Analysis

| Category | Threats | Mitigations | Priority |
|----------|---------|-------------|----------|
| **Spoofing** | CSWSH, stolen tokens | Origin check, token rotation | CRITICAL |
| **Tampering** | Message modification | TLS/WSS, message signing | HIGH |
| **Repudiation** | No audit trail | Log all actions with context | MEDIUM |
| **Information Disclosure** | Data leakage via CSWSH | Origin validation, encryption | HIGH |
| **Denial of Service** | Connection/message flooding | Rate limiting, connection limits | MEDIUM |
| **Elevation of Privilege** | Authorization bypass | Per-message permission checks | HIGH |

---

## Security Testing Checklist

### CSWSH Testing
- [ ] Connection rejected from unknown origin
- [ ] Cookie-only auth is not sufficient
- [ ] Token required in query params

### Authentication Testing
- [ ] Invalid token rejected
- [ ] Expired token rejected
- [ ] Token works from valid origin

### Authorization Testing
- [ ] Each action requires permission check
- [ ] User cannot access others' resources

### DoS Testing
- [ ] Connection limit per IP enforced
- [ ] Message rate limiting works
- [ ] Large messages rejected
