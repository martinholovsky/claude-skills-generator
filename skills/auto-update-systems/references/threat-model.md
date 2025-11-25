# Auto-Update Systems Threat Model

## Asset Identification

### Primary Assets
1. **Update Signing Keys** - Private keys for signing updates
2. **Update Artifacts** - Compiled application binaries
3. **Update Infrastructure** - Servers hosting updates
4. **User Installations** - End-user application instances

### Secondary Assets
1. **Update Manifests** - Version and signature information
2. **Public Keys** - Embedded in application
3. **Update Logs** - Analytics and error data

---

## Threat Actors

| Actor | Motivation | Capabilities | Target |
|-------|------------|--------------|--------|
| **Nation State** | Espionage, sabotage | Supply chain compromise | Infrastructure |
| **Cybercriminal** | Ransomware, theft | Malware distribution | All users |
| **Competitor** | Sabotage | DoS, reputation damage | Update availability |
| **Insider** | Various | Direct access to keys | Signing infrastructure |
| **Network Attacker** | Data theft | MITM attacks | Update traffic |

---

## Attack Vectors & Mitigations

### 1. Signing Key Compromise

**Threat**: Attacker obtains private signing key and distributes malicious updates.

**Impact**: CRITICAL - All users can be compromised

**Attack Scenarios**:
- Key stolen from developer machine
- Key leaked in CI logs or artifacts
- Key extracted from memory during signing
- Insider theft

**CVE Example**: This is the ultimate goal of many CVEs like CVE-2024-39698 (signature bypass)

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| HSM storage | Store keys in hardware security module | Very High |
| CI-only access | Never on developer machines | High |
| Key encryption | Password-protected keys | Medium |
| Access logging | Audit all key usage | High |
| Key rotation | Regular rotation procedure | Medium |

**Detection**:
- Monitor for unexpected signed artifacts
- Alert on CI jobs outside normal times
- Check for key access from unusual IPs

### 2. Man-in-the-Middle Attack

**Threat**: Attacker intercepts update traffic and serves malicious update.

**Attack Scenarios**:
- Compromised network (public WiFi, corporate proxy)
- DNS hijacking
- BGP hijacking
- Rogue certificate authority

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Signature verification | Ed25519 signatures | Critical |
| HTTPS only | TLS 1.2+ required | High |
| Certificate pinning | Pin update server cert | Very High |
| Multiple endpoints | Failover to different CDN | Medium |

**Implementation**:
```rust
// Even if MITM succeeds in serving malicious file,
// signature verification will fail because attacker
// doesn't have the private key to sign their payload
```

### 3. Update Server Compromise

**Threat**: Attacker gains access to update infrastructure and modifies hosted files.

**Attack Scenarios**:
- Server vulnerability exploitation
- Credential theft
- Supply chain attack on hosting provider
- DNS takeover

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Signature verification | Files signed before upload | Critical |
| Integrity monitoring | Hash verification of hosted files | High |
| Access controls | Minimal permissions | High |
| CDN separation | Separate signing from hosting | High |

**Architecture**:
```
Build Server -> Sign -> Upload to CDN
                  |
                  v
              Audit Log

Update Server NEVER has access to signing keys
```

### 4. Signature Bypass

**Threat**: Attacker exploits vulnerability to bypass signature verification.

**CVE Examples**:
- CVE-2024-39698: electron-updater environment variable expansion
- CVE-2020-electron-updater: Path traversal in signature verification

**Attack Scenario**:
```javascript
// CVE-2024-39698 exploit
// Attacker crafts filename with environment variable
// %TEMP%/legitimate-signed-file.exe
// Signature check reads different file than installed
```

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Update dependencies | Latest electron-builder/Tauri | Critical |
| Defense in depth | Multiple verification layers | High |
| Security testing | Test signature bypass scenarios | High |
| Code audit | Review verification code | High |

### 5. Rollback Attack

**Threat**: Attacker forces installation of older vulnerable version.

**Attack Scenarios**:
- Serve old manifest with known vulnerable version
- Block updates to prevent security patches
- Corrupt update to trigger rollback to vulnerable version

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| Version validation | Only allow upgrades, not downgrades | High |
| Minimum version | Enforce minimum acceptable version | High |
| Update monitoring | Alert if users on old versions | Medium |
| Force update | Mandatory updates for critical issues | High |

### 6. Denial of Service

**Threat**: Attacker prevents users from receiving updates.

**Attack Scenarios**:
- DDoS update servers
- DNS blocking
- Firewall rules in enterprise environments
- Corrupt manifest to crash updater

**Mitigations**:

| Control | Implementation | Effectiveness |
|---------|----------------|---------------|
| CDN distribution | Distributed hosting | High |
| Multiple endpoints | Fallback URLs | High |
| Graceful degradation | App works without updates | Medium |
| Out-of-band updates | Alternative update channels | Medium |

---

## Defense in Depth Strategy

### Layer 1: Key Security
- HSM or secure CI-only storage
- Key encryption with strong password
- Access logging and alerting
- Regular rotation

### Layer 2: Signing Process
- Isolated signing environment
- Deterministic builds
- Signature verification after signing
- Audit trail

### Layer 3: Distribution Security
- HTTPS only endpoints
- CDN with access controls
- Integrity monitoring
- Geographic distribution

### Layer 4: Client Verification
- Ed25519 signature verification
- Version validation (no downgrades)
- Certificate pinning
- Checksum verification

### Layer 5: Monitoring
- Update success/failure rates
- Version distribution analytics
- Error logging and alerting
- Security event monitoring

---

## Incident Response

### Compromised Signing Key

**Immediate (0-1 hour)**:
1. Revoke/rotate compromised key
2. Stop all update distribution
3. Alert security team
4. Begin investigation

**Short-term (1-24 hours)**:
1. Generate new key pair
2. Build new release with new key
3. Analyze what was signed with compromised key
4. Notify users if malicious updates distributed

**Long-term (1-7 days)**:
1. Forensic analysis of compromise
2. Improve key protection
3. User communication
4. Post-mortem documentation

### Malicious Update Distributed

**Immediate**:
1. Take down update servers
2. Push emergency "null" update to stop downloads
3. Alert all hands

**Short-term**:
1. Identify affected version range
2. Notify users to not run affected versions
3. Push clean update
4. Provide remediation tools

**Long-term**:
1. Full incident post-mortem
2. Improve detection capabilities
3. Legal/regulatory notifications
4. User compensation if applicable

---

## Security Monitoring

### Key Metrics

| Metric | Alert Threshold | Action |
|--------|-----------------|--------|
| Update failures | >5% over 1 hour | Investigate |
| Unknown versions | Any | Security review |
| Old versions | >10% of users | Prompt update |
| Signature errors | Any | Immediate investigation |

### Log Events to Monitor

```rust
pub enum SecurityEvent {
    UpdateCheckStarted { version: String },
    UpdateAvailable { new_version: String },
    SignatureVerified { artifact: String },
    SignatureInvalid { artifact: String, error: String },
    UpdateInstalled { version: String },
    UpdateFailed { version: String, error: String },
    DowngradeAttempt { from: String, to: String },
    UnusualUpdateSource { url: String },
}
```

---

## Compliance Considerations

### Code Signing Requirements

- **Windows SmartScreen**: Requires signed executables
- **macOS Gatekeeper**: Requires notarized apps
- **Enterprise deployment**: May require internal CA

### Audit Trail Requirements

For regulated industries (healthcare, finance):
- Log all update activities
- Retain logs for compliance period
- Tamper-evident logging
- Access controls on logs

---

## Security Checklist

### Build Time
- [ ] Signing keys in HSM or CI secrets
- [ ] Key password in separate secret
- [ ] Builds are reproducible
- [ ] Artifacts signed before upload

### Distribution
- [ ] HTTPS only endpoints
- [ ] CDN with access controls
- [ ] Multiple fallback endpoints
- [ ] Integrity monitoring enabled

### Client
- [ ] Public key embedded correctly
- [ ] Signature verification cannot be bypassed
- [ ] Version validation prevents downgrades
- [ ] Error handling doesn't skip verification

### Operations
- [ ] Update success rate monitored
- [ ] Version distribution tracked
- [ ] Security event alerting
- [ ] Incident response plan documented
