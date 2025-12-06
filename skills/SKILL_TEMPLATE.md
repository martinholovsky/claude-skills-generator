---
name: your-skill-name
description: Brief one-line description of what this skill covers
model: sonnet
risk_level: MEDIUM  # Options: LOW, MEDIUM, HIGH
---

# [Your Skill Name] - Claude Code Skill

## File Organization

- **SKILL.md**: Core principles, patterns, essential security (this file)
- **references/security-examples.md**: CVE details and OWASP implementations (optional)
- **references/advanced-patterns.md**: Advanced patterns and use cases (optional)
- **references/threat-model.md**: Attack scenarios and STRIDE analysis (optional)

## Validation Gates

### Gate 0.2: Vulnerability Research (BLOCKING for HIGH-RISK only)
- **Status**: PASSED / PENDING / N/A
- **Research Date**: YYYY-MM-DD
- **CVEs**: List relevant CVEs if HIGH risk, or "None documented" for LOW/MEDIUM

---

## 1. Overview

**Risk Level**: [LOW | MEDIUM | HIGH]

**Justification**:
[Explain why this risk level was assigned. For HIGH: mention security-critical operations like auth, file I/O, network access. For MEDIUM: explain potential security implications. For LOW: explain why security concerns are minimal.]

You are an expert [technology/domain] developer creating [type of application/feature]. You focus on [key areas of expertise].

### Core Expertise Areas
- Area 1: Brief description
- Area 2: Brief description
- Area 3: Brief description
- Area 4: Brief description
- Area 5: Brief description

---

## 2. Core Responsibilities

### Fundamental Principles

1. **TDD First**: Write tests before implementation code
2. **[Principle 2]**: Description
3. **[Principle 3]**: Description
4. **[Principle 4]**: Description
5. **[Principle 5]**: Description
6. **[Principle 6]**: Description
7. **Security First**: Always consider security implications

---

## 3. Technical Foundation

### Version Recommendations

| Component | Version | Notes |
|-----------|---------|-------|
| **[Main Framework/Library]** | X.Y.Z+ | Reason for version requirement |
| **[Dependency 1]** | X.Y.Z+ | Reason |
| **[Dependency 2]** | X.Y.Z+ | Reason |
| **[Language]** | X.Y+ | Reason |

### Dependencies

```bash
# Package manager specific
# For npm/yarn:
npm install [packages]

# For pip:
pip install [packages]

# For cargo:
cargo add [packages]
```

Or include configuration file example:

```toml
# pyproject.toml example
[project]
dependencies = [
    "package>=version",
]
```

```json
// package.json example
{
  "dependencies": {
    "package": "^version"
  }
}
```

---

## 4. Implementation Patterns

### Pattern 1: [Pattern Name]

**When to use:** Brief description of use case

**Security considerations:**
- Consideration 1
- Consideration 2

**Example:**

```[language]
// Clear, commented code example
// Showing the pattern in action
// With security best practices
```

**What makes this secure:**
- Explanation 1
- Explanation 2
- Explanation 3

---

### Pattern 2: [Another Pattern Name]

**When to use:** Brief description

**Security considerations:**
- Consideration 1
- Consideration 2

**Example:**

```[language]
// Another code example
```

**What makes this secure:**
- Explanation 1
- Explanation 2

---

### Pattern 3: [Error Handling]

**When to use:** All implementations

**Security considerations:**
- Never leak sensitive information in error messages
- Log errors securely
- Provide user-friendly messages

**Example:**

```[language]
// Error handling example
try {
    // Operation
} catch (error) {
    // Log internally
    logger.error({ error, context: 'Operation failed' });

    // Return safe message to user
    return { error: 'Operation failed. Please try again.' };
}
```

---

## 5. Security Patterns

### OWASP Top 10 Relevance

#### A01:2021 - Broken Access Control
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Strategy 1
- Strategy 2
- Code example or reference

#### A02:2021 - Cryptographic Failures
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Strategy 1
- Strategy 2

#### A03:2021 - Injection
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Use parameterized queries
- Validate all inputs
- Example code

#### A04:2021 - Insecure Design
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Design consideration 1
- Design consideration 2

#### A05:2021 - Security Misconfiguration
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Configuration best practice 1
- Configuration best practice 2

#### A06:2021 - Vulnerable and Outdated Components
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Keep dependencies updated
- Use automated scanning
- Pin versions with known security

#### A07:2021 - Identification and Authentication Failures
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Authentication strategy 1
- Authentication strategy 2

#### A08:2021 - Software and Data Integrity Failures
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Integrity check 1
- Integrity check 2

#### A09:2021 - Security Logging and Monitoring Failures
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Logging strategy 1
- Logging strategy 2

#### A10:2021 - Server-Side Request Forgery (SSRF)
**Relevance:** [HIGH | MEDIUM | LOW | N/A]

**Mitigation:**
- Validation strategy 1
- Validation strategy 2

---

## 6. Known Vulnerabilities

### CVE-YYYY-XXXXX: [Vulnerability Name]

**Affected Versions:** [Package] < X.Y.Z

**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]

**Description:**
Brief description of the vulnerability and its impact.

**Mitigation:**
```bash
# Update to patched version
[package-manager] install [package]@X.Y.Z
```

**Additional Protection:**
- Extra security measure 1
- Extra security measure 2

---

### CVE-YYYY-XXXXX: [Another Vulnerability]

[Repeat structure as above]

---

## 7. Testing Requirements

### Test Coverage Targets
- Unit tests: 90%+ coverage
- Integration tests: Critical paths
- Security tests: All authentication/authorization flows

### Required Test Types

**Unit Tests:**
```[language]
// Example unit test
describe('[Feature]', () => {
    it('should [expected behavior]', () => {
        // Test implementation
    });
});
```

**Security Tests:**
```[language]
// Example security test
it('should reject invalid authentication', () => {
    // Security test implementation
});
```

**Integration Tests:**
```[language]
// Example integration test
```

---

## 8. Deployment Considerations

### Production Checklist

- [ ] All dependencies updated to secure versions
- [ ] Security headers configured
- [ ] HTTPS enforced
- [ ] Secrets stored in environment variables or keychain
- [ ] Error logging configured (without leaking sensitive data)
- [ ] Rate limiting enabled
- [ ] Authentication/authorization tested
- [ ] Input validation on all endpoints
- [ ] Security audit completed
- [ ] Monitoring and alerting configured

### Environment Variables

```bash
# Required environment variables
REQUIRED_VAR=value
OPTIONAL_VAR=value

# Security-sensitive variables (use OS keychain or secrets manager)
SECRET_KEY=  # Never commit this
API_KEY=     # Never commit this
DATABASE_URL=  # May contain credentials
```

### Configuration

```[language]
// Example production configuration
const config = {
    environment: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 3000,
    // Security settings
    rateLimiting: {
        enabled: true,
        maxRequests: 100,
        windowMs: 60000,
    },
};
```

---

## 9. Best Practices

### Do's ✅

1. **Always validate inputs** using schema validation
2. **Use parameterized queries** to prevent injection
3. **Store secrets securely** in OS keychain or secrets manager
4. **Enable rate limiting** on all public endpoints
5. **Log security events** (authentication, authorization failures)
6. **Keep dependencies updated** with automated scanning
7. **Use HTTPS** in production
8. **Implement proper error handling** without leaking details
9. **Write tests first** (TDD approach)
10. **Follow the principle of least privilege**

### Don'ts ❌

1. **Never commit secrets** to version control
2. **Never trust user input** without validation
3. **Never expose internal errors** to users
4. **Never use outdated dependencies** with known CVEs
5. **Never skip authentication/authorization** checks
6. **Never store passwords in plaintext**
7. **Never disable security features** in production
8. **Never use eval()** or similar with user input
9. **Never skip security headers** configuration
10. **Never ignore security warnings** from tools

---

## 10. Common Pitfalls

### Pitfall 1: [Common Mistake]

**Problem:**
Description of what developers commonly do wrong.

**Solution:**
```[language]
// Correct implementation
```

**Why this is important:**
Security or functionality explanation.

---

### Pitfall 2: [Another Common Mistake]

**Problem:**
Description.

**Solution:**
```[language]
// Correct implementation
```

---

## 11. Performance Considerations

### Optimization 1: [Optimization Name]

**When to apply:** Description of scenario

**Implementation:**
```[language]
// Optimized code example
```

**Trade-offs:**
- Benefit 1
- Potential drawback 1

---

## 12. Resources

### Official Documentation
- [Technology Documentation](https://example.com)
- [Security Guide](https://example.com/security)
- [Best Practices](https://example.com/best-practices)

### Security Resources
- [OWASP Guide for [Technology]](https://owasp.org)
- [CVE Database](https://cve.mitre.org)
- [Security Advisories](https://example.com/security)

### Community Resources
- [GitHub Repository](https://github.com)
- [Community Forum](https://example.com/forum)
- [Stack Overflow Tag](https://stackoverflow.com/questions/tagged/technology)

### Related Skills
- `related-skill-1` - Brief description
- `related-skill-2` - Brief description
- `related-skill-3` - Brief description

---

## 13. Changelog

### 2025-12-06
- Initial skill creation
- Added core patterns
- Documented OWASP Top 10 relevance

---

## Appendix A: Quick Reference

### Cheat Sheet

```[language]
// Common operations quick reference

// Pattern 1
// code

// Pattern 2
// code

// Pattern 3
// code
```

### CLI Commands

```bash
# Development
command-dev

# Testing
command-test

# Production build
command-build

# Security audit
command-audit
```

---

## Appendix B: Troubleshooting

### Issue 1: [Common Problem]

**Symptoms:**
- Symptom 1
- Symptom 2

**Solution:**
```bash
# Fix commands
```

**Explanation:**
Why this works.

---

### Issue 2: [Another Problem]

**Symptoms:**
- Symptom 1

**Solution:**
```bash
# Fix commands
```

---

**Last Updated:** YYYY-MM-DD
**Maintained By:** [Your Name/Team]
**Risk Level:** [LOW | MEDIUM | HIGH]
