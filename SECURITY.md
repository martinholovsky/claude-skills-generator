# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| {{SUPPORTED_VERSIONS}} |

## Reporting a Vulnerability

We take the security of {{PROJECT_NAME}} seriously. If you discover a security vulnerability, please follow these steps:

### Do NOT

- Create a public GitHub issue
- Disclose the vulnerability publicly before it's fixed
- Exploit the vulnerability

### Do

1. **Email us at**: {{SECURITY_EMAIL}}
2. **Or use GitHub's private vulnerability reporting**: Go to Security tab → Report a vulnerability

### What to Include

- Type of vulnerability (XSS, SQL Injection, RCE, etc.)
- Full paths of affected source files
- Step-by-step reproduction instructions
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days (for critical issues)

### What to Expect

1. We'll acknowledge receipt of your report
2. We'll investigate and validate the vulnerability
3. We'll develop and test a fix
4. We'll coordinate disclosure timing with you
5. We'll credit you (unless you prefer anonymity)

## Security Best Practices for Contributors

### Code Security

- **Input Validation**: Validate and sanitize all user inputs
- **Output Encoding**: Encode output to prevent XSS
- **Parameterized Queries**: Never concatenate SQL queries
- **Least Privilege**: Request minimal permissions
- **Secure Defaults**: Default to secure configurations

### Secrets Management

- **Never commit secrets**: Use environment variables
- **Use .gitignore**: Exclude sensitive files
- **Rotate compromised secrets**: Immediately if leaked
- **Use secret scanning**: Enable GitHub secret scanning

### Dependencies

- **Keep updated**: Regularly update dependencies
- **Audit regularly**: `npm audit` / `pip-audit`
- **Pin versions**: Use exact versions in production
- **Review licenses**: Ensure compatibility

### AI-Assisted Development Security

When using Claude Code or other AI tools:

1. **Review all generated code** for security issues
2. **Don't trust AI for security** - it may generate vulnerable code
3. **Verify crypto implementations** - AI often gets this wrong
4. **Check for OWASP Top 10** in AI-generated code
5. **Load security skills** before implementing security features

## Security Features

### Authentication

{{AUTH_SECURITY_FEATURES}}

### Data Protection

{{DATA_PROTECTION_FEATURES}}

### Logging & Monitoring

{{LOGGING_SECURITY_FEATURES}}

## Compliance

{{COMPLIANCE_INFORMATION}}

## Security Contacts

- **Security Team Email**: {{SECURITY_EMAIL}}
- **PGP Key**: {{PGP_KEY_LINK}} (optional)

## Acknowledgments

We thank the following security researchers for responsibly disclosing vulnerabilities:

{{SECURITY_ACKNOWLEDGMENTS}}

---

Last updated: {{LAST_UPDATED}}
