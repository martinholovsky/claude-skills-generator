# Claude AI Skills Directory

This directory contains domain-specific knowledge modules ("skills") that provide Claude Code with expert guidance, security considerations, and implementation patterns for specific technologies and domains.

## 📋 What Are Skills?

Skills are specialized knowledge files that Claude Code can read to gain expertise in specific areas. Each skill includes:

- **Core Principles** - Best practices and fundamental concepts
- **Security Patterns** - OWASP Top 10 mapping and CVE tracking
- **Implementation Examples** - Code patterns with security annotations
- **Risk Assessment** - Classification (HIGH/MEDIUM/LOW)
- **Testing Guidelines** - Required test coverage and patterns
- **Known Vulnerabilities** - CVE tracking with mitigations

## 🏗️ Skill Structure

```
skills/
├── SKILL_TEMPLATE.md          # Template for creating new skills
├── README.md                  # This file
│
├── skill-name/                # Individual skill directory
│   ├── SKILL.md               # Main skill file (required)
│   └── references/            # Optional extended documentation
│       ├── advanced-patterns.md
│       ├── security-examples.md
│       └── threat-model.md
```

## 🆕 Creating a New Skill

### Step 1: Copy the Template

```bash
# Copy template to new skill directory
cp SKILL_TEMPLATE.md your-skill-name/SKILL.md
```

### Step 2: Fill Out Metadata

Edit the front matter at the top of SKILL.md:

```yaml
---
name: your-skill-name
description: Brief one-line description
model: sonnet
risk_level: MEDIUM  # LOW, MEDIUM, or HIGH
---
```

### Step 3: Determine Risk Level

**Choose the appropriate risk level:**

- **HIGH** - Handles authentication, authorization, file I/O, network requests, database access, encryption, or system-level operations
- **MEDIUM** - Processes user input, manages state, or integrates with external services
- **LOW** - Pure presentation logic, styling, or utility functions with minimal security implications

**HIGH-risk skills REQUIRE:**
- Research and documentation of 5+ relevant CVEs
- Complete OWASP Top 10 analysis
- Threat modeling (STRIDE analysis)
- Security examples in references/

### Step 4: Complete Core Sections

1. **Overview** - Explain what this skill covers and justify the risk level
2. **Core Responsibilities** - List fundamental principles
3. **Technical Foundation** - Specify versions and dependencies
4. **Implementation Patterns** - Provide 3-5 secure code patterns
5. **Security Patterns** - Complete OWASP Top 10 analysis
6. **Known Vulnerabilities** - Document relevant CVEs (HIGH-risk only)
7. **Testing Requirements** - Specify test coverage expectations
8. **Best Practices** - Do's and Don'ts

### Step 5: Add Optional References

For complex or high-risk skills, create additional documentation:

```bash
mkdir -p your-skill-name/references

# Optional reference files:
# - advanced-patterns.md: Deep dives into complex implementations
# - security-examples.md: Detailed CVE analysis and secure code examples
# - threat-model.md: STRIDE analysis and attack scenarios
```

### Step 6: Test Your Skill

Create a test project and have Claude Code read your skill:

```markdown
# In your project's CLAUDE.md or a slash command
Please read skills/your-skill-name/SKILL.md before implementing [feature].
```

## 📊 Skill Categories

Skills are organized into these categories:

### Frontend & UI
- `vue-nuxt` - Vue 3 and Nuxt 3 framework
- `pinia` - Vue state management
- `tailwindcss` - Utility-first CSS
- `design-systems` - Component libraries
- `ui-ux-design` - UI/UX principles
- `gsap` - Animation library
- `threejs-tresjs` - 3D graphics
- `webgl` - Low-level graphics
- `glsl` - Shader programming

### Backend & API
- `fastapi` - Python REST APIs
- `api-expert` - General API design
- `rest-api-design` - RESTful patterns
- `graphql-expert` - GraphQL APIs
- `websocket` - Real-time communication
- `async-expert` - Async programming
- `celery-expert` - Task queues
- `rabbitmq-expert` - Message brokers
- `json-rpc` - RPC protocol
- `mcp` - Model Context Protocol

### Programming Languages
- `typescript` - TypeScript fundamentals
- `javascript-expert` - Advanced JavaScript
- `python` - Python development
- `rust` - Systems programming

### Databases
- `database-design` - Schema design
- `sqlite` - SQLite database
- `sqlcipher` - Encrypted SQLite
- `surrealdb-expert` - SurrealDB
- `graph-database-expert` - Graph databases

### Security
- `appsec-expert` - Application security
- `security-auditing` - Security reviews
- `encryption` - Cryptography
- `os-keychain` - Credential storage
- `sandboxing` - Process isolation
- `devsecops-expert` - Security automation

### DevOps & Infrastructure
- `ci-cd` - CI/CD fundamentals
- `cicd-expert` - Advanced CI/CD
- `argo-expert` - ArgoCD ecosystem
- `cilium-expert` - Kubernetes networking
- `harbor-expert` - Container registry
- `talos-os-expert` - Talos Linux
- `kanidm-expert` - Identity management
- `cloud-api-integration` - Cloud APIs
- `cross-platform-builds` - Multi-platform builds

### Desktop & Native
- `tauri` - Desktop applications
- `browser-automation` - Puppeteer/Playwright
- `auto-update-systems` - App updates

### Platform-Specific
- `macos-accessibility` - macOS automation
- `windows-ui-automation` - Windows automation
- `linux-at-spi2` - Linux accessibility
- `applescript` - macOS scripting
- `dbus` - Linux IPC

### AI & Machine Learning
- `llm-integration` - LLM integration
- `model-quantization` - Model optimization
- `prompt-engineering` - Prompt design
- `speech-to-text` - Speech recognition
- `text-to-speech` - TTS synthesis
- `wake-word-detection` - Wake word detection

### Multimedia
- `web-audio-api` - Audio processing

### Accessibility
- `accessibility-wcag` - WCAG compliance

## 🔒 Security Guidelines

### All Skills Must:

1. ✅ Include OWASP Top 10 analysis with relevance ratings
2. ✅ Provide secure code examples with explanations
3. ✅ Document input validation requirements
4. ✅ Specify dependency versions with security notes
5. ✅ Include error handling patterns that don't leak information
6. ✅ List security best practices (Do's and Don'ts)

### HIGH-Risk Skills Must Also:

1. ✅ Document 5+ relevant CVEs with mitigations
2. ✅ Include threat modeling (STRIDE analysis)
3. ✅ Provide detailed security examples in references/
4. ✅ Specify comprehensive testing requirements
5. ✅ Document secure configuration patterns
6. ✅ Include deployment security checklist

## 📝 Writing Style Guidelines

### Be Concise and Actionable

❌ Bad:
```markdown
It's generally a good idea to validate inputs because it can help prevent various security issues.
```

✅ Good:
```markdown
**Always validate inputs** using schema validation to prevent injection attacks.
```

### Provide Context

❌ Bad:
```python
# Use this
user = db.query(User).filter(User.id == user_id).first()
```

✅ Good:
```python
# Secure: Use parameterized query to prevent SQL injection
user = db.query(User).filter(User.id == user_id).first()
```

### Explain Security Implications

❌ Bad:
```markdown
Don't use eval().
```

✅ Good:
```markdown
**Never use eval()** with user input - it allows arbitrary code execution and can compromise the entire system.
```

## 🧪 Skill Quality Checklist

Before submitting a new skill, ensure:

- [ ] Front matter is complete (name, description, model, risk_level)
- [ ] Risk level is justified in the Overview section
- [ ] All OWASP Top 10 items are addressed (mark N/A if not applicable)
- [ ] Code examples are secure and well-commented
- [ ] CVEs are documented (for HIGH-risk skills)
- [ ] Testing requirements are specified
- [ ] Best practices include both Do's and Don'ts
- [ ] Resources section has relevant links
- [ ] Related skills are cross-referenced
- [ ] No secrets or credentials in examples
- [ ] Examples use placeholders for sensitive data

## 🔄 Updating Existing Skills

### When to Update

- New CVEs are discovered
- Framework/library releases major version
- OWASP Top 10 is updated
- New security patterns emerge
- Best practices evolve

### Update Process

1. Update the **Changelog** section with date and changes
2. Update **Version Recommendations** if needed
3. Add new **CVEs** to Known Vulnerabilities section
4. Revise **Security Patterns** if OWASP guidance changes
5. Update **Last Updated** date at bottom

## 📚 Skill Usage Patterns

### Loading Skills in Claude Code

**Via CLAUDE.md (Auto-load):**
```markdown
## Skill Loading Requirements

Before implementing API features:
1. Read `skills/fastapi/SKILL.md`
2. Read `skills/rest-api-design/SKILL.md`
```

**Via Slash Command:**
```markdown
<!-- .claude/commands/load-api-skills.md -->
Read the following skills:
- skills/fastapi/SKILL.md
- skills/rest-api-design/SKILL.md
- skills/async-expert/SKILL.md
```

**Direct Request:**
```
Please read skills/appsec-expert/SKILL.md before implementing authentication
```

### Combining Skills

For complex features, load multiple related skills:

**Real-time API with Authentication:**
```markdown
Before implementing, read these skills:
- skills/fastapi/SKILL.md
- skills/websocket/SKILL.md
- skills/async-expert/SKILL.md
- skills/appsec-expert/SKILL.md
- skills/encryption/SKILL.md
```

## 🤝 Contributing

### Adding a New Skill

1. Check if a similar skill already exists
2. Copy `SKILL_TEMPLATE.md` to `your-skill-name/SKILL.md`
3. Fill out all required sections
4. Add to appropriate category in this README
5. Submit pull request with:
   - Skill file(s)
   - Updated skills/README.md (this file)
   - Updated root SKILLS_REFERENCE.md

### Skill Naming Conventions

- Use lowercase with hyphens: `skill-name`
- Be specific: `vue-nuxt` not just `vue`
- Use `-expert` suffix for advanced versions: `fastapi-expert`
- Platform-specific: `macos-accessibility`, `windows-ui-automation`

### Directory Structure Standards

```
skill-name/
├── SKILL.md                           # Always required
└── references/                        # Optional, for complex skills
    ├── advanced-patterns.md           # Deep dives
    ├── security-examples.md           # CVE analysis (HIGH-risk)
    └── threat-model.md                # STRIDE analysis (HIGH-risk)
```

## 📞 Questions?

- **Usage Guide:** See [USAGE.md](../USAGE.md) in repository root
- **Skills Catalog:** See [SKILLS_REFERENCE.md](../SKILLS_REFERENCE.md) for all skills
- **Main Documentation:** See [README.md](../README.md)
- **Issues:** Report issues via GitHub Issues

---

**Last Updated:** 2025-12-06
**Total Skills:** 67+
**Maintainer:** Claude AI Skill Generator Community
