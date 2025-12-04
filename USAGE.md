# Usage Guide - Claude AI Skill Generator

This comprehensive guide explains how to use the Claude AI Skill Generator to bootstrap your AI-assisted development projects.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Setup Scripts](#setup-scripts)
- [Interactive Walkthrough](#interactive-walkthrough)
- [Template Variables](#template-variables)
- [Skills System](#skills-system)
- [Claude Code Integration](#claude-code-integration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Installation

### Prerequisites

- Git
- Bash shell (Linux, macOS, or Windows with WSL/Git Bash)
- Claude Code (for AI-assisted development)

### Clone the Repository

```bash
git clone https://github.com/martinholovsky/ai-templates.git
cd ai-templates
```

### Make Scripts Executable

```bash
chmod +x setup-repo-multitype.sh
chmod +x init-new-repo.sh
```

## Quick Start

### Basic Usage

```bash
# Create a new project in a specific directory
./setup-repo-multitype.sh /path/to/your/new-project

# Create a new project in the current parent directory
./setup-repo-multitype.sh my-project-name
```

### What Happens Next

1. The script asks questions about your project
2. It copies relevant templates and skills
3. It replaces placeholder variables with your values
4. It initializes a Git repository (optional)
5. Your project is ready for Claude Code!

## Setup Scripts

### `setup-repo-multitype.sh` (Recommended)

Enhanced setup script with multi-type support.

**Features:**
- Multi-select project types
- Intelligent skill selection
- Support for hybrid projects (e.g., Web + Desktop)
- More granular configuration options

**Usage:**
```bash
./setup-repo-multitype.sh [target-directory] [options]
```

**Options:**
- `target-directory` - Where to create the project (required)
- `--no-git` - Skip Git repository initialization
- `--no-skills` - Skip copying skills directory

### `init-new-repo.sh` (Original)

Original comprehensive setup script.

**Features:**
- Single project type selection
- Comprehensive template generation
- Full GitHub integration setup

**Usage:**
```bash
./init-new-repo.sh [target-directory]
```

## Interactive Walkthrough

### Step-by-Step Guide

When you run the setup script, you'll go through these steps:

#### 1. Project Information

```
┌─ Project Information
└────────────────────────────────────────────────────────────────

Project name: my-awesome-app
Project description: A full-stack task management application
Author name: John Doe
Author email: john@example.com
License type [MIT]: MIT
```

**Tips:**
- Use kebab-case for project names (e.g., `my-awesome-app`)
- Keep descriptions concise but descriptive
- Choose a license (MIT, Apache-2.0, GPL-3.0, etc.)

#### 2. Project Type Selection

```
┌─ Project Type (Multi-Select)
└────────────────────────────────────────────────────────────────

What type(s) of project is this? (You can select multiple)

  1. Web Application
     Frontend web app (React, Vue, Next.js, Nuxt, etc.)

  2. Backend/API
     Server-side application or REST/GraphQL API

  3. Full-Stack
     Combined frontend and backend (covers 1 + 2)

  4. Desktop Application
     Cross-platform desktop app (Electron, Tauri)

  5. CLI Tool
     Command-line interface application

  6. Library/Package
     Reusable library for npm/PyPI/crates.io

Enter your selections separated by spaces (e.g., '3 4' for Full-Stack + Desktop):
Choices: 3
```

**Tips:**
- Choose `3` (Full-Stack) for most web applications
- Select multiple types for hybrid projects
- `4` (Desktop) + `3` (Full-Stack) for apps like VS Code
- `5` (CLI) for command-line tools
- `6` (Library) for reusable packages

#### 3. Language Selection

```
┌─ Programming Languages
└────────────────────────────────────────────────────────────────

Select language for web/backend:
  1. TypeScript (frontend + backend)
  2. TypeScript (frontend) + Python (backend)
  3. Python only

Choice: 1
```

**Language Recommendations:**

| Project Type | Recommended Language | Why |
|-------------|---------------------|-----|
| Web App | TypeScript | Type safety, excellent tooling |
| Backend API | Python or TypeScript | FastAPI (Python) or NestJS (TypeScript) |
| Desktop App | Rust + TypeScript | Tauri uses Rust backend, TS frontend |
| CLI Tool | Python or Rust | Python for ease, Rust for performance |
| Library | Match target ecosystem | npm (TS), PyPI (Python), crates.io (Rust) |

#### 4. Framework Selection

```
┌─ Framework Selection
└────────────────────────────────────────────────────────────────

Select frontend framework:
  1. Vue 3 + Nuxt 3 (recommended)
  2. React + Next.js
  3. Svelte + SvelteKit
  4. Vue 3 (SPA only)

Choice: 1
```

**Framework Recommendations:**
- **Vue 3 + Nuxt 3**: Full-featured, great DX, SSR support
- **React + Next.js**: Industry standard, huge ecosystem
- **Svelte + SvelteKit**: Smaller bundle sizes, simpler syntax
- **Vue 3 SPA**: For simple single-page apps

#### 5. Features and Skills

```
┌─ Features and Skills
└────────────────────────────────────────────────────────────────

Which features do you need? (multi-select)

  1. Database (SQLite, PostgreSQL)
  2. Authentication & Authorization
  3. API (REST/GraphQL)
  4. WebSockets (Real-time)
  5. Background Tasks (Celery/Bull)
  6. File Uploads
  7. Email/Notifications
  8. Search (Full-text)
  9. Testing (Unit, Integration, E2E)
  10. DevOps (CI/CD, Docker)

Enter selections (e.g., '1 2 3 9 10'): 1 2 3 9 10
```

**Feature-to-Skill Mapping:**

| Feature | Skills Included |
|---------|----------------|
| Database | `database-design`, `sqlite`, `sqlcipher` |
| Authentication | `api-expert`, `security-auditing`, `encryption` |
| API | `rest-api-design`, `fastapi`, `graphql-expert` |
| WebSockets | `websocket`, `async-expert` |
| Background Tasks | `celery-expert`, `rabbitmq-expert`, `async-programming` |
| File Uploads | `appsec-expert`, `sandboxing` |
| Testing | `cicd-expert`, `devsecops-expert` |
| DevOps | `ci-cd`, `cicd-expert`, `argo-expert` |

#### 6. Git Initialization

```
┌─ Git Repository
└────────────────────────────────────────────────────────────────

Initialize Git repository? [Y/n]: y
Create initial commit? [Y/n]: y
```

**Tips:**
- Say `y` to both for a clean starting point
- Initial commit includes all templates and configuration
- `.gitignore` is automatically configured

#### 7. Completion

```
═══════════════════════════════════════════════════════════════
  Setup Complete!
═══════════════════════════════════════════════════════════════

Your project has been created at: /path/to/my-awesome-app

Next steps:

1. Navigate to your project:
   cd my-awesome-app

2. Review and customize CLAUDE.md for project-specific rules

3. Install dependencies:
   npm install  # or: pip install -e .

4. Start coding with Claude Code!

Skills included:
  ✓ typescript
  ✓ vue-nuxt
  ✓ fastapi
  ✓ database-design
  ✓ sqlite
  ✓ rest-api-design
  ✓ security-auditing
  ✓ ci-cd

Happy coding! 🚀
```

## Template Variables

### Available Variables

All template files support these placeholders:

#### Project Information
- `{{PROJECT_NAME}}` - Project name (e.g., `my-awesome-app`)
- `{{PROJECT_DESCRIPTION}}` - Brief description
- `{{AUTHOR_NAME}}` - Your name
- `{{AUTHOR_EMAIL}}` - Your email
- `{{LICENSE_TYPE}}` - License (e.g., `MIT`)
- `{{GITHUB_REPO}}` - GitHub repository URL

#### Architecture
- `{{ARCHITECTURE_DESCRIPTION}}` - Architecture overview
- `{{PROJECT_STRUCTURE}}` - Directory structure description
- `{{TECH_STACK}}` - Technology stack summary

#### Commands
- `{{INSTALL_COMMAND}}` - Installation command (e.g., `npm install`)
- `{{DEV_COMMAND}}` - Development server command (e.g., `npm run dev`)
- `{{BUILD_COMMAND}}` - Build command (e.g., `npm run build`)
- `{{TEST_COMMAND}}` - Test command (e.g., `npm test`)
- `{{LINT_COMMAND}}` - Lint command (e.g., `npm run lint`)
- `{{FORMAT_COMMAND}}` - Format command (e.g., `npm run format`)

#### Environment
- `{{PREREQUISITES}}` - Required software/tools
- `{{NODE_VERSION}}` - Node.js version (if applicable)
- `{{PYTHON_VERSION}}` - Python version (if applicable)

#### Claude Code
- `{{CLAUDE_COMMANDS}}` - List of available slash commands
- `{{SKILLS_LIST}}` - List of included skills

### How Variables Are Replaced

**Before (template):**
```markdown
# {{PROJECT_NAME}}

{{PROJECT_DESCRIPTION}}

## Installation

```bash
{{INSTALL_COMMAND}}
```

## Running Tests

```bash
{{TEST_COMMAND}}
```
```

**After (generated):**
```markdown
# my-awesome-app

A full-stack task management application

## Installation

```bash
npm install
```

## Running Tests

```bash
npm test
```
```

### Customizing Variables

You can manually edit any generated file after setup to adjust variables that weren't quite right:

```bash
# After setup, search and replace any variable
cd my-awesome-app
grep -r "{{" .  # Find any remaining template variables
```

## Skills System

### What Are Skills?

Skills are domain-specific knowledge modules that Claude Code can use to provide expert guidance. Each skill contains:

- **Core Principles** - Fundamental concepts and patterns
- **Security Considerations** - CVE tracking and OWASP awareness
- **Code Examples** - Implementation patterns
- **Risk Level** - Classification (HIGH, MEDIUM, LOW)
- **Extended References** - Advanced patterns and threat models

### Skill Structure

```
skills/
├── skill-name/
│   ├── SKILL.md                 # Main skill file (required)
│   └── references/              # Optional extended docs
│       ├── advanced-patterns.md
│       ├── security-examples.md
│       └── threat-model.md
```

### How Skills Are Selected

Skills are automatically selected based on your project configuration:

#### By Project Type

**Web Application:**
- `vue-nuxt` or `react-nextjs`
- `tailwindcss`
- `ui-ux-design`
- `pinia` (if Vue)
- `typescript`

**Backend/API:**
- `fastapi` or `nestjs`
- `rest-api-design` or `graphql-expert`
- `database-design`
- `async-expert`
- `api-expert`

**Full-Stack:**
- All Web + Backend skills
- `websocket` (if real-time features)
- `cicd-expert`

**Desktop Application:**
- `tauri` or `electron`
- `auto-update-systems`
- `browser-automation`
- Platform-specific skills (`macos-accessibility`, `windows-ui-automation`, `linux-at-spi2`)
- `rust` + `typescript`

**CLI Tool:**
- Language skill (`python`, `rust`, `typescript`)
- `applescript` or `dbus` (for system integration)

**Library/Package:**
- Language skill
- `cross-platform-builds`
- `cicd-expert`

#### By Feature

**Database:**
- `database-design`
- `sqlite` or `postgresql`
- `sqlcipher` (if encryption needed)
- `graph-database-expert` (if graph DB)

**Authentication:**
- `appsec-expert`
- `encryption`
- `os-keychain`
- `security-auditing`

**Real-time:**
- `websocket`
- `async-expert`
- `rabbitmq-expert` (for message queuing)

**Background Jobs:**
- `celery-expert` (Python)
- `async-programming`
- `rabbitmq-expert`

**AI/ML:**
- `llm-integration`
- `prompt-engineering`
- `model-quantization`
- `speech-to-text`, `text-to-speech`
- `wake-word-detection`

### Manually Adding Skills

After project creation, you can copy additional skills:

```bash
# Copy a specific skill
cp -r /path/to/ai-templates/skills/skill-name ./skills/

# Copy multiple skills
for skill in skill1 skill2 skill3; do
    cp -r /path/to/ai-templates/skills/$skill ./skills/
done
```

### Loading Skills in Claude Code

Skills can be loaded in several ways:

#### 1. Via CLAUDE.md (Auto-load)

Edit your project's `CLAUDE.md`:

```markdown
# My Project Instructions

## Skill Loading Requirements

Before implementing features, read the following skills:

1. Read `skills/fastapi/SKILL.md` for API implementation
2. Read `skills/database-design/SKILL.md` for database schema
3. Read `skills/security-auditing/SKILL.md` for security review

## Implementation Process

1. Load required skills
2. Review security considerations
3. Implement following TDD principles
4. Run tests before committing
```

#### 2. Via Slash Commands

Create a command in `.claude/commands/load-api-skills.md`:

```markdown
# Load API Development Skills

Read the following skills before implementing API features:

1. Read `skills/fastapi/SKILL.md`
2. Read `skills/rest-api-design/SKILL.md`
3. Read `skills/api-expert/SKILL.md`
4. Read `skills/async-expert/SKILL.md`

Now you're ready to implement API features following best practices!
```

Then use: `/load-api-skills`

#### 3. Direct Request

Simply ask Claude:

```
Please read skills/fastapi/SKILL.md before implementing the API endpoint
```

### Creating Custom Skills

#### 1. Create Skill Directory

```bash
mkdir -p skills/my-custom-skill/references
```

#### 2. Write SKILL.md

```markdown
# My Custom Skill

**Domain:** Brief description
**Risk Level:** MEDIUM
**Last Updated:** 2025-12-04

## Core Principles

1. Principle 1
2. Principle 2
3. Principle 3

## Security Considerations

### OWASP Top 10 Relevance
- A01:2021 - Broken Access Control: [Mitigation strategy]
- A02:2021 - Cryptographic Failures: [Mitigation strategy]

### Known CVEs
- CVE-YYYY-XXXXX: Description and mitigation

## Implementation Patterns

### Pattern 1: Pattern Name

```[language]
// Example code
```

**When to use:** Description
**Security notes:** Important considerations

## References

- [Official Documentation](https://example.com)
- [Security Guide](https://example.com/security)
```

#### 3. Add References (Optional)

```bash
# Advanced patterns
cat > skills/my-custom-skill/references/advanced-patterns.md << 'EOF'
# Advanced Patterns

## Pattern 1
...
EOF

# Security examples
cat > skills/my-custom-skill/references/security-examples.md << 'EOF'
# Security Examples

## Example 1: Secure Implementation
...
EOF
```

## Claude Code Integration

### CLAUDE.md Configuration

The `CLAUDE.md` file is automatically read by Claude Code at session start. This is where you define mandatory rules.

#### Example CLAUDE.md

```markdown
# My Project - Claude Code Instructions

## Project Overview

Full-stack task management application with real-time collaboration.

## Code Quality Requirements

### Security First
- Never introduce OWASP Top 10 vulnerabilities
- Validate all user inputs
- Use parameterized queries for database operations
- Store credentials in OS keychain only

### Architecture

This is a Nuxt 3 frontend + FastAPI backend application.

**Frontend:** TypeScript, Vue 3, Nuxt 3, Tailwind CSS, Pinia
**Backend:** Python 3.11+, FastAPI, SQLAlchemy, SQLite
**Deployment:** Docker, CI/CD via GitHub Actions

## Skill Loading Requirements

### For API Implementation
Before implementing API endpoints:
1. Read `skills/fastapi/SKILL.md`
2. Read `skills/rest-api-design/SKILL.md`
3. Read `skills/async-expert/SKILL.md`

### For Database Changes
Before modifying database schema:
1. Read `skills/database-design/SKILL.md`
2. Read `skills/sqlite/SKILL.md`

### For Security Features
Before implementing authentication or authorization:
1. Read `skills/appsec-expert/SKILL.md`
2. Read `skills/encryption/SKILL.md`
3. Read `skills/os-keychain/SKILL.md`

## Testing Requirements

### When User Asks to "Run Tests"

Execute ALL of these automatically:

```bash
# Frontend tests
cd frontend && npm test

# Backend tests
cd backend && pytest

# E2E tests
npm run test:e2e

# Lint
npm run lint
```

Report results for each step. Fix failures before proceeding.

### After Any Code Change

Before committing:

```bash
npm run lint
npm test
npm run build  # Ensure it builds
```

## Commit Guidelines

- Use conventional commit format
- Ensure all tests pass
- Never commit secrets or credentials

## Questions?

Ask for clarification before implementing if unclear.
```

### Slash Commands

Create custom commands for common workflows.

#### Example: `/implement-feature`

Create `.claude/commands/implement-feature.md`:

```markdown
# Feature Implementation Workflow

You are implementing a new feature. Follow this process:

## Step 1: Load Relevant Skills

Based on the feature type, read appropriate skills from `skills/`.

## Step 2: Security Review

Before writing code:
1. Identify potential security risks
2. Review OWASP Top 10 relevance
3. Check for applicable CVEs in skill files
4. Plan mitigations

## Step 3: TDD Implementation

1. Write tests first
2. Implement feature
3. Ensure tests pass
4. Refactor if needed

## Step 4: Code Quality

Run:
- Linting
- Type checking
- Security audit (if applicable)

## Step 5: Documentation

Update:
- Code comments (where needed)
- README (if user-facing feature)
- API docs (if API changes)

## Step 6: Commit

Create commit with conventional format:
- `feat:` for new features
- `fix:` for bug fixes
- `refactor:` for refactoring
- `docs:` for documentation

Ready to implement!
```

#### Example: `/security-review`

Create `.claude/commands/security-review.md`:

```markdown
# Security Review Checklist

Perform a comprehensive security review of the current code.

## Load Security Skills

Read these skills first:
1. `skills/appsec-expert/SKILL.md`
2. `skills/security-auditing/SKILL.md`

## Review Checklist

### 1. OWASP Top 10

Check for:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Security Logging Failures
- A10: Server-Side Request Forgery

### 2. Input Validation

- [ ] All user inputs are validated
- [ ] Type checking is enforced
- [ ] Length limits are applied
- [ ] Allowlist validation where possible

### 3. Authentication & Authorization

- [ ] Authentication is required where needed
- [ ] Authorization checks are in place
- [ ] Session management is secure
- [ ] Password handling is secure

### 4. Data Protection

- [ ] Sensitive data is encrypted
- [ ] Credentials use OS keychain
- [ ] Database queries are parameterized
- [ ] File operations respect sandboxing

### 5. Error Handling

- [ ] Errors don't leak sensitive info
- [ ] Logging is comprehensive
- [ ] Error messages are user-friendly

Report findings with severity levels and recommended fixes.
```

### Hooks Configuration

Edit `.claude/settings.json` to configure automated hooks:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "name": "dangerous-command-blocker",
        "command": "echo 'Checking for dangerous commands...'",
        "description": "Blocks potentially dangerous operations"
      }
    ],
    "PostToolUse": [
      {
        "name": "auto-format-python",
        "command": "black .",
        "description": "Auto-format Python code with black",
        "enabled": true
      },
      {
        "name": "auto-format-typescript",
        "command": "prettier --write .",
        "description": "Auto-format TypeScript with prettier",
        "enabled": true
      }
    ]
  }
}
```

## Advanced Usage

### Multi-Type Projects

Create projects that span multiple types:

```bash
./setup-repo-multitype.sh my-hybrid-app

# Select: 1 (Web) + 4 (Desktop)
# Result: A Tauri desktop app with web frontend
```

**Example Combinations:**

| Types | Use Case | Skills Included |
|-------|----------|-----------------|
| Web + Desktop | Electron/Tauri app | `tauri`, `vue-nuxt`, `typescript` |
| Backend + CLI | API with CLI client | `fastapi`, `python`, `rest-api-design` |
| Full-Stack + Library | App + SDK | All web/backend + `cross-platform-builds` |

### Custom Template Variables

Add your own variables to templates:

1. **Edit template files** to include `{{YOUR_VARIABLE}}`
2. **Edit setup script** to prompt for the variable
3. **Add replacement logic** in the script

Example:

```bash
# In setup script:
DATABASE_URL=$(prompt_with_default "Database URL" "sqlite:///./app.db")

# Add to replacement:
replace_variable "{{DATABASE_URL}}" "$DATABASE_URL" "$file"
```

### Skill Composition

Combine multiple skills for complex features:

```bash
# For a real-time API with authentication
# Skills: fastapi + websocket + async-expert + appsec-expert + encryption
```

### Version-Specific Templates

Create templates for specific framework versions:

```bash
# Branch per major version
git checkout -b nuxt-4-template
# Update templates for Nuxt 4
```

### Monorepo Setup

For monorepo projects:

```bash
# Create root project
./setup-repo-multitype.sh my-monorepo --project-type=3

# Create sub-projects
cd my-monorepo
mkdir -p apps/frontend apps/backend packages/shared

# Copy skills to each sub-project as needed
```

## Troubleshooting

### Common Issues

#### 1. Script Permission Denied

**Problem:**
```bash
bash: ./setup-repo-multitype.sh: Permission denied
```

**Solution:**
```bash
chmod +x setup-repo-multitype.sh
```

#### 2. Template Variables Not Replaced

**Problem:** Generated files still contain `{{VARIABLE_NAME}}`

**Solution:**
- Check if variable is defined in the setup script
- Manually search and replace:
```bash
grep -r "{{" . | grep -v ".git"
# Manually edit files with remaining variables
```

#### 3. Skills Not Copying

**Problem:** Skills directory is empty after setup

**Solution:**
```bash
# Manually copy skills
cp -r /path/to/ai-templates/skills/[skill-name] ./skills/
```

#### 4. Git Initialization Fails

**Problem:** Git commands fail during setup

**Solution:**
```bash
# Skip git init during setup
./setup-repo-multitype.sh my-project --no-git

# Manually initialize later
cd my-project
git init
git add .
git commit -m "Initial commit"
```

#### 5. Claude Code Doesn't Read CLAUDE.md

**Problem:** Claude doesn't follow rules in CLAUDE.md

**Solution:**
- Ensure file is named exactly `CLAUDE.md` (case-sensitive)
- Check file is in repository root
- Restart Claude Code session
- Verify file syntax (must be valid Markdown)

### Debug Mode

Run scripts in debug mode:

```bash
bash -x ./setup-repo-multitype.sh my-project 2>&1 | tee setup.log
```

This creates a log file with all commands executed.

## Best Practices

### 1. Start Simple

- Begin with basic setup
- Add skills incrementally
- Customize CLAUDE.md gradually

### 2. Review Generated Files

After setup, review:
- `CLAUDE.md` - Ensure rules are appropriate
- `README.md` - Customize for your project
- `.github/workflows/` - Adjust CI/CD pipeline
- `skills/` - Remove unused skills

### 3. Commit Early, Commit Often

```bash
# After setup
git add .
git commit -m "chore: initial project setup from ai-templates"

# After customizations
git commit -m "chore: customize CLAUDE.md and README"
```

### 4. Keep Skills Updated

Periodically sync skills from ai-templates:

```bash
# Pull latest changes from ai-templates
cd /path/to/ai-templates
git pull

# Copy updated skills to your project
cp -r /path/to/ai-templates/skills/[skill-name] /path/to/your-project/skills/
```

### 5. Document Project-Specific Patterns

Add custom skills for your project:

```bash
mkdir -p skills/project-patterns
# Document your project's specific patterns
```

### 6. Use Slash Commands Liberally

Create commands for repetitive tasks:
- `/setup-dev` - Set up development environment
- `/run-all-tests` - Run full test suite
- `/deploy-staging` - Deploy to staging
- `/security-check` - Run security audit

### 7. Leverage Hooks for Consistency

Configure hooks for automatic formatting:
- Black for Python
- Prettier for JavaScript/TypeScript
- ESLint for type checking
- Security linting

### 8. Security First

Always:
- Load security skills before implementing auth
- Review OWASP Top 10 considerations
- Use OS keychain for credentials
- Validate all inputs
- Parameterize database queries

---

## Next Steps

1. **Create your first project:**
   ```bash
   ./setup-repo-multitype.sh my-first-project
   ```

2. **Review generated files** and customize as needed

3. **Start coding with Claude Code** and use slash commands

4. **Explore the [Skills Reference](./SKILLS_REFERENCE.md)** for available skills

5. **Read [CLAUDE_CODE_ARCHITECTURE.md](./CLAUDE_CODE_ARCHITECTURE.md)** to understand how Claude Code integration works

---

**Need Help?**
- Check [README.md](./README.md) for overview
- See [SKILLS_REFERENCE.md](./SKILLS_REFERENCE.md) for skills catalog
- Open an issue on GitHub
- Ask Claude Code directly!
