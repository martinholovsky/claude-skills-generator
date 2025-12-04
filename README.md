# Claude AI Skill Generator

A comprehensive template repository system for bootstrapping AI-assisted development projects with Claude Code integration. This repository provides production-ready templates, domain-specific skills, and automated setup scripts to quickly initialize new projects optimized for AI-assisted development.

## 🚀 Quick Start

```bash
# Clone this repository
git clone https://github.com/martinholovsky/ai-templates.git
cd ai-templates

# Run the setup script (interactive mode)
./setup-repo-multitype.sh /path/to/your/new-project

# Or use the original script
./init-new-repo.sh /path/to/your/new-project
```

The script will guide you through:
- Project type selection (Web, Backend, Full-Stack, Desktop, CLI, Library)
- Language selection (TypeScript, Python, Rust, etc.)
- Feature selection and skill copying
- Template file generation with your project details
- Git repository initialization

## 📋 What's Included

### 1. **Interactive Setup Scripts**

- **`setup-repo-multitype.sh`** - Enhanced setup with multi-type support
- **`init-new-repo.sh`** - Original comprehensive setup script

Both scripts provide:
- Interactive project configuration
- Automatic skill selection based on project type
- Template variable substitution
- Git repository initialization
- Claude Code configuration

### 2. **Production-Ready Templates**

All template files use placeholders (e.g., `{{PROJECT_NAME}}`) that get replaced during setup:

- **`CLAUDE.md`** - Claude Code project instructions (auto-read by Claude)
- **`README.md`** - Project documentation template
- **`CONTRIBUTING.md`** - Contribution guidelines with AI-assisted workflows
- **`SECURITY.md`** - Security policy with AI-specific considerations
- **`CODE_OF_CONDUCT.md`** - Community code of conduct
- **`.gitignore`** - Comprehensive ignore patterns
- **`.env.example`** - Environment variable template

### 3. **Claude Code Integration**

The `.claude/` directory contains:

**Configuration:**
- `settings.json` - Hooks configuration (pre/post tool use, formatting)

**Slash Commands** (user-invoked):
- `/implement-feature` - Feature implementation workflow
- `/run-tests` - Automated test execution
- `/review-code` - Code review checklist

### 4. **GitHub Templates**

The `.github/` directory includes:

- **`workflows/ci.yml`** - CI/CD pipeline (lint, test, build, security audit)
- **`PULL_REQUEST_TEMPLATE.md`** - PR template with AI disclosure section
- **Issue Templates:**
  - `bug_report.md`
  - `feature_request.md`

### 5. **Domain-Specific Skills (67+ Skills)**

Specialized knowledge modules for specific technologies. See [SKILLS_REFERENCE.md](./SKILLS_REFERENCE.md) for the complete catalog.

**Categories:**
- **Frontend/UI** (11): Vue, Nuxt, Pinia, Tailwind, GSAP, Three.js, WebGL, Design Systems, UI/UX
- **Backend/API** (15): FastAPI, GraphQL, REST, WebSocket, JSON-RPC, async, Celery, RabbitMQ, MCP
- **Languages** (4): TypeScript, JavaScript, Python, Rust
- **Databases** (5): SQLite, SQLCipher, SurrealDB, Graph Databases, Database Design
- **Security** (6): AppSec, Security Auditing, Encryption, OS Keychain, Sandboxing, DevSecOps
- **DevOps** (8): CI/CD, ArgoCD, Cilium, Harbor, Talos OS, Kanidm, Cloud APIs, Cross-Platform Builds
- **Desktop** (3): Tauri, Browser Automation, Auto-Update Systems
- **Platform-Specific** (7): macOS, Windows, Linux accessibility and automation
- **AI/ML** (4): LLM Integration, Model Quantization, Prompt Engineering, Speech/Wake-Word
- **Multimedia** (2): Web Audio API, Text-to-Speech/Speech-to-Text
- **Accessibility** (2): WCAG, platform-specific accessibility

Each skill includes:
- Core principles and best practices
- Security considerations and CVE tracking
- Code patterns and examples
- Risk level classification (HIGH/MEDIUM/LOW)
- Extended references for advanced patterns

## 🎯 Key Features

### Security-First Development
- OWASP Top 10 awareness built into all templates
- CVE tracking in skill files
- Credential management via OS keychain
- Input validation emphasis
- Security audit workflows

### AI-Assisted Development Guidelines
- TDD-first principles
- Skill loading protocols
- Security review requirements
- AI code verification procedures
- Conventional commit format enforcement

### Template Variable System
All templates use placeholders that get replaced during setup:
- `{{PROJECT_NAME}}` - Your project name
- `{{PROJECT_DESCRIPTION}}` - Project description
- `{{ARCHITECTURE_DESCRIPTION}}` - Architecture overview
- `{{TEST_COMMAND}}` - Test command
- `{{BUILD_COMMAND}}` - Build command
- `{{DEV_COMMAND}}` - Development command
- And many more...

## 📖 Documentation

- **[USAGE.md](./USAGE.md)** - Detailed usage guide with examples
- **[SKILLS_REFERENCE.md](./SKILLS_REFERENCE.md)** - Complete skills catalog
- **[CLAUDE_CODE_ARCHITECTURE.md](./CLAUDE_CODE_ARCHITECTURE.md)** - Claude Code integration architecture (template)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines (template)

## 🛠️ Supported Project Types

### 1. Web Application
- Frontend SPAs (React, Vue, Svelte)
- SSR frameworks (Next.js, Nuxt)
- Relevant skills: vue-nuxt, tailwindcss, pinia, ui-ux-design

### 2. Backend/API
- REST APIs (FastAPI, Express, NestJS)
- GraphQL APIs
- WebSocket servers
- Relevant skills: fastapi, rest-api-design, graphql, websocket

### 3. Full-Stack
- Monorepo setups
- Combined frontend + backend
- Relevant skills: Combination of web + backend skills

### 4. Desktop Application
- Cross-platform apps (Tauri, Electron)
- Native integrations
- Relevant skills: tauri, browser-automation, auto-update-systems

### 5. CLI Tool
- Command-line applications
- Terminal utilities
- Relevant skills: python, rust, typescript

### 6. Library/Package
- Reusable libraries
- npm/PyPI/crates.io packages
- Relevant skills: Language-specific skills

## 🔧 How It Works

### 1. Setup Process

```bash
./setup-repo-multitype.sh my-new-project
```

The script will:
1. **Prompt for project details:**
   - Project name and description
   - Project type(s) (multi-select supported)
   - Programming language(s)
   - Features and frameworks

2. **Copy relevant skills:**
   - Automatically selects skills based on your choices
   - Copies selected skills to your project's `skills/` directory

3. **Generate configuration files:**
   - Replaces template variables with your values
   - Creates `.claude/` configuration
   - Sets up `.github/` workflows

4. **Initialize Git repository:**
   - Creates initial commit
   - Sets up branch structure (optional)

### 2. Template Variable Replacement

During setup, all template files are processed:

**Before:**
```markdown
# {{PROJECT_NAME}}

{{PROJECT_DESCRIPTION}}
```

**After:**
```markdown
# My Awesome Project

A full-stack application for managing tasks with AI assistance.
```

### 3. Skill Loading

Skills are loaded based on your project configuration:

- **Automatic:** Selected during setup based on project type
- **Manual:** Copy additional skills from the `skills/` directory
- **Claude Code:** Reference skills in your `CLAUDE.md` or slash commands

## 🎓 Usage Examples

### Example 1: Full-Stack Web Application

```bash
./setup-repo-multitype.sh ~/projects/task-manager

# Interactive prompts:
# - Project name: task-manager
# - Type: 3 (Full-Stack)
# - Language: 1 (TypeScript)
# - Framework: Nuxt 3 + FastAPI
# - Features: Database (SQLite), Authentication, API
```

**Result:**
- Vue/Nuxt frontend skills
- FastAPI backend skills
- Database design and SQLite skills
- TypeScript configuration
- Full CI/CD pipeline
- Claude Code integration

### Example 2: Desktop Application

```bash
./setup-repo-multitype.sh ~/projects/my-desktop-app

# Interactive prompts:
# - Project name: my-desktop-app
# - Type: 4 (Desktop)
# - Framework: Tauri
# - Features: Auto-updates, System integration
```

**Result:**
- Tauri skill with security patterns
- Auto-update systems skill
- Platform-specific skills (macOS, Windows, Linux)
- Rust + TypeScript configuration
- Cross-platform build workflows

### Example 3: Python CLI Tool

```bash
./setup-repo-multitype.sh ~/projects/cli-tool

# Interactive prompts:
# - Project name: cli-tool
# - Type: 5 (CLI)
# - Language: 3 (Python only)
# - Features: Configuration, Logging
```

**Result:**
- Python skill with best practices
- CLI patterns and examples
- Testing configuration (pytest)
- PyPI packaging setup

## 🤖 Claude Code Integration

After project creation, Claude Code automatically:

1. **Reads `CLAUDE.md`** at session start
2. **Applies project-specific rules** and guidelines
3. **Uses skills** when invoked via commands or instructions
4. **Enforces security** and code quality standards
5. **Runs hooks** for formatting and validation

### Working with Claude Code

```bash
# In your new project
cd my-new-project

# Claude Code automatically reads CLAUDE.md
# Use slash commands:
/implement-feature     # Load feature implementation workflow
/run-tests            # Run all tests automatically
/review-code          # Run code review checklist

# Skills are referenced in CLAUDE.md and loaded as needed
```

## 📦 Project Structure After Setup

```
my-new-project/
├── CLAUDE.md                          # Claude's project instructions
├── README.md                          # Your project documentation
├── CONTRIBUTING.md                    # Contribution guidelines
├── SECURITY.md                        # Security policy
├── CODE_OF_CONDUCT.md                 # Code of conduct
│
├── .claude/
│   ├── settings.json                  # Claude Code configuration
│   └── commands/                      # Slash commands
│       ├── implement-feature.md
│       ├── run-tests.md
│       └── review-code.md
│
├── .github/
│   ├── workflows/
│   │   └── ci.yml                     # CI/CD pipeline
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── skills/                            # Relevant domain skills
│   ├── typescript/
│   ├── fastapi/
│   ├── database-design/
│   └── ...
│
├── src/                               # Your source code
└── tests/                             # Your tests
```

## 🔒 Security Considerations

### Built-in Security Features

- **OWASP Top 10** awareness in all templates
- **CVE tracking** in security-sensitive skills
- **Credential management** via OS keychain (never plaintext)
- **Input validation** emphasis throughout
- **Security audit** workflow in CI/CD
- **Sandboxing** guidelines for file operations
- **Security policy** template for responsible disclosure

### Security Skills

The repository includes specialized security skills:
- **appsec-expert** - Application security patterns
- **security-auditing** - Security review checklists
- **encryption** - Cryptography best practices
- **os-keychain** - Secure credential storage
- **sandboxing** - File system isolation
- **devsecops-expert** - Security automation

## 🤝 Contributing

This is a template repository designed to bootstrap new projects. Contributions are welcome!

### How to Contribute

1. **Add new skills:**
   - Create skill directory: `skills/your-skill/`
   - Add `SKILL.md` with patterns and security considerations
   - Include risk level classification
   - Add references if needed

2. **Improve templates:**
   - Enhance existing template files
   - Add new template variables
   - Improve Claude Code integration

3. **Enhance setup scripts:**
   - Add new project types
   - Improve interactive prompts
   - Add validation and error handling

4. **Update documentation:**
   - Improve usage examples
   - Add troubleshooting guides
   - Document new features

### Contribution Guidelines

- Follow security-first principles
- Include examples and documentation
- Test setup scripts thoroughly
- Maintain template variable consistency
- Follow conventional commit format

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## 🙏 Acknowledgments

- Built for use with [Claude Code](https://claude.ai/code) by Anthropic
- Inspired by best practices from the open-source community
- Security patterns from OWASP and CVE databases
- Framework-specific patterns from official documentation

## 📞 Support

- **Documentation:** See [USAGE.md](./USAGE.md) for detailed usage instructions
- **Skills Reference:** See [SKILLS_REFERENCE.md](./SKILLS_REFERENCE.md) for all available skills
- **Issues:** Report issues via GitHub Issues
- **Questions:** Open a discussion in GitHub Discussions

---

**Built with ❤️ for AI-assisted development**
