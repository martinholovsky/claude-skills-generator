# Skills Reference - Complete Catalog

This document provides a comprehensive catalog of all available skills in the AI Templates repository. Each skill is a domain-specific knowledge module that provides Claude Code with expert guidance, security considerations, and implementation patterns.

## Table of Contents

- [Overview](#overview)
- [Skill Structure](#skill-structure)
- [Skills by Category](#skills-by-category)
  - [Frontend & UI](#frontend--ui)
  - [Backend & API](#backend--api)
  - [Programming Languages](#programming-languages)
  - [Databases](#databases)
  - [Security](#security)
  - [DevOps & Infrastructure](#devops--infrastructure)
  - [Desktop & Native](#desktop--native)
  - [Platform-Specific](#platform-specific)
  - [AI & Machine Learning](#ai--machine-learning)
  - [Multimedia](#multimedia)
  - [Accessibility](#accessibility)
- [Quick Reference Table](#quick-reference-table)
- [How to Use Skills](#how-to-use-skills)

## Overview

**Total Skills:** 67+
**Last Updated:** 2025-12-04

Each skill includes:
- **Core Principles** - Fundamental concepts and best practices
- **Security Considerations** - OWASP Top 10 relevance and CVE tracking
- **Implementation Patterns** - Code examples and patterns
- **Risk Level** - Classification (HIGH, MEDIUM, LOW)
- **References** - Links to official documentation and advanced patterns

## Skill Structure

```
skills/
├── skill-name/
│   ├── SKILL.md                      # Main skill file (required)
│   └── references/                   # Optional extended documentation
│       ├── advanced-patterns.md      # Advanced implementation patterns
│       ├── security-examples.md      # Security-specific examples
│       ├── threat-model.md           # STRIDE analysis and attack scenarios
│       └── [framework]-guide.md      # Framework-specific guides
```

## Skills by Category

### Frontend & UI

#### vue-nuxt
- **Description:** Vue 3 and Nuxt 3 framework expertise
- **Risk Level:** MEDIUM
- **Use Cases:** SPAs, SSR web applications, universal apps
- **Key Topics:** Composition API, auto-imports, server routes, Nitro engine
- **Security Focus:** XSS prevention, CSP, CORS, input sanitization
- **Related Skills:** `pinia`, `tailwindcss`, `typescript`

#### vue-nuxt-expert
- **Description:** Advanced Vue 3 and Nuxt 3 patterns
- **Risk Level:** MEDIUM
- **Use Cases:** Complex state management, advanced composables, custom plugins
- **Key Topics:** Advanced reactivity, SSR optimization, performance tuning
- **Security Focus:** Advanced XSS prevention, hydration security
- **Extended Docs:** Advanced patterns, performance optimization
- **Related Skills:** `vue-nuxt`, `pinia`

#### pinia
- **Description:** Pinia state management for Vue 3
- **Risk Level:** LOW
- **Use Cases:** Application state management, shared state
- **Key Topics:** Stores, getters, actions, plugins
- **Security Focus:** State tampering prevention, sensitive data handling
- **Related Skills:** `vue-nuxt`, `vue-nuxt-expert`

#### tailwindcss
- **Description:** Utility-first CSS framework
- **Risk Level:** LOW
- **Use Cases:** Rapid UI development, responsive design
- **Key Topics:** Utility classes, custom configuration, dark mode, responsive design
- **Security Focus:** CSS injection prevention, safe dynamic classes
- **Related Skills:** `design-systems`, `ui-ux-design`

#### design-systems
- **Description:** Design system architecture and implementation
- **Risk Level:** LOW
- **Use Cases:** Component libraries, design tokens, style guides
- **Key Topics:** Atomic design, design tokens, component APIs
- **Security Focus:** Component security, input validation in components
- **Related Skills:** `ui-ux-design`, `tailwindcss`

#### ui-ux-design
- **Description:** UI/UX design principles and patterns
- **Risk Level:** LOW
- **Use Cases:** User interface design, user experience optimization
- **Key Topics:** Design principles, interaction patterns, information architecture
- **Security Focus:** Dark patterns avoidance, privacy by design
- **Related Skills:** `design-systems`, `accessibility-wcag`

#### ui-ux-expert
- **Description:** Advanced UI/UX design patterns and accessibility
- **Risk Level:** LOW
- **Use Cases:** Complex UI systems, advanced interactions, accessibility
- **Key Topics:** Advanced patterns, accessibility, performance, internationalization
- **Security Focus:** Accessibility security, inclusive design
- **Extended Docs:** 125K+ of advanced patterns
- **Related Skills:** `ui-ux-design`, `accessibility-wcag`

#### gsap
- **Description:** GreenSock Animation Platform (GSAP)
- **Risk Level:** LOW
- **Use Cases:** Web animations, interactive experiences
- **Key Topics:** Tweens, timelines, ScrollTrigger, advanced effects
- **Security Focus:** Animation performance, DOM manipulation security
- **Related Skills:** `motion-design`, `threejs-tresjs`

#### motion-design
- **Description:** Motion design principles for web
- **Risk Level:** LOW
- **Use Cases:** Animated UIs, transitions, micro-interactions
- **Key Topics:** Animation principles, easing, choreography
- **Security Focus:** Performance considerations, accessibility
- **Related Skills:** `gsap`, `web-audio-api`

#### threejs-tresjs
- **Description:** Three.js 3D graphics and TresJS for Vue
- **Risk Level:** MEDIUM
- **Use Cases:** 3D visualizations, WebGL applications
- **Key Topics:** 3D scenes, meshes, materials, lighting, TresJS integration
- **Security Focus:** Resource limits, shader safety, input validation
- **Related Skills:** `webgl`, `glsl`

#### webgl
- **Description:** WebGL graphics programming
- **Risk Level:** HIGH
- **Use Cases:** High-performance 3D graphics, custom renderers
- **Key Topics:** WebGL API, buffers, shaders, textures
- **Security Focus:** Shader injection, GPU resource management, timing attacks
- **Related Skills:** `glsl`, `threejs-tresjs`

#### glsl
- **Description:** OpenGL Shading Language for WebGL
- **Risk Level:** HIGH
- **Use Cases:** Custom shaders, visual effects, GPU computing
- **Key Topics:** Vertex shaders, fragment shaders, GLSL syntax
- **Security Focus:** Shader injection, infinite loops, timing attacks
- **Related Skills:** `webgl`, `threejs-tresjs`

---

### Backend & API

#### fastapi
- **Description:** FastAPI Python web framework fundamentals
- **Risk Level:** MEDIUM
- **Use Cases:** REST APIs, async web applications
- **Key Topics:** Path operations, dependency injection, Pydantic validation
- **Security Focus:** Input validation, SQL injection prevention, authentication
- **Related Skills:** `fastapi-expert`, `rest-api-design`, `async-expert`

#### fastapi-expert
- **Description:** Advanced FastAPI patterns and optimization
- **Risk Level:** HIGH
- **Use Cases:** High-performance APIs, complex authentication, advanced patterns
- **Key Topics:** Advanced dependencies, middleware, background tasks, WebSockets
- **Security Focus:** Advanced authentication, rate limiting, security middleware
- **Extended Docs:** Security examples, advanced patterns, threat models
- **Related Skills:** `fastapi`, `api-expert`, `async-expert`

#### api-expert
- **Description:** General API design and implementation expertise
- **Risk Level:** MEDIUM
- **Use Cases:** Any API development, API architecture
- **Key Topics:** API design, versioning, documentation, testing
- **Security Focus:** API security best practices, rate limiting, authentication
- **Related Skills:** `rest-api-design`, `graphql-expert`

#### rest-api-design
- **Description:** RESTful API design principles
- **Risk Level:** MEDIUM
- **Use Cases:** REST API development, API architecture
- **Key Topics:** Resource design, HTTP methods, status codes, HATEOAS
- **Security Focus:** REST security, OWASP API Security Top 10
- **Related Skills:** `api-expert`, `fastapi`

#### graphql-expert
- **Description:** GraphQL API development
- **Risk Level:** HIGH
- **Use Cases:** GraphQL APIs, flexible data querying
- **Key Topics:** Schema design, resolvers, queries, mutations, subscriptions
- **Security Focus:** Query depth limiting, complexity analysis, authorization
- **Related Skills:** `api-expert`, `websocket`

#### async-expert
- **Description:** Advanced asynchronous programming
- **Risk Level:** MEDIUM
- **Use Cases:** Async I/O, concurrent operations, event-driven systems
- **Key Topics:** async/await, event loops, concurrent patterns
- **Security Focus:** Race conditions, deadlocks, resource exhaustion
- **Related Skills:** `async-programming`, `fastapi-expert`, `celery-expert`

#### async-programming
- **Description:** Asynchronous programming fundamentals
- **Risk Level:** MEDIUM
- **Use Cases:** Basic async operations, concurrent programming
- **Key Topics:** Promises, async/await, callbacks, coroutines
- **Security Focus:** Basic concurrency safety
- **Related Skills:** `async-expert`

#### celery-expert
- **Description:** Celery distributed task queue
- **Risk Level:** MEDIUM
- **Use Cases:** Background tasks, scheduled jobs, distributed processing
- **Key Topics:** Tasks, workers, brokers, result backends, scheduling
- **Security Focus:** Task injection, result tampering, broker security
- **Related Skills:** `rabbitmq-expert`, `async-expert`

#### rabbitmq-expert
- **Description:** RabbitMQ message broker
- **Risk Level:** MEDIUM
- **Use Cases:** Message queuing, event-driven architecture, microservices
- **Key Topics:** Exchanges, queues, bindings, routing, clustering
- **Security Focus:** Message tampering, authentication, SSL/TLS
- **Related Skills:** `celery-expert`, `websocket`

#### websocket
- **Description:** WebSocket real-time communication
- **Risk Level:** HIGH
- **Use Cases:** Real-time applications, chat, live updates
- **Key Topics:** WebSocket protocol, connections, messages, authentication
- **Security Focus:** CSRF, XSS via WebSocket, DoS, authentication
- **Related Skills:** `fastapi-expert`, `async-expert`

#### json-rpc
- **Description:** JSON-RPC protocol implementation
- **Risk Level:** MEDIUM
- **Use Cases:** RPC-style APIs, method-based APIs
- **Key Topics:** JSON-RPC 2.0, methods, notifications, batching
- **Security Focus:** Method injection, authorization, input validation
- **Related Skills:** `api-expert`, `websocket`

#### mcp
- **Description:** Model Context Protocol for AI integrations
- **Risk Level:** MEDIUM
- **Use Cases:** AI tool integration, Claude Code extensions
- **Key Topics:** MCP servers, tools, prompts, resources
- **Security Focus:** Tool security, input validation, sandboxing
- **Related Skills:** `llm-integration`, `prompt-engineering`

---

### Programming Languages

#### typescript
- **Description:** TypeScript fundamentals
- **Risk Level:** LOW
- **Use Cases:** Type-safe JavaScript development
- **Key Topics:** Types, interfaces, generics, type guards
- **Security Focus:** Type safety for security, any-type avoidance
- **Related Skills:** `typescript-expert`, `javascript-expert`

#### typescript-expert
- **Description:** Advanced TypeScript patterns
- **Risk Level:** LOW
- **Use Cases:** Complex type systems, advanced patterns
- **Key Topics:** Advanced types, conditional types, mapped types, decorators
- **Security Focus:** Type-level security, branded types
- **Related Skills:** `typescript`

#### javascript-expert
- **Description:** Advanced JavaScript expertise
- **Risk Level:** MEDIUM
- **Use Cases:** Complex JavaScript applications, advanced patterns
- **Key Topics:** Prototypes, closures, async patterns, modern features
- **Security Focus:** XSS, prototype pollution, eval dangers
- **Related Skills:** `typescript`, `typescript-expert`

#### python
- **Description:** Python programming fundamentals
- **Risk Level:** MEDIUM
- **Use Cases:** General Python development, scripting, automation
- **Key Topics:** Python syntax, standard library, OOP, functional patterns
- **Security Focus:** Input validation, code injection, pickle dangers
- **Related Skills:** `fastapi`, `celery-expert`

#### rust
- **Description:** Rust systems programming
- **Risk Level:** MEDIUM
- **Use Cases:** Systems programming, high-performance applications, Tauri backends
- **Key Topics:** Ownership, borrowing, lifetimes, unsafe code
- **Security Focus:** Memory safety, unsafe code auditing, FFI safety
- **Related Skills:** `tauri`, `cross-platform-builds`

---

### Databases

#### database-design
- **Description:** Database schema design and modeling
- **Risk Level:** MEDIUM
- **Use Cases:** Database architecture, schema design, normalization
- **Key Topics:** ER modeling, normalization, indexing, query optimization
- **Security Focus:** SQL injection prevention, access control, encryption
- **Related Skills:** `sqlite`, `sqlcipher`, `surrealdb-expert`

#### sqlite
- **Description:** SQLite embedded database
- **Risk Level:** MEDIUM
- **Use Cases:** Embedded databases, mobile apps, desktop apps
- **Key Topics:** SQLite API, transactions, WAL mode, FTS5
- **Security Focus:** SQL injection, file permissions, encryption needs
- **Related Skills:** `sqlcipher`, `database-design`

#### sqlcipher
- **Description:** SQLCipher encrypted SQLite
- **Risk Level:** HIGH
- **Use Cases:** Encrypted local databases, secure data storage
- **Key Topics:** Encryption setup, key management, migration from SQLite
- **Security Focus:** Encryption key management, secure key derivation
- **Related Skills:** `sqlite`, `encryption`, `os-keychain`

#### surrealdb-expert
- **Description:** SurrealDB multi-model database
- **Risk Level:** MEDIUM
- **Use Cases:** Modern multi-model databases, graph + document + SQL
- **Key Topics:** SurrealQL, relations, graph queries, real-time
- **Security Focus:** Query injection, authentication, permissions
- **Related Skills:** `database-design`, `graph-database-expert`

#### graph-database-expert
- **Description:** Graph database concepts and patterns
- **Risk Level:** MEDIUM
- **Use Cases:** Graph data modeling, relationship-heavy data
- **Key Topics:** Graph modeling, traversal algorithms, Cypher/Gremlin
- **Security Focus:** Traversal injection, access control, query limits
- **Related Skills:** `surrealdb-expert`, `database-design`

---

### Security

#### appsec-expert
- **Description:** Application security expertise (OWASP Top 10)
- **Risk Level:** HIGH
- **Use Cases:** Security auditing, secure development, threat modeling
- **Key Topics:** OWASP Top 10, secure coding, threat modeling, penetration testing
- **Security Focus:** ALL security concerns, comprehensive coverage
- **Extended Docs:** Security examples, CVE tracking, threat models
- **Related Skills:** `security-auditing`, `encryption`, `devsecops-expert`

#### security-auditing
- **Description:** Security audit processes and checklists
- **Risk Level:** HIGH
- **Use Cases:** Code reviews, security assessments, compliance
- **Key Topics:** Audit checklists, vulnerability scanning, SAST/DAST
- **Security Focus:** Comprehensive security review process
- **Related Skills:** `appsec-expert`, `devsecops-expert`

#### encryption
- **Description:** Cryptography and encryption best practices
- **Risk Level:** HIGH
- **Use Cases:** Data encryption, password hashing, secure communication
- **Key Topics:** Symmetric/asymmetric encryption, hashing, key management
- **Security Focus:** Crypto implementation, key management, algorithm selection
- **Related Skills:** `os-keychain`, `sqlcipher`, `appsec-expert`

#### os-keychain
- **Description:** Operating system keychain/credential management
- **Risk Level:** HIGH
- **Use Cases:** Secure credential storage, API key management
- **Key Topics:** macOS Keychain, Windows Credential Manager, Linux Secret Service
- **Security Focus:** Secure credential storage, never plaintext passwords
- **Related Skills:** `encryption`, `appsec-expert`

#### sandboxing
- **Description:** File system and process sandboxing
- **Risk Level:** HIGH
- **Use Cases:** Secure file operations, process isolation
- **Key Topics:** Chroot, containers, file path validation, directory traversal prevention
- **Security Focus:** Path traversal, sandbox escape prevention
- **Related Skills:** `appsec-expert`, `tauri`

#### devsecops-expert
- **Description:** DevSecOps practices and security automation
- **Risk Level:** HIGH
- **Use Cases:** Security in CI/CD, automated security testing
- **Key Topics:** SAST, DAST, dependency scanning, secrets detection
- **Security Focus:** Automated security in pipeline
- **Related Skills:** `security-auditing`, `cicd-expert`, `appsec-expert`

---

### DevOps & Infrastructure

#### ci-cd
- **Description:** CI/CD fundamentals
- **Risk Level:** MEDIUM
- **Use Cases:** Continuous integration, automated deployment
- **Key Topics:** Pipeline design, automated testing, deployment strategies
- **Security Focus:** Pipeline security, secrets management, supply chain
- **Related Skills:** `cicd-expert`, `devsecops-expert`

#### cicd-expert
- **Description:** Advanced CI/CD patterns
- **Risk Level:** MEDIUM
- **Use Cases:** Complex pipelines, multi-environment deployments
- **Key Topics:** Advanced workflows, GitOps, canary deployments
- **Security Focus:** Advanced pipeline security, compliance
- **Related Skills:** `ci-cd`, `argo-expert`, `devsecops-expert`

#### argo-expert
- **Description:** ArgoCD, Argo Workflows, Argo Rollouts expertise
- **Risk Level:** MEDIUM
- **Use Cases:** Kubernetes GitOps, workflow orchestration, progressive delivery
- **Key Topics:** ArgoCD apps, Argo Workflows, Argo Rollouts, Argo Events
- **Security Focus:** GitOps security, RBAC, secret management
- **Extended Docs:** 158K+ comprehensive guide
- **Related Skills:** `cicd-expert`, `cilium-expert`, `talos-os-expert`

#### cilium-expert
- **Description:** Cilium networking and security for Kubernetes
- **Risk Level:** HIGH
- **Use Cases:** Kubernetes networking, network policies, observability
- **Key Topics:** eBPF, network policies, service mesh, Hubble
- **Security Focus:** Network security, zero-trust networking
- **Related Skills:** `argo-expert`, `talos-os-expert`

#### harbor-expert
- **Description:** Harbor container registry
- **Risk Level:** MEDIUM
- **Use Cases:** Private container registries, image scanning
- **Key Topics:** Registry management, image scanning, replication, RBAC
- **Security Focus:** Image security, vulnerability scanning, access control
- **Related Skills:** `cicd-expert`, `devsecops-expert`

#### talos-os-expert
- **Description:** Talos Linux for Kubernetes
- **Risk Level:** HIGH
- **Use Cases:** Immutable Kubernetes OS, secure clusters
- **Key Topics:** Talos installation, configuration, maintenance, security
- **Security Focus:** OS-level security, immutability, secure boot
- **Extended Docs:** 105K+ comprehensive guide
- **Related Skills:** `cilium-expert`, `argo-expert`

#### kanidm-expert
- **Description:** Kanidm identity management
- **Risk Level:** HIGH
- **Use Cases:** Identity and access management, OAuth2, LDAP
- **Key Topics:** User management, OAuth2, LDAP, RADIUS, authentication
- **Security Focus:** Identity security, MFA, password policies
- **Extended Docs:** 103K+ comprehensive guide
- **Related Skills:** `appsec-expert`, `encryption`

#### cloud-api-integration
- **Description:** Cloud provider API integration
- **Risk Level:** MEDIUM
- **Use Cases:** AWS/Azure/GCP integrations, cloud automation
- **Key Topics:** Cloud APIs, SDKs, authentication, service integration
- **Security Focus:** API key management, IAM, least privilege
- **Related Skills:** `api-expert`, `os-keychain`

#### cross-platform-builds
- **Description:** Cross-platform build systems
- **Risk Level:** MEDIUM
- **Use Cases:** Multi-platform releases, native builds
- **Key Topics:** Build matrices, cross-compilation, packaging
- **Security Focus:** Build reproducibility, supply chain security
- **Related Skills:** `cicd-expert`, `tauri`

---

### Desktop & Native

#### tauri
- **Description:** Tauri desktop application framework
- **Risk Level:** HIGH
- **Use Cases:** Cross-platform desktop apps with web frontends
- **Key Topics:** Tauri architecture, commands, events, IPC, window management
- **Security Focus:** IPC security, CSP, allowlist, command validation
- **Related Skills:** `rust`, `auto-update-systems`, `browser-automation`

#### browser-automation
- **Description:** Browser automation with Puppeteer/Playwright
- **Risk Level:** MEDIUM
- **Use Cases:** E2E testing, web scraping, automation
- **Key Topics:** Browser control, selectors, screenshots, PDF generation
- **Security Focus:** XSS in automation, secure credential handling
- **Related Skills:** `tauri`, `websocket`

#### auto-update-systems
- **Description:** Application auto-update mechanisms
- **Risk Level:** HIGH
- **Use Cases:** Desktop app updates, Electron/Tauri updaters
- **Key Topics:** Update channels, delta updates, signature verification
- **Security Focus:** Update verification, MITM prevention, secure channels
- **Related Skills:** `tauri`, `cross-platform-builds`

---

### Platform-Specific

#### macos-accessibility
- **Description:** macOS Accessibility API
- **Risk Level:** HIGH
- **Use Cases:** macOS automation, accessibility features
- **Key Topics:** Accessibility API, UI inspection, automation
- **Security Focus:** Permission model, privacy, TCC
- **Related Skills:** `applescript`, `windows-ui-automation`

#### windows-ui-automation
- **Description:** Windows UI Automation API
- **Risk Level:** HIGH
- **Use Cases:** Windows automation, accessibility
- **Key Topics:** UI Automation, control patterns, tree walking
- **Security Focus:** UAC, permissions, security contexts
- **Related Skills:** `macos-accessibility`, `linux-at-spi2`

#### linux-at-spi2
- **Description:** Linux AT-SPI2 accessibility
- **Risk Level:** HIGH
- **Use Cases:** Linux accessibility, automation
- **Key Topics:** AT-SPI2 protocol, DBus, accessibility tree
- **Security Focus:** DBus security, permission model
- **Related Skills:** `dbus`, `macos-accessibility`

#### applescript
- **Description:** macOS AppleScript automation
- **Risk Level:** MEDIUM
- **Use Cases:** macOS system automation, application scripting
- **Key Topics:** AppleScript syntax, tell blocks, application control
- **Security Focus:** Code injection, sandboxing limitations
- **Related Skills:** `macos-accessibility`

#### dbus
- **Description:** D-Bus inter-process communication (Linux)
- **Risk Level:** HIGH
- **Use Cases:** Linux IPC, system service communication
- **Key Topics:** D-Bus protocol, system bus, session bus, services
- **Security Focus:** D-Bus security policies, privilege escalation
- **Related Skills:** `linux-at-spi2`

---

### AI & Machine Learning

#### llm-integration
- **Description:** Large Language Model integration
- **Risk Level:** HIGH
- **Use Cases:** AI features, chatbots, code generation
- **Key Topics:** API integration, prompt engineering, token management
- **Security Focus:** Prompt injection, data privacy, API key security
- **Related Skills:** `prompt-engineering`, `mcp`

#### model-quantization
- **Description:** Model quantization for efficient inference
- **Risk Level:** MEDIUM
- **Use Cases:** Optimizing model size, edge deployment
- **Key Topics:** Quantization techniques, ONNX, TensorRT
- **Security Focus:** Model integrity, adversarial attacks
- **Related Skills:** `llm-integration`

#### prompt-engineering
- **Description:** Prompt engineering best practices
- **Risk Level:** MEDIUM
- **Use Cases:** LLM application development, AI UX
- **Key Topics:** Prompt design, few-shot learning, chain-of-thought
- **Security Focus:** Prompt injection prevention, output validation
- **Related Skills:** `llm-integration`

#### speech-to-text
- **Description:** Speech recognition integration
- **Risk Level:** MEDIUM
- **Use Cases:** Voice interfaces, transcription
- **Key Topics:** STT APIs, Web Speech API, accuracy optimization
- **Security Focus:** Audio data privacy, API security
- **Related Skills:** `text-to-speech`, `wake-word-detection`

#### text-to-speech
- **Description:** Text-to-speech synthesis
- **Risk Level:** LOW
- **Use Cases:** Voice output, accessibility features
- **Key Topics:** TTS APIs, Web Speech API, voice selection
- **Security Focus:** Content validation, injection prevention
- **Related Skills:** `speech-to-text`, `web-audio-api`

#### wake-word-detection
- **Description:** Wake word detection for voice assistants
- **Risk Level:** MEDIUM
- **Use Cases:** Voice-activated features, smart assistants
- **Key Topics:** Wake word models, audio processing, optimization
- **Security Focus:** False positive prevention, privacy
- **Related Skills:** `speech-to-text`, `web-audio-api`

---

### Multimedia

#### web-audio-api
- **Description:** Web Audio API for audio processing
- **Risk Level:** MEDIUM
- **Use Cases:** Audio playback, effects, synthesis, analysis
- **Key Topics:** Audio context, nodes, effects, synthesis
- **Security Focus:** Audio injection, resource management
- **Related Skills:** `speech-to-text`, `text-to-speech`

---

### Accessibility

#### accessibility-wcag
- **Description:** WCAG accessibility standards
- **Risk Level:** MEDIUM
- **Use Cases:** Accessible web applications, compliance
- **Key Topics:** WCAG 2.1, ARIA, semantic HTML, keyboard navigation
- **Security Focus:** Accessibility as security (inclusive security)
- **Related Skills:** `ui-ux-expert`, `macos-accessibility`

---

## Quick Reference Table

| Skill | Category | Risk | Primary Use Case |
|-------|----------|------|------------------|
| vue-nuxt | Frontend | MEDIUM | Vue 3/Nuxt 3 web apps |
| vue-nuxt-expert | Frontend | MEDIUM | Advanced Vue patterns |
| pinia | Frontend | LOW | Vue state management |
| tailwindcss | Frontend | LOW | Utility-first CSS |
| design-systems | Frontend | LOW | Component libraries |
| ui-ux-design | Frontend | LOW | UI/UX design |
| ui-ux-expert | Frontend | LOW | Advanced UI/UX |
| gsap | Frontend | LOW | Web animations |
| motion-design | Frontend | LOW | Motion design |
| threejs-tresjs | Frontend | MEDIUM | 3D graphics |
| webgl | Frontend | HIGH | Low-level 3D |
| glsl | Frontend | HIGH | Custom shaders |
| fastapi | Backend | MEDIUM | Python REST APIs |
| fastapi-expert | Backend | HIGH | Advanced FastAPI |
| api-expert | Backend | MEDIUM | General API design |
| rest-api-design | Backend | MEDIUM | RESTful APIs |
| graphql-expert | Backend | HIGH | GraphQL APIs |
| async-expert | Backend | MEDIUM | Advanced async |
| async-programming | Backend | MEDIUM | Basic async |
| celery-expert | Backend | MEDIUM | Task queues |
| rabbitmq-expert | Backend | MEDIUM | Message brokers |
| websocket | Backend | HIGH | Real-time comms |
| json-rpc | Backend | MEDIUM | RPC APIs |
| mcp | Backend | MEDIUM | AI tool integration |
| typescript | Language | LOW | TypeScript basics |
| typescript-expert | Language | LOW | Advanced TypeScript |
| javascript-expert | Language | MEDIUM | Advanced JavaScript |
| python | Language | MEDIUM | Python development |
| rust | Language | MEDIUM | Systems programming |
| database-design | Database | MEDIUM | Schema design |
| sqlite | Database | MEDIUM | SQLite databases |
| sqlcipher | Database | HIGH | Encrypted SQLite |
| surrealdb-expert | Database | MEDIUM | SurrealDB |
| graph-database-expert | Database | MEDIUM | Graph databases |
| appsec-expert | Security | HIGH | Application security |
| security-auditing | Security | HIGH | Security audits |
| encryption | Security | HIGH | Cryptography |
| os-keychain | Security | HIGH | Credential storage |
| sandboxing | Security | HIGH | Process isolation |
| devsecops-expert | Security | HIGH | Security automation |
| ci-cd | DevOps | MEDIUM | CI/CD basics |
| cicd-expert | DevOps | MEDIUM | Advanced CI/CD |
| argo-expert | DevOps | MEDIUM | Argo ecosystem |
| cilium-expert | DevOps | HIGH | K8s networking |
| harbor-expert | DevOps | MEDIUM | Container registry |
| talos-os-expert | DevOps | HIGH | Talos Linux |
| kanidm-expert | DevOps | HIGH | Identity management |
| cloud-api-integration | DevOps | MEDIUM | Cloud APIs |
| cross-platform-builds | DevOps | MEDIUM | Multi-platform builds |
| tauri | Desktop | HIGH | Desktop apps |
| browser-automation | Desktop | MEDIUM | Browser automation |
| auto-update-systems | Desktop | HIGH | App updates |
| macos-accessibility | Platform | HIGH | macOS automation |
| windows-ui-automation | Platform | HIGH | Windows automation |
| linux-at-spi2 | Platform | HIGH | Linux accessibility |
| applescript | Platform | MEDIUM | macOS scripting |
| dbus | Platform | HIGH | Linux IPC |
| llm-integration | AI/ML | HIGH | LLM integration |
| model-quantization | AI/ML | MEDIUM | Model optimization |
| prompt-engineering | AI/ML | MEDIUM | Prompt design |
| speech-to-text | AI/ML | MEDIUM | Speech recognition |
| text-to-speech | AI/ML | LOW | TTS synthesis |
| wake-word-detection | AI/ML | MEDIUM | Wake word detection |
| web-audio-api | Multimedia | MEDIUM | Audio processing |
| accessibility-wcag | Accessibility | MEDIUM | WCAG compliance |

## How to Use Skills

### 1. During Project Setup

Skills are automatically selected based on your project configuration. See [USAGE.md](./USAGE.md) for details.

### 2. Load Skills in Claude Code

**Via CLAUDE.md:**
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

### 3. Combine Skills

For complex features, combine multiple skills:

**Real-time API with Authentication:**
- `fastapi` - API framework
- `websocket` - Real-time communication
- `async-expert` - Concurrency patterns
- `appsec-expert` - Security
- `encryption` - Secure credentials

**Desktop App with Database:**
- `tauri` - Desktop framework
- `rust` - Backend language
- `typescript` - Frontend language
- `sqlite` or `sqlcipher` - Database
- `database-design` - Schema design
- `auto-update-systems` - Updates

### 4. Skill Selection by Project Type

**Web Application:**
```
Frontend: vue-nuxt, tailwindcss, pinia, typescript
Backend: fastapi, rest-api-design, async-expert, python
Database: database-design, sqlite
Security: appsec-expert, security-auditing
DevOps: ci-cd, devsecops-expert
```

**Desktop Application:**
```
Framework: tauri
Languages: rust, typescript
Platform: macos-accessibility, windows-ui-automation, linux-at-spi2
System: auto-update-systems, browser-automation
Security: appsec-expert, sandboxing, os-keychain
Build: cross-platform-builds
```

**API Service:**
```
Framework: fastapi-expert
API: rest-api-design, api-expert
Async: async-expert, celery-expert, rabbitmq-expert
Database: database-design, sqlite
Security: appsec-expert, encryption, devsecops-expert
DevOps: cicd-expert, harbor-expert
```

### 5. Create Custom Skills

See [USAGE.md - Creating Custom Skills](./USAGE.md#creating-custom-skills) for instructions on creating your own skills.

---

## Skill Maintenance

### Keeping Skills Updated

```bash
# Pull latest ai-templates
cd /path/to/ai-templates
git pull

# Copy updated skill to your project
cp -r skills/[skill-name] /path/to/your-project/skills/
```

### Contributing New Skills

See [Contributing](#contributing) in README.md for guidelines on adding new skills.

---

## Need More Information?

- **Main Documentation:** [README.md](./README.md)
- **Detailed Usage Guide:** [USAGE.md](./USAGE.md)
- **Claude Code Architecture:** [CLAUDE_CODE_ARCHITECTURE.md](./CLAUDE_CODE_ARCHITECTURE.md)

---

**Last Updated:** 2025-12-04
**Total Skills:** 67+
**Total Categories:** 11
