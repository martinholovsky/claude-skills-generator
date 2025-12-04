#!/bin/bash

# =============================================================================
# Claude AI Skill Generator - Repository Setup Script
# =============================================================================
# Interactive script to guide through repository initialization for AI-assisted
# development projects.
#
# Usage: ./setup-repo.sh [target-directory]
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script directory (where templates are located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${CYAN}┌─ $1${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_recommendation() {
    echo -e "${GREEN}★ Recommended: $1${NC}"
}

# Prompt with default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local result

    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " result
        echo "${result:-$default}"
    else
        read -p "$prompt: " result
        echo "$result"
    fi
}

# Yes/No prompt with default
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local result

    if [ "$default" = "y" ]; then
        read -p "$prompt [Y/n]: " result
        result="${result:-y}"
    else
        read -p "$prompt [y/N]: " result
        result="${result:-n}"
    fi

    [[ "$result" =~ ^[Yy] ]]
}

# Multi-choice prompt
prompt_choice() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice

    echo ""
    echo -e "${BOLD}$prompt${NC}"
    echo ""

    for i in "${!options[@]}"; do
        echo "  $((i+1)). ${options[$i]}"
    done

    echo ""
    while true; do
        read -p "Enter choice (1-${#options[@]}): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "$choice"
            return
        fi
        echo "Invalid choice. Please enter a number between 1 and ${#options[@]}"
    done
}

# =============================================================================
# Setup Functions
# =============================================================================

setup_project_info() {
    print_section "Project Information"

    PROJECT_NAME=$(prompt_with_default "Project name" "$(basename "$TARGET_DIR")")
    PROJECT_DESCRIPTION=$(prompt_with_default "Project description (one line)" "")
    AUTHOR_NAME=$(prompt_with_default "Author name" "$(git config user.name 2>/dev/null || echo '')")
    AUTHOR_EMAIL=$(prompt_with_default "Author email" "$(git config user.email 2>/dev/null || echo '')")
    REPO_URL=$(prompt_with_default "Repository URL (GitHub)" "")
}

setup_project_type() {
    print_section "Project Type"

    echo ""
    echo "What type of project is this?"
    echo ""
    echo -e "  ${BOLD}1. Web Application${NC}"
    echo "     Frontend web app (React, Vue, Next.js, Nuxt, etc.)"
    echo "     ${GREEN}★ Best for: User-facing applications with rich UI${NC}"
    echo ""
    echo -e "  ${BOLD}2. Backend/API${NC}"
    echo "     Server-side application or REST/GraphQL API"
    echo "     ${GREEN}★ Best for: Services, microservices, data processing${NC}"
    echo ""
    echo -e "  ${BOLD}3. Full-Stack${NC}"
    echo "     Combined frontend and backend in monorepo"
    echo "     ${GREEN}★ Best for: Complete applications with both UI and server${NC}"
    echo ""
    echo -e "  ${BOLD}4. Desktop Application${NC}"
    echo "     Cross-platform desktop app (Electron, Tauri)"
    echo "     ${GREEN}★ Best for: Native-like apps with system access${NC}"
    echo ""
    echo -e "  ${BOLD}5. CLI Tool${NC}"
    echo "     Command-line interface application"
    echo "     ${GREEN}★ Best for: Developer tools, automation scripts${NC}"
    echo ""
    echo -e "  ${BOLD}6. Library/Package${NC}"
    echo "     Reusable library for npm/PyPI/crates.io"
    echo "     ${GREEN}★ Best for: Shared code, SDKs, utilities${NC}"
    echo ""

    read -p "Enter choice (1-6): " PROJECT_TYPE_CHOICE

    case $PROJECT_TYPE_CHOICE in
        1) PROJECT_TYPE="web" ;;
        2) PROJECT_TYPE="backend" ;;
        3) PROJECT_TYPE="fullstack" ;;
        4) PROJECT_TYPE="desktop" ;;
        5) PROJECT_TYPE="cli" ;;
        6) PROJECT_TYPE="library" ;;
        *) PROJECT_TYPE="web" ;;
    esac
}

setup_language() {
    print_section "Primary Programming Language"

    echo ""
    echo "Select primary programming language:"
    echo ""
    echo -e "  ${BOLD}1. TypeScript${NC}"
    echo "     Pros: Type safety, great tooling, large ecosystem"
    echo "     Cons: Build step required, learning curve for types"
    echo "     ${GREEN}★ Recommended for: Web apps, Node.js backends, most projects${NC}"
    echo ""
    echo -e "  ${BOLD}2. JavaScript${NC}"
    echo "     Pros: No build step, ubiquitous, easy to start"
    echo "     Cons: No type safety, runtime errors harder to catch"
    echo "     Best for: Quick prototypes, simple scripts"
    echo ""
    echo -e "  ${BOLD}3. Python${NC}"
    echo "     Pros: Readable, great for AI/ML, rapid development"
    echo "     Cons: Slower execution, GIL limitations"
    echo "     ${GREEN}★ Recommended for: AI/ML, data science, backend APIs${NC}"
    echo ""
    echo -e "  ${BOLD}4. Rust${NC}"
    echo "     Pros: Memory safety, performance, reliability"
    echo "     Cons: Steep learning curve, longer compile times"
    echo "     ${GREEN}★ Recommended for: Performance-critical, system-level code${NC}"
    echo ""
    echo -e "  ${BOLD}5. Go${NC}"
    echo "     Pros: Simple, fast compilation, great concurrency"
    echo "     Cons: Limited generics, verbose error handling"
    echo "     Best for: Microservices, CLI tools, DevOps"
    echo ""

    read -p "Enter choice (1-5): " LANGUAGE_CHOICE

    case $LANGUAGE_CHOICE in
        1) PRIMARY_LANGUAGE="typescript" ;;
        2) PRIMARY_LANGUAGE="javascript" ;;
        3) PRIMARY_LANGUAGE="python" ;;
        4) PRIMARY_LANGUAGE="rust" ;;
        5) PRIMARY_LANGUAGE="go" ;;
        *) PRIMARY_LANGUAGE="typescript" ;;
    esac
}

setup_framework() {
    print_section "Framework Selection"

    case $PROJECT_TYPE in
        "web"|"fullstack")
            echo ""
            echo "Select frontend framework:"
            echo ""
            echo -e "  ${BOLD}1. Vue/Nuxt${NC}"
            echo "     Pros: Gentle learning curve, great DX, flexible"
            echo "     Cons: Smaller ecosystem than React"
            echo "     ${GREEN}★ Recommended for: Moderate complexity apps, rapid development${NC}"
            echo ""
            echo -e "  ${BOLD}2. React/Next.js${NC}"
            echo "     Pros: Large ecosystem, many jobs, Meta backing"
            echo "     Cons: More boilerplate, needs more libraries"
            echo "     Best for: Large teams, enterprise apps"
            echo ""
            echo -e "  ${BOLD}3. Svelte/SvelteKit${NC}"
            echo "     Pros: Best performance, minimal code, no virtual DOM"
            echo "     Cons: Smaller ecosystem, fewer developers"
            echo "     Best for: Performance-critical UIs, simple apps"
            echo ""
            echo -e "  ${BOLD}4. Plain HTML/CSS/JS${NC}"
            echo "     Pros: No build step, maximum control"
            echo "     Cons: No reactivity, more manual work"
            echo "     Best for: Static sites, simple pages"
            echo ""

            read -p "Enter choice (1-4): " FE_FRAMEWORK_CHOICE

            case $FE_FRAMEWORK_CHOICE in
                1) FRONTEND_FRAMEWORK="nuxt" ;;
                2) FRONTEND_FRAMEWORK="nextjs" ;;
                3) FRONTEND_FRAMEWORK="sveltekit" ;;
                4) FRONTEND_FRAMEWORK="vanilla" ;;
                *) FRONTEND_FRAMEWORK="nuxt" ;;
            esac
            ;;
    esac

    case $PROJECT_TYPE in
        "backend"|"fullstack")
            echo ""
            echo "Select backend framework:"
            echo ""

            if [ "$PRIMARY_LANGUAGE" = "python" ]; then
                echo -e "  ${BOLD}1. FastAPI${NC}"
                echo "     Pros: Fast, auto-docs, async, type hints"
                echo "     Cons: Newer, less battle-tested than Django"
                echo "     ${GREEN}★ Recommended for: Modern APIs, async workloads${NC}"
                echo ""
                echo -e "  ${BOLD}2. Django${NC}"
                echo "     Pros: Batteries included, ORM, admin panel"
                echo "     Cons: Monolithic, can be heavy"
                echo "     Best for: Full-featured web apps, content sites"
                echo ""
                echo -e "  ${BOLD}3. Flask${NC}"
                echo "     Pros: Minimal, flexible, easy to learn"
                echo "     Cons: Manual setup for features, no async"
                echo "     Best for: Simple APIs, microservices"
                echo ""

                read -p "Enter choice (1-3): " BE_FRAMEWORK_CHOICE

                case $BE_FRAMEWORK_CHOICE in
                    1) BACKEND_FRAMEWORK="fastapi" ;;
                    2) BACKEND_FRAMEWORK="django" ;;
                    3) BACKEND_FRAMEWORK="flask" ;;
                    *) BACKEND_FRAMEWORK="fastapi" ;;
                esac
            else
                echo -e "  ${BOLD}1. Express${NC}"
                echo "     Pros: Minimal, huge ecosystem, flexible"
                echo "     Cons: No structure, manual setup needed"
                echo "     Best for: Simple APIs, experienced devs"
                echo ""
                echo -e "  ${BOLD}2. Fastify${NC}"
                echo "     Pros: Fast, schema-based, plugin system"
                echo "     Cons: Smaller ecosystem than Express"
                echo "     ${GREEN}★ Recommended for: Performance-critical APIs${NC}"
                echo ""
                echo -e "  ${BOLD}3. NestJS${NC}"
                echo "     Pros: Structured, TypeScript-first, scalable"
                echo "     Cons: More boilerplate, steeper learning curve"
                echo "     Best for: Large teams, enterprise apps"
                echo ""

                read -p "Enter choice (1-3): " BE_FRAMEWORK_CHOICE

                case $BE_FRAMEWORK_CHOICE in
                    1) BACKEND_FRAMEWORK="express" ;;
                    2) BACKEND_FRAMEWORK="fastify" ;;
                    3) BACKEND_FRAMEWORK="nestjs" ;;
                    *) BACKEND_FRAMEWORK="fastify" ;;
                esac
            fi
            ;;
    esac
}

setup_package_manager() {
    print_section "Package Manager"

    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        echo ""
        echo "Select Python package manager:"
        echo ""
        echo -e "  ${BOLD}1. uv${NC}"
        echo "     Pros: Extremely fast, Rust-based, drop-in pip replacement"
        echo "     Cons: Newer tool, still maturing"
        echo "     ${GREEN}★ Recommended: Best performance, modern approach${NC}"
        echo ""
        echo -e "  ${BOLD}2. Poetry${NC}"
        echo "     Pros: Lock files, virtual envs, dependency resolution"
        echo "     Cons: Slower than pip, opinionated"
        echo "     Best for: Libraries, strict dependency management"
        echo ""
        echo -e "  ${BOLD}3. pip + venv${NC}"
        echo "     Pros: Built-in, universal, well-documented"
        echo "     Cons: No lock file, manual virtual env"
        echo "     Best for: Simple projects, compatibility"
        echo ""

        read -p "Enter choice (1-3): " PKG_CHOICE

        case $PKG_CHOICE in
            1) PACKAGE_MANAGER="uv" ;;
            2) PACKAGE_MANAGER="poetry" ;;
            3) PACKAGE_MANAGER="pip" ;;
            *) PACKAGE_MANAGER="uv" ;;
        esac
    else
        echo ""
        echo "Select JavaScript/TypeScript package manager:"
        echo ""
        echo -e "  ${BOLD}1. pnpm${NC}"
        echo "     Pros: Fast, disk efficient, strict by default"
        echo "     Cons: Some compatibility issues with old packages"
        echo "     ${GREEN}★ Recommended: Best performance and disk usage${NC}"
        echo ""
        echo -e "  ${BOLD}2. npm${NC}"
        echo "     Pros: Built-in with Node, universal compatibility"
        echo "     Cons: Slower, uses more disk space"
        echo "     Best for: Maximum compatibility"
        echo ""
        echo -e "  ${BOLD}3. yarn${NC}"
        echo "     Pros: Fast, good DX, Plug'n'Play option"
        echo "     Cons: Complex config, two major versions"
        echo "     Best for: Existing yarn projects"
        echo ""
        echo -e "  ${BOLD}4. bun${NC}"
        echo "     Pros: Extremely fast, all-in-one runtime"
        echo "     Cons: Newer, not 100% Node compatible"
        echo "     Best for: Performance-critical, new projects"
        echo ""

        read -p "Enter choice (1-4): " PKG_CHOICE

        case $PKG_CHOICE in
            1) PACKAGE_MANAGER="pnpm" ;;
            2) PACKAGE_MANAGER="npm" ;;
            3) PACKAGE_MANAGER="yarn" ;;
            4) PACKAGE_MANAGER="bun" ;;
            *) PACKAGE_MANAGER="pnpm" ;;
        esac
    fi
}

setup_testing() {
    print_section "Testing Framework"

    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        echo ""
        echo "Select testing framework:"
        echo ""
        echo -e "  ${BOLD}1. pytest${NC}"
        echo "     Pros: Powerful fixtures, great plugins, readable"
        echo "     Cons: Not in standard library"
        echo "     ${GREEN}★ Recommended: Industry standard for Python testing${NC}"
        echo ""
        echo -e "  ${BOLD}2. unittest${NC}"
        echo "     Pros: Built-in, no dependencies"
        echo "     Cons: Verbose, fewer features"
        echo "     Best for: Minimal dependencies requirement"
        echo ""

        read -p "Enter choice (1-2): " TEST_CHOICE

        case $TEST_CHOICE in
            1) TEST_FRAMEWORK="pytest" ;;
            2) TEST_FRAMEWORK="unittest" ;;
            *) TEST_FRAMEWORK="pytest" ;;
        esac
    else
        echo ""
        echo "Select testing framework:"
        echo ""
        echo -e "  ${BOLD}1. Vitest${NC}"
        echo "     Pros: Fast, Vite-native, Jest-compatible API"
        echo "     Cons: Newer, smaller ecosystem"
        echo "     ${GREEN}★ Recommended: Best for Vite/modern projects${NC}"
        echo ""
        echo -e "  ${BOLD}2. Jest${NC}"
        echo "     Pros: Feature-rich, large ecosystem, snapshots"
        echo "     Cons: Slower, heavier"
        echo "     Best for: React projects, existing Jest setups"
        echo ""
        echo -e "  ${BOLD}3. Playwright${NC}"
        echo "     Pros: Cross-browser E2E, great DX, auto-wait"
        echo "     Cons: Heavier for unit tests"
        echo "     Best for: E2E testing, browser automation"
        echo ""

        read -p "Enter choice (1-3): " TEST_CHOICE

        case $TEST_CHOICE in
            1) TEST_FRAMEWORK="vitest" ;;
            2) TEST_FRAMEWORK="jest" ;;
            3) TEST_FRAMEWORK="playwright" ;;
            *) TEST_FRAMEWORK="vitest" ;;
        esac
    fi
}

setup_license() {
    print_section "License Selection"

    echo ""
    echo "Select a license for your project:"
    echo ""
    echo -e "  ${BOLD}1. MIT${NC}"
    echo "     Very permissive, allows commercial use"
    echo "     ${GREEN}★ Recommended for: Open source libraries, maximum adoption${NC}"
    echo ""
    echo -e "  ${BOLD}2. Apache 2.0${NC}"
    echo "     Permissive with patent grant"
    echo "     Best for: Projects with potential patent concerns"
    echo ""
    echo -e "  ${BOLD}3. GPL 3.0${NC}"
    echo "     Copyleft, derivatives must be GPL"
    echo "     Best for: Ensuring code stays open source"
    echo ""
    echo -e "  ${BOLD}4. BSD 3-Clause${NC}"
    echo "     Similar to MIT, explicit no-endorsement clause"
    echo "     Best for: Academic projects"
    echo ""
    echo -e "  ${BOLD}5. Proprietary/None${NC}"
    echo "     All rights reserved"
    echo "     Best for: Commercial, closed-source projects"
    echo ""

    read -p "Enter choice (1-5): " LICENSE_CHOICE

    case $LICENSE_CHOICE in
        1) LICENSE_TYPE="MIT" ;;
        2) LICENSE_TYPE="Apache-2.0" ;;
        3) LICENSE_TYPE="GPL-3.0" ;;
        4) LICENSE_TYPE="BSD-3-Clause" ;;
        5) LICENSE_TYPE="Proprietary" ;;
        *) LICENSE_TYPE="MIT" ;;
    esac
}

setup_ai_features() {
    print_section "AI-Assisted Development Features"

    echo ""
    echo "This project will be set up for Claude Code AI-assisted development."
    echo ""

    if prompt_yes_no "Include CLAUDE.md with project instructions?" "y"; then
        INCLUDE_CLAUDE_MD=true
    else
        INCLUDE_CLAUDE_MD=false
    fi

    if prompt_yes_no "Include .claude/ directory with slash commands?" "y"; then
        INCLUDE_CLAUDE_COMMANDS=true
    else
        INCLUDE_CLAUDE_COMMANDS=false
    fi

    if prompt_yes_no "Include skill templates for domain-specific knowledge?" "n"; then
        INCLUDE_SKILLS=true
    else
        INCLUDE_SKILLS=false
    fi

    echo ""
    echo "Security level for AI coding:"
    echo ""
    echo -e "  ${BOLD}1. Standard${NC}"
    echo "     Basic input validation and secure defaults"
    echo "     ${GREEN}★ Recommended for: Most projects${NC}"
    echo ""
    echo -e "  ${BOLD}2. High Security${NC}"
    echo "     Strict validation, encryption, audit logging"
    echo "     Best for: Financial, healthcare, sensitive data"
    echo ""
    echo -e "  ${BOLD}3. Maximum Security${NC}"
    echo "     Everything in High + additional constraints"
    echo "     Best for: Critical infrastructure, government"
    echo ""

    read -p "Enter choice (1-3): " SECURITY_CHOICE

    case $SECURITY_CHOICE in
        1) SECURITY_LEVEL="standard" ;;
        2) SECURITY_LEVEL="high" ;;
        3) SECURITY_LEVEL="maximum" ;;
        *) SECURITY_LEVEL="standard" ;;
    esac
}

setup_github_features() {
    print_section "GitHub Features"

    if prompt_yes_no "Include GitHub Actions CI workflow?" "y"; then
        INCLUDE_CI=true
    else
        INCLUDE_CI=false
    fi

    if prompt_yes_no "Include PR and Issue templates?" "y"; then
        INCLUDE_GITHUB_TEMPLATES=true
    else
        INCLUDE_GITHUB_TEMPLATES=false
    fi

    if prompt_yes_no "Include CONTRIBUTING.md?" "y"; then
        INCLUDE_CONTRIBUTING=true
    else
        INCLUDE_CONTRIBUTING=false
    fi

    if prompt_yes_no "Include CODE_OF_CONDUCT.md?" "y"; then
        INCLUDE_CODE_OF_CONDUCT=true
    else
        INCLUDE_CODE_OF_CONDUCT=false
    fi

    if prompt_yes_no "Include SECURITY.md policy?" "y"; then
        INCLUDE_SECURITY=true
        SECURITY_EMAIL=$(prompt_with_default "Security contact email" "$AUTHOR_EMAIL")
    else
        INCLUDE_SECURITY=false
    fi
}

# =============================================================================
# Template Generation Functions
# =============================================================================

generate_files() {
    print_header "Generating Project Files"

    echo "Creating directory structure..."
    mkdir -p "$TARGET_DIR"/{src,tests,docs}
    mkdir -p "$TARGET_DIR/.github/workflows"
    mkdir -p "$TARGET_DIR/.github/ISSUE_TEMPLATE"

    # Generate CLAUDE.md
    if [ "$INCLUDE_CLAUDE_MD" = true ]; then
        generate_claude_md
        print_success "Created CLAUDE.md"
    fi

    # Generate .claude/ directory
    if [ "$INCLUDE_CLAUDE_COMMANDS" = true ]; then
        generate_claude_commands
        print_success "Created .claude/ directory with commands"
    fi

    # Generate README
    generate_readme
    print_success "Created README.md"

    # Generate CONTRIBUTING
    if [ "$INCLUDE_CONTRIBUTING" = true ]; then
        generate_contributing
        print_success "Created CONTRIBUTING.md"
    fi

    # Generate SECURITY
    if [ "$INCLUDE_SECURITY" = true ]; then
        generate_security
        print_success "Created SECURITY.md"
    fi

    # Generate CODE_OF_CONDUCT
    if [ "$INCLUDE_CODE_OF_CONDUCT" = true ]; then
        generate_code_of_conduct
        print_success "Created CODE_OF_CONDUCT.md"
    fi

    # Generate GitHub templates
    if [ "$INCLUDE_GITHUB_TEMPLATES" = true ]; then
        generate_github_templates
        print_success "Created GitHub issue and PR templates"
    fi

    # Generate CI workflow
    if [ "$INCLUDE_CI" = true ]; then
        generate_ci_workflow
        print_success "Created GitHub Actions CI workflow"
    fi

    # Generate .gitignore
    generate_gitignore
    print_success "Created .gitignore"

    # Generate LICENSE
    generate_license
    print_success "Created LICENSE"

    # Generate skills based on tech stack
    if [ "$INCLUDE_SKILLS" = true ]; then
        echo ""
        echo "Generating skills based on your tech stack..."
        generate_skills
    fi
}

generate_claude_md() {
    local security_section=""

    if [ "$SECURITY_LEVEL" = "high" ] || [ "$SECURITY_LEVEL" = "maximum" ]; then
        security_section="
## Security Requirements

### Mandatory Security Practices

- All user inputs MUST be validated
- Credentials MUST use OS keychain, never plaintext
- SQL queries MUST use parameterized statements
- File operations MUST be sandboxed
- All external data MUST be sanitized

### Security Review Required For

- Authentication/Authorization changes
- Encryption/Cryptography implementations
- External API integrations
- Database schema changes
"
    fi

    cat > "$TARGET_DIR/CLAUDE.md" << EOF
# ${PROJECT_NAME} - Claude Code Instructions

## Project Overview

${PROJECT_DESCRIPTION}

**Primary Language**: ${PRIMARY_LANGUAGE}
**Project Type**: ${PROJECT_TYPE}

## Architecture

- **Framework**: ${FRONTEND_FRAMEWORK:-N/A} (Frontend) / ${BACKEND_FRAMEWORK:-N/A} (Backend)
- **Package Manager**: ${PACKAGE_MANAGER}
- **Testing**: ${TEST_FRAMEWORK}

## Development Commands

### Setup

\`\`\`bash
# Install dependencies
$(get_install_command)

# Start development server
$(get_dev_command)
\`\`\`

### Testing

\`\`\`bash
# Run tests
$(get_test_command)

# Run linter
$(get_lint_command)
\`\`\`

### Build

\`\`\`bash
$(get_build_command)
\`\`\`

## Code Quality Requirements

### General Guidelines

- Write self-documenting code
- Follow existing code patterns
- Keep functions focused and small
- Handle errors appropriately
- No over-engineering - solve the current problem

### Testing Requirements

When user asks to "run tests", execute:
1. Unit tests
2. Build verification
3. Type checking (if applicable)
4. Linting
${security_section}

## Commit Guidelines

Use conventional commit format:
- \`feat:\` New features
- \`fix:\` Bug fixes
- \`docs:\` Documentation
- \`refactor:\` Code refactoring
- \`test:\` Adding tests
- \`chore:\` Maintenance

## Questions?

If unclear about implementation approach, ask for clarification before proceeding.
EOF
}

generate_claude_commands() {
    mkdir -p "$TARGET_DIR/.claude/commands"

    # Create settings.json
    cat > "$TARGET_DIR/.claude/settings.json" << 'EOF'
{
  "hooks": {
    "pre-tool-use": [],
    "post-tool-use": []
  }
}
EOF

    # Create a sample command
    cat > "$TARGET_DIR/.claude/commands/run-tests.md" << EOF
# Run Tests Command

Execute the full test suite for this project.

## Steps

1. Run unit tests
2. Run linter
3. Check types (if applicable)
4. Report results

## Commands

\`\`\`bash
$(get_test_command)
$(get_lint_command)
\`\`\`
EOF
}

generate_readme() {
    cat > "$TARGET_DIR/README.md" << EOF
# ${PROJECT_NAME}

${PROJECT_DESCRIPTION}

## Quick Start

### Prerequisites

$(get_prerequisites)

### Installation

\`\`\`bash
$(get_install_command)
\`\`\`

### Development

\`\`\`bash
$(get_dev_command)
\`\`\`

## Testing

\`\`\`bash
$(get_test_command)
\`\`\`

## Documentation

- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)

## AI-Assisted Development

This project uses Claude Code for AI-assisted development. See [CLAUDE.md](./CLAUDE.md) for guidelines.

## License

This project is licensed under the ${LICENSE_TYPE} License - see the [LICENSE](./LICENSE) file for details.

---

Built with AI assistance
EOF
}

generate_contributing() {
    sed -e "s/{{PROJECT_NAME}}/${PROJECT_NAME}/g" \
        -e "s/{{REPO_NAME}}/$(basename "$TARGET_DIR")/g" \
        -e "s/{{DEV_SETUP_COMMANDS}}/$(get_install_command | sed 's/[&/\]/\\&/g')/g" \
        -e "s/{{TEST_COMMANDS}}/$(get_test_command | sed 's/[&/\]/\\&/g')/g" \
        -e "s/{{LINT_COMMANDS}}/$(get_lint_command | sed 's/[&/\]/\\&/g')/g" \
        -e "s/{{PRIMARY_LANGUAGE}}/${PRIMARY_LANGUAGE}/g" \
        -e "s/{{MIN_REVIEWERS}}/1/g" \
        -e "s/{{SECURITY_EMAIL}}/${SECURITY_EMAIL:-security@example.com}/g" \
        "$SCRIPT_DIR/project-docs/CONTRIBUTING.template.md" > "$TARGET_DIR/CONTRIBUTING.md" 2>/dev/null || \
    cat > "$TARGET_DIR/CONTRIBUTING.md" << EOF
# Contributing to ${PROJECT_NAME}

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Install dependencies: \`$(get_install_command)\`
4. Create a feature branch

## Development

- Run tests: \`$(get_test_command)\`
- Run linter: \`$(get_lint_command)\`

## Pull Requests

- Follow conventional commit format
- Include tests for new features
- Update documentation as needed

## Questions?

Open an issue for questions or concerns.
EOF
}

generate_security() {
    cat > "$TARGET_DIR/SECURITY.md" << EOF
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities via email to: ${SECURITY_EMAIL}

Do NOT create public issues for security vulnerabilities.

### What to Include

- Type of vulnerability
- Steps to reproduce
- Impact assessment

### Response Time

- Initial response: Within 48 hours
- Status update: Within 7 days

## Security Best Practices

- Never commit secrets
- Validate all inputs
- Use parameterized queries
- Keep dependencies updated

Thank you for helping keep ${PROJECT_NAME} secure!
EOF
}

generate_code_of_conduct() {
    sed -e "s/{{CONDUCT_EMAIL}}/${AUTHOR_EMAIL}/g" \
        "$SCRIPT_DIR/project-docs/CODE_OF_CONDUCT.template.md" > "$TARGET_DIR/CODE_OF_CONDUCT.md" 2>/dev/null || \
    cat > "$TARGET_DIR/CODE_OF_CONDUCT.md" << EOF
# Code of Conduct

## Our Pledge

We pledge to make participation in our community a harassment-free experience for everyone.

## Standards

Be respectful, give constructive feedback, and focus on what's best for the community.

## Enforcement

Report unacceptable behavior to: ${AUTHOR_EMAIL}

---

Adapted from the Contributor Covenant.
EOF
}

generate_github_templates() {
    # PR template
    cp "$SCRIPT_DIR/github/PULL_REQUEST_TEMPLATE.md" "$TARGET_DIR/.github/PULL_REQUEST_TEMPLATE.md" 2>/dev/null || \
    cat > "$TARGET_DIR/.github/PULL_REQUEST_TEMPLATE.md" << 'EOF'
## Summary

<!-- Brief description of changes -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation

## Testing

- [ ] Tests pass
- [ ] Manual testing done

## Checklist

- [ ] Code follows project standards
- [ ] Documentation updated
- [ ] Tests added/updated
EOF

    # Issue templates
    mkdir -p "$TARGET_DIR/.github/ISSUE_TEMPLATE"

    cp "$SCRIPT_DIR/github/ISSUE_TEMPLATE/bug_report.md" "$TARGET_DIR/.github/ISSUE_TEMPLATE/" 2>/dev/null || true
    cp "$SCRIPT_DIR/github/ISSUE_TEMPLATE/feature_request.md" "$TARGET_DIR/.github/ISSUE_TEMPLATE/" 2>/dev/null || true
}

generate_ci_workflow() {
    local install_cmd=$(get_install_command)
    local test_cmd=$(get_test_command)
    local lint_cmd=$(get_lint_command)
    local build_cmd=$(get_build_command)

    cat > "$TARGET_DIR/.github/workflows/ci.yml" << EOF
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

$(get_ci_setup_steps)

      - name: Install dependencies
        run: ${install_cmd}

      - name: Run linter
        run: ${lint_cmd}

      - name: Run tests
        run: ${test_cmd}

      - name: Build
        run: ${build_cmd}
EOF
}

generate_gitignore() {
    cat > "$TARGET_DIR/.gitignore" << EOF
# Dependencies
node_modules/
__pycache__/
*.pyc
.venv/
venv/
target/

# Build outputs
dist/
build/
.nuxt/
.next/
.output/

# IDE
.idea/
.vscode/
*.swp

# Environment
.env
.env.local
.env.*.local

# Testing
coverage/
.pytest_cache/
.coverage

# OS
.DS_Store
Thumbs.db

# Logs
*.log
npm-debug.log*

# Misc
*.bak
*.tmp
EOF
}

generate_skills() {
    local skills_dir="$TARGET_DIR/skills"
    local templates_dir="$SCRIPT_DIR/skills/skill-templates"
    local current_date=$(date +%Y-%m-%d)

    mkdir -p "$skills_dir"

    # Helper to copy and customize skill
    copy_skill() {
        local skill_name="$1"
        local source_dir="$templates_dir/$skill_name"

        if [ -d "$source_dir" ]; then
            mkdir -p "$skills_dir/$skill_name"
            sed -e "s/{{PROJECT_NAME}}/${PROJECT_NAME}/g" \
                -e "s/{{PROJECT_NAME_LOWER}}/$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')/g" \
                -e "s/{{DATE}}/${current_date}/g" \
                "$source_dir/SKILL.md" > "$skills_dir/$skill_name/SKILL.md"
            print_success "Created skills/$skill_name/"
        fi
    }

    # Generate skills based on language
    case $PRIMARY_LANGUAGE in
        "python")
            copy_skill "python"
            ;;
        "typescript"|"javascript")
            copy_skill "typescript"
            ;;
    esac

    # Generate skills based on backend framework
    case $BACKEND_FRAMEWORK in
        "fastapi")
            copy_skill "fastapi"
            ;;
    esac

    # Generate skills based on frontend framework
    case $FRONTEND_FRAMEWORK in
        "nuxt"|"vue")
            copy_skill "vue-nuxt"
            ;;
    esac

    # Generate testing skills
    case $TEST_FRAMEWORK in
        "pytest")
            copy_skill "testing-python"
            ;;
        "vitest"|"jest")
            copy_skill "testing-js"
            ;;
    esac

    # Create skills README
    cat > "$skills_dir/README.md" << EOF
# Skills Directory

Domain-specific AI knowledge for ${PROJECT_NAME}.

## Available Skills

$(ls -1 "$skills_dir" 2>/dev/null | grep -v README.md | while read skill; do
    echo "- **$skill** - See \`$skill/SKILL.md\`"
done)

## Usage

Claude Code will load these skills when implementing related features.
Reference skills in CLAUDE.md to ensure they are used.

## Adding New Skills

1. Create a new directory: \`skills/skill-name/\`
2. Add \`SKILL.md\` with patterns and best practices
3. Reference in CLAUDE.md
EOF
}

# Determine which skills will be generated
get_skills_list() {
    local skills=""

    case $PRIMARY_LANGUAGE in
        "python") skills="python" ;;
        "typescript"|"javascript") skills="typescript" ;;
    esac

    case $BACKEND_FRAMEWORK in
        "fastapi") skills="$skills fastapi" ;;
    esac

    case $FRONTEND_FRAMEWORK in
        "nuxt"|"vue") skills="$skills vue-nuxt" ;;
    esac

    case $TEST_FRAMEWORK in
        "pytest") skills="$skills testing-python" ;;
        "vitest"|"jest") skills="$skills testing-js" ;;
    esac

    echo "$skills"
}

generate_license() {
    local year=$(date +%Y)

    case $LICENSE_TYPE in
        "MIT")
            cat > "$TARGET_DIR/LICENSE" << EOF
MIT License

Copyright (c) ${year} ${AUTHOR_NAME}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
            ;;
        "Apache-2.0")
            cat > "$TARGET_DIR/LICENSE" << EOF
Apache License 2.0

Copyright ${year} ${AUTHOR_NAME}

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
EOF
            ;;
        *)
            cat > "$TARGET_DIR/LICENSE" << EOF
Copyright (c) ${year} ${AUTHOR_NAME}
All Rights Reserved.
EOF
            ;;
    esac
}

# =============================================================================
# Helper Functions for Commands
# =============================================================================

get_install_command() {
    case $PACKAGE_MANAGER in
        "pnpm") echo "pnpm install" ;;
        "npm") echo "npm install" ;;
        "yarn") echo "yarn install" ;;
        "bun") echo "bun install" ;;
        "uv") echo "uv pip install -e ." ;;
        "poetry") echo "poetry install" ;;
        "pip") echo "pip install -e ." ;;
        *) echo "npm install" ;;
    esac
}

get_dev_command() {
    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        case $BACKEND_FRAMEWORK in
            "fastapi") echo "uvicorn main:app --reload" ;;
            "django") echo "python manage.py runserver" ;;
            "flask") echo "flask run --reload" ;;
            *) echo "python main.py" ;;
        esac
    else
        case $PACKAGE_MANAGER in
            "pnpm") echo "pnpm dev" ;;
            "npm") echo "npm run dev" ;;
            "yarn") echo "yarn dev" ;;
            "bun") echo "bun run dev" ;;
            *) echo "npm run dev" ;;
        esac
    fi
}

get_test_command() {
    case $TEST_FRAMEWORK in
        "vitest") echo "npx vitest run" ;;
        "jest") echo "npx jest" ;;
        "playwright") echo "npx playwright test" ;;
        "pytest") echo "pytest" ;;
        "unittest") echo "python -m unittest discover" ;;
        *) echo "npm test" ;;
    esac
}

get_lint_command() {
    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        echo "ruff check . && black --check ."
    else
        echo "npx eslint . && npx prettier --check ."
    fi
}

get_build_command() {
    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        echo "python -m build"
    else
        case $PACKAGE_MANAGER in
            "pnpm") echo "pnpm build" ;;
            "npm") echo "npm run build" ;;
            "yarn") echo "yarn build" ;;
            "bun") echo "bun run build" ;;
            *) echo "npm run build" ;;
        esac
    fi
}

get_prerequisites() {
    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        echo "- Python 3.10+"
        echo "- ${PACKAGE_MANAGER}"
    else
        echo "- Node.js 18+"
        echo "- ${PACKAGE_MANAGER}"
    fi
}

get_ci_setup_steps() {
    if [ "$PRIMARY_LANGUAGE" = "python" ]; then
        cat << 'EOF'
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
EOF
    else
        cat << 'EOF'
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
EOF

        if [ "$PACKAGE_MANAGER" = "pnpm" ]; then
            cat << 'EOF'

      - uses: pnpm/action-setup@v2
        with:
          version: 8
EOF
        fi
    fi
}

# =============================================================================
# Summary Display
# =============================================================================

display_summary() {
    print_header "Setup Summary"

    echo -e "${BOLD}Project Configuration:${NC}"
    echo "  Name:             $PROJECT_NAME"
    echo "  Type:             $PROJECT_TYPE"
    echo "  Language:         $PRIMARY_LANGUAGE"
    echo "  Package Manager:  $PACKAGE_MANAGER"
    echo "  Testing:          $TEST_FRAMEWORK"
    echo "  License:          $LICENSE_TYPE"
    echo ""

    if [ -n "$FRONTEND_FRAMEWORK" ]; then
        echo "  Frontend:         $FRONTEND_FRAMEWORK"
    fi
    if [ -n "$BACKEND_FRAMEWORK" ]; then
        echo "  Backend:          $BACKEND_FRAMEWORK"
    fi
    echo ""

    echo -e "${BOLD}Files to Create:${NC}"
    echo "  ✓ README.md"
    echo "  ✓ LICENSE"
    echo "  ✓ .gitignore"
    [ "$INCLUDE_CLAUDE_MD" = true ] && echo "  ✓ CLAUDE.md"
    [ "$INCLUDE_CLAUDE_COMMANDS" = true ] && echo "  ✓ .claude/ directory"
    [ "$INCLUDE_CONTRIBUTING" = true ] && echo "  ✓ CONTRIBUTING.md"
    [ "$INCLUDE_SECURITY" = true ] && echo "  ✓ SECURITY.md"
    [ "$INCLUDE_CODE_OF_CONDUCT" = true ] && echo "  ✓ CODE_OF_CONDUCT.md"
    [ "$INCLUDE_CI" = true ] && echo "  ✓ .github/workflows/ci.yml"
    [ "$INCLUDE_GITHUB_TEMPLATES" = true ] && echo "  ✓ GitHub issue/PR templates"
    echo ""

    # Show skills to be generated
    if [ "$INCLUDE_SKILLS" = true ]; then
        echo -e "${BOLD}Skills to Generate (based on tech stack):${NC}"
        local skills_list=$(get_skills_list)
        for skill in $skills_list; do
            echo "  ✓ skills/$skill/"
        done
        echo ""
    fi
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    print_header "AI-Templates Repository Setup"

    echo "This script will guide you through setting up a new repository with"
    echo "AI-assisted development support (Claude Code) and best practices."
    echo ""

    # Set target directory
    TARGET_DIR="${1:-$(pwd)}"

    if [ ! -d "$TARGET_DIR" ]; then
        if prompt_yes_no "Directory '$TARGET_DIR' doesn't exist. Create it?" "y"; then
            mkdir -p "$TARGET_DIR"
        else
            print_error "Setup cancelled."
            exit 1
        fi
    fi

    echo "Target directory: $TARGET_DIR"
    echo ""

    # Run setup steps
    setup_project_info
    setup_project_type
    setup_language
    setup_framework
    setup_package_manager
    setup_testing
    setup_license
    setup_ai_features
    setup_github_features

    # Display summary
    display_summary

    # Confirm and generate
    if prompt_yes_no "Proceed with generating files?" "y"; then
        generate_files

        print_header "Setup Complete! 🎉"

        echo "Your project has been initialized at: $TARGET_DIR"
        echo ""
        echo "Next steps:"
        echo "  1. cd $TARGET_DIR"
        echo "  2. git init"
        echo "  3. $(get_install_command)"
        echo "  4. Review and customize the generated files"
        echo "  5. Start developing with Claude Code!"
        echo ""
        print_info "Tip: Run 'claude' in your project directory to start AI-assisted development."
    else
        print_warning "Setup cancelled."
    fi
}

# Run main
main "$@"
