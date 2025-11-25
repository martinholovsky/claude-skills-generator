#!/bin/bash

# =============================================================================
# AI-Templates Repository Setup Script - Multi-Type Support
# =============================================================================
# Enhanced version that supports multiple project types
# Usage: ./setup-repo-multitype.sh [target-directory]
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

# =============================================================================
# Enhanced Setup Functions
# =============================================================================

setup_project_types() {
    print_section "Project Type (Multi-Select)"

    echo ""
    echo "What type(s) of project is this? (You can select multiple)"
    echo ""
    echo -e "  ${BOLD}1. Web Application${NC}"
    echo "     Frontend web app (React, Vue, Next.js, Nuxt, etc.)"
    echo ""
    echo -e "  ${BOLD}2. Backend/API${NC}"
    echo "     Server-side application or REST/GraphQL API"
    echo ""
    echo -e "  ${BOLD}3. Full-Stack${NC}"
    echo "     Combined frontend and backend (covers 1 + 2)"
    echo ""
    echo -e "  ${BOLD}4. Desktop Application${NC}"
    echo "     Cross-platform desktop app (Electron, Tauri)"
    echo ""
    echo -e "  ${BOLD}5. CLI Tool${NC}"
    echo "     Command-line interface application"
    echo ""
    echo -e "  ${BOLD}6. Library/Package${NC}"
    echo "     Reusable library for npm/PyPI/crates.io"
    echo ""

    # Multi-select logic
    echo "Enter your selections separated by spaces (e.g., '3 4' for Full-Stack + Desktop):"
    read -p "Choices: " PROJECT_TYPE_CHOICES

    # Parse selections
    PROJECT_TYPES=()
    HAS_WEB=false
    HAS_BACKEND=false
    HAS_FULLSTACK=false
    HAS_DESKTOP=false
    HAS_CLI=false
    HAS_LIBRARY=false

    for choice in $PROJECT_TYPE_CHOICES; do
        case $choice in
            1) HAS_WEB=true; PROJECT_TYPES+=("web") ;;
            2) HAS_BACKEND=true; PROJECT_TYPES+=("backend") ;;
            3) HAS_FULLSTACK=true; PROJECT_TYPES+=("fullstack") ;;
            4) HAS_DESKTOP=true; PROJECT_TYPES+=("desktop") ;;
            5) HAS_CLI=true; PROJECT_TYPES+=("cli") ;;
            6) HAS_LIBRARY=true; PROJECT_TYPES+=("library") ;;
        esac
    done

    # Validation
    if [ ${#PROJECT_TYPES[@]} -eq 0 ]; then
        print_warning "No valid selection, defaulting to Full-Stack"
        HAS_FULLSTACK=true
        PROJECT_TYPES+=("fullstack")
    fi

    # Show selected types
    echo ""
    echo -e "${GREEN}Selected project types:${NC}"
    for type in "${PROJECT_TYPES[@]}"; do
        echo "  ✓ $type"
    done
    echo ""
}

setup_languages() {
    print_section "Programming Languages"

    LANGUAGES=()

    # Determine languages based on project types
    if [ "$HAS_FULLSTACK" = true ] || [ "$HAS_WEB" = true ] || [ "$HAS_BACKEND" = true ]; then
        echo "Select language for web/backend:"
        echo "  1. TypeScript (frontend + backend)"
        echo "  2. TypeScript (frontend) + Python (backend)"
        echo "  3. Python only"
        read -p "Choice: " WEB_LANG_CHOICE

        case $WEB_LANG_CHOICE in
            1) LANGUAGES+=("typescript") ;;
            2) LANGUAGES+=("typescript" "python") ;;
            3) LANGUAGES+=("python") ;;
            *) LANGUAGES+=("typescript") ;;
        esac
    fi

    if [ "$HAS_DESKTOP" = true ]; then
        echo ""
        echo "Desktop apps typically use:"
        echo "  1. Tauri (Rust + Web frontend)"
        echo "  2. Electron (JavaScript/TypeScript)"
        read -p "Choice: " DESKTOP_CHOICE

        case $DESKTOP_CHOICE in
            1) LANGUAGES+=("rust"); DESKTOP_FRAMEWORK="tauri" ;;
            2) DESKTOP_FRAMEWORK="electron" ;;
        esac
    fi

    # Remove duplicates
    LANGUAGES=($(echo "${LANGUAGES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    echo ""
    echo -e "${GREEN}Languages to use:${NC}"
    for lang in "${LANGUAGES[@]}"; do
        echo "  ✓ $lang"
    done
    echo ""
}

generate_multi_type_skills() {
    local skills_dir="$TARGET_DIR/skills"
    local templates_dir="$SCRIPT_DIR/skills/skill-templates"

    mkdir -p "$skills_dir"

    echo ""
    print_info "Generating skills for all project types..."

    # Copy skill helper
    copy_skill() {
        local skill_name="$1"
        local source_dir="$templates_dir/$skill_name"

        if [ -d "$source_dir" ]; then
            mkdir -p "$skills_dir/$skill_name"
            cp "$source_dir/SKILL.md" "$skills_dir/$skill_name/"
            print_success "Added skills/$skill_name/"
        else
            print_warning "Skill template not found: $skill_name"
        fi
    }

    # Language skills
    for lang in "${LANGUAGES[@]}"; do
        copy_skill "$lang"
    done

    # Full-stack skills
    if [ "$HAS_FULLSTACK" = true ]; then
        copy_skill "vue-nuxt"
        copy_skill "fastapi"
        copy_skill "async-python"
        copy_skill "database"
        copy_skill "testing-js"
        copy_skill "testing-python"
    fi

    # Web-only skills
    if [ "$HAS_WEB" = true ] && [ "$HAS_FULLSTACK" != true ]; then
        copy_skill "vue-nuxt"
        copy_skill "testing-js"
    fi

    # Backend-only skills
    if [ "$HAS_BACKEND" = true ] && [ "$HAS_FULLSTACK" != true ]; then
        copy_skill "fastapi"
        copy_skill "async-python"
        copy_skill "database"
        copy_skill "testing-python"
    fi

    # Desktop skills
    if [ "$HAS_DESKTOP" = true ]; then
        if [ "$DESKTOP_FRAMEWORK" = "tauri" ]; then
            copy_skill "tauri"
            copy_skill "rust"
        else
            copy_skill "electron"
        fi

        # Platform-specific automation skills
        copy_skill "macos-ui-automation"
        copy_skill "windows-ui-automation"
        copy_skill "linux-ui-automation"
    fi

    # CLI skills
    if [ "$HAS_CLI" = true ]; then
        copy_skill "shell-automation"
    fi

    echo ""
}

generate_multi_type_claude_md() {
    cat > "$TARGET_DIR/CLAUDE.md" << 'EOF'
# {{PROJECT_NAME}} - Claude Code Instructions

## Project Overview

{{PROJECT_DESCRIPTION}}

This is a multi-type project including:
EOF

    # Add project types
    for type in "${PROJECT_TYPES[@]}"; do
        echo "- **$type**" >> "$TARGET_DIR/CLAUDE.md"
    done

    cat >> "$TARGET_DIR/CLAUDE.md" << 'EOF'

## Quick Reference - Task Skills

EOF

    # Add skill sections based on types
    if [ "$HAS_FULLSTACK" = true ] || [ "$HAS_WEB" = true ]; then
        cat >> "$TARGET_DIR/CLAUDE.md" << 'EOF'
**Frontend Features:**
```
MUST READ:
- skills/vue-nuxt/SKILL.md
- skills/typescript/SKILL.md
```

EOF
    fi

    if [ "$HAS_FULLSTACK" = true ] || [ "$HAS_BACKEND" = true ]; then
        cat >> "$TARGET_DIR/CLAUDE.md" << 'EOF'
**Backend Features:**
```
MUST READ:
- skills/fastapi/SKILL.md
- skills/python/SKILL.md
- skills/async-python/SKILL.md
```

EOF
    fi

    if [ "$HAS_DESKTOP" = true ]; then
        cat >> "$TARGET_DIR/CLAUDE.md" << 'EOF'
**Desktop Features:**
```
MUST READ:
- skills/tauri/SKILL.md
- skills/rust/SKILL.md
- skills/macos-ui-automation/SKILL.md (on macOS)
- skills/windows-ui-automation/SKILL.md (on Windows)
```

EOF
    fi

    # Add rest of template
    cat >> "$TARGET_DIR/CLAUDE.md" << 'EOF'
## Code Quality Requirements

### Security First
- Never introduce OWASP Top 10 vulnerabilities
- All file operations must respect sandboxing rules
- Credentials must use OS keychain, never plaintext

### Testing Requirements
- Write tests before implementation (TDD)
- Run all tests before committing
- Maintain test coverage above 80%

## Commands

```bash
# Install dependencies
{{INSTALL_COMMAND}}

# Run development
{{DEV_COMMAND}}

# Run tests
{{TEST_COMMAND}}

# Build production
{{BUILD_COMMAND}}
```

## Commit Guidelines

- Use conventional commit format
- Ensure all tests pass before committing
- Never commit sensitive credentials
EOF

    print_success "Generated multi-type CLAUDE.md"
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    print_header "AI-Templates Multi-Type Repository Setup"

    # Set target directory
    TARGET_DIR="${1:-$(pwd)}"

    if [ ! -d "$TARGET_DIR" ]; then
        read -p "Directory '$TARGET_DIR' doesn't exist. Create it? [Y/n]: " create
        if [[ ! "$create" =~ ^[Nn] ]]; then
            mkdir -p "$TARGET_DIR"
        else
            print_error "Setup cancelled."
            exit 1
        fi
    fi

    echo "Target directory: $TARGET_DIR"
    echo ""

    # Run setup
    setup_project_types
    setup_languages

    # Collect basic info
    read -p "Project name: " PROJECT_NAME
    read -p "Project description: " PROJECT_DESCRIPTION

    # Generate files
    generate_multi_type_skills
    generate_multi_type_claude_md

    # Copy other templates (README, .github, etc.)
    cp "$SCRIPT_DIR/project-docs/README.template.md" "$TARGET_DIR/README.md" 2>/dev/null || true
    mkdir -p "$TARGET_DIR/.claude/commands"
    cp -r "$SCRIPT_DIR/claude-code/dot-claude-example/"* "$TARGET_DIR/.claude/" 2>/dev/null || true

    echo ""
    print_success "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. cd $TARGET_DIR"
    echo "  2. Review and customize CLAUDE.md"
    echo "  3. Review skills/ directory"
    echo "  4. git init && git add . && git commit -m 'Initial commit'"
}

main "$@"
