# {{PROJECT_NAME}} - Claude Code Instructions

## Project Overview

{{PROJECT_DESCRIPTION}}

This file contains mandatory instructions for Claude Code when working on this project.

## Code Quality Requirements

### Security First

- Never introduce OWASP Top 10 vulnerabilities
- All file operations must respect sandboxing rules
- Credentials must use OS keychain, never plaintext
- All user inputs must be validated

### Architecture

{{ARCHITECTURE_DESCRIPTION}}

## Key Documentation

- **README**: `README.md` - Project overview
- **Contributing**: `CONTRIBUTING.md` - How to contribute
- **Architecture**: `CLAUDE_CODE_ARCHITECTURE.md` - Claude Code integration guide

## Slash Commands

Use these commands for common implementation tasks (customize as needed):
- `/implement-feature` - Load feature implementation skills
- `/run-tests` - Execute test suite

## Commit Guidelines

- Use conventional commit format
- Ensure all tests pass before committing
- Never commit sensitive credentials

## Dependency Management Rules

### CRITICAL: Never Guess Package Versions

**STOP! Before updating ANY dependency, you MUST:**

1. **Check actual latest version**:
   ```bash
   npm view <package> version
   # or for Python
   pip index versions <package>
   ```

2. **Read migration guide** for major version updates
3. **Update one package at a time** - never bulk update

4. **Run verification after each update**:
   ```bash
   {{INSTALL_COMMAND}} && {{DEV_COMMAND}} && {{BUILD_COMMAND}} && {{TEST_COMMAND}}
   ```

### Version Specification Rules

```json
// Use conservative ranges for production dependencies
"package": "~1.0.0"          // Patch only

// Caret (^) only for dev tools
"eslint": "^9.0.0"           // Minor + patch OK
```

## Testing Requirements

### When User Asks to "Run Tests"

When the user asks to run tests, **execute ALL of these automatically**:

```bash
{{TEST_COMMANDS}}
```

**Report results for each step.** If any step fails, attempt to fix the issue before proceeding.

### After Any Code Change

Run these commands and fix any failures before committing:

```bash
{{VERIFICATION_COMMANDS}}
```

## Questions?

If unclear about implementation approach, ask for clarification before proceeding.

---

## Optional Sections (Uncomment and customize as needed)

<!--
## Skill Loading Requirements (for projects using skills/)

### Process Details

1. Identify the task domain
2. Read the required skill files from `skills/[skill-name]/SKILL.md`
3. Load supporting skills if additional patterns are needed
4. **Confirm patterns and security requirements to user**
5. Only then begin implementation

### Verification Required

Before implementing, you MUST explicitly state:
```
Skills loaded:
- [skill-name]: Applied patterns X, Y, Z
- [skill-name]: Security considerations A, B, C

Ready to implement following these skill requirements.
```
-->

<!--
## Performance Targets

- UI responsiveness: 60 FPS minimum
- API latency: <100ms
- Memory (idle): <{{MEMORY_LIMIT}}
-->
