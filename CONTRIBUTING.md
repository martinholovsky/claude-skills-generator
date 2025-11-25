# Contributing to {{PROJECT_NAME}}

Thank you for your interest in contributing! This document provides guidelines and information about contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [AI-Assisted Development](#ai-assisted-development)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

## Code of Conduct

This project adheres to our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/{{REPO_NAME}}.git`
3. Set up the development environment:
   ```bash
   {{DEV_SETUP_COMMANDS}}
   ```
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## AI-Assisted Development

This project uses Claude Code for AI-assisted development. When using AI tools:

### Guidelines

1. **Read CLAUDE.md First**: Understand the project-specific AI instructions before starting
2. **Load Required Skills**: Use the appropriate slash commands to load domain-specific knowledge
3. **Security First**: Always consider security implications - AI may generate insecure code
4. **Verify All Output**: Review and test all AI-generated code thoroughly
5. **Don't Trust Blindly**: Validate versions, APIs, and security patterns

### Using Slash Commands

{{SLASH_COMMAND_EXAMPLES}}

### Required Reading Protocol

Before implementing features with AI assistance:

1. Load the relevant skills for your task domain
2. Confirm which patterns will be applied
3. List security considerations
4. Begin implementation

## Development Workflow

### Branch Naming

- Features: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`
- Refactoring: `refactor/description`

### Testing Requirements

All contributions must include appropriate tests:

```bash
{{TEST_COMMANDS}}
```

Minimum requirements:
- Unit tests for new functions
- Integration tests for new features
- No decrease in code coverage

## Coding Standards

### {{PRIMARY_LANGUAGE}}

{{LANGUAGE_SPECIFIC_STANDARDS}}

### General Guidelines

- Write self-documenting code
- Follow existing code patterns
- Keep functions focused and small
- Handle errors appropriately
- Add comments only when logic isn't self-evident
- No over-engineering - solve the current problem

### Security Standards

- Never commit secrets or credentials
- Validate all user inputs
- Follow OWASP Top 10 guidelines
- Use parameterized queries for databases
- Apply principle of least privilege

## Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(auth): add OAuth2 login support

Implements OAuth2 flow with Google and GitHub providers.
Includes token refresh mechanism and secure storage.

Closes #123
```

```
fix(api): prevent SQL injection in user search

Sanitize user input and use parameterized queries.

Security: Addresses CVE-2024-XXXXX
```

## Pull Request Process

### Before Submitting

1. **Run all tests**: `{{TEST_COMMANDS}}`
2. **Run linters**: `{{LINT_COMMANDS}}`
3. **Update documentation** if needed
4. **Add tests** for new functionality
5. **Rebase on main** to ensure no conflicts

### PR Template

When creating a PR, include:

- **Summary**: What changes were made and why
- **Testing**: How the changes were tested
- **Screenshots**: For UI changes
- **Breaking Changes**: Any breaking changes
- **Related Issues**: Link to related issues

### Review Process

1. PRs require at least {{MIN_REVIEWERS}} reviewer approval
2. All CI checks must pass
3. No unresolved comments
4. Follows coding standards
5. Includes appropriate tests

### After Merge

- Delete your feature branch
- Update related issues
- Verify deployment (if applicable)

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities privately via:
- Email: {{SECURITY_EMAIL}}
- Or use GitHub's private vulnerability reporting

**Do NOT** create public issues for security vulnerabilities.

### Security Review

PRs affecting security-sensitive areas require additional review:
- Authentication/Authorization
- Encryption/Cryptography
- User input handling
- External API integration

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues and discussions first

Thank you for contributing! 🎉
