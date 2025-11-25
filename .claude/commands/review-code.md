# Review Code

Perform a code review on recent changes.

## Review Checklist

### Functionality
- [ ] Code accomplishes the intended purpose
- [ ] Edge cases are handled
- [ ] Error handling is appropriate

### Code Quality
- [ ] Follows project coding standards
- [ ] No unnecessary complexity
- [ ] Clear naming conventions
- [ ] No code duplication

### Security
- [ ] No hardcoded secrets
- [ ] Input validation present
- [ ] No SQL injection vulnerabilities
- [ ] No XSS vulnerabilities

### Testing
- [ ] Adequate test coverage
- [ ] Tests are meaningful, not just for coverage
- [ ] Edge cases tested

### Performance
- [ ] No obvious performance issues
- [ ] Efficient algorithms used
- [ ] No memory leaks

## Commands

```bash
# View recent changes
git diff HEAD~1

# Run tests
{{TEST_COMMAND}}

# Run linter
{{LINT_COMMAND}}
```

## Output

Provide feedback with:
1. Issues found (if any)
2. Suggestions for improvement
3. Positive observations
