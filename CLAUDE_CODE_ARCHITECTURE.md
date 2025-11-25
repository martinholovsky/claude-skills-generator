# Claude Code Architecture for {{PROJECT_NAME}}

This document explains the directory structure for Claude Code integration and how each component affects Claude's behavior.

## Directory Structure

```
{{PROJECT_NAME}}/
├── CLAUDE.md                          # PRIMARY: Claude's project instructions (auto-read)
├── README.md                          # Project overview
├── CONTRIBUTING.md                    # Contribution guidelines
│
├── .claude/
│   ├── settings.json                  # Claude Code settings (auto-read)
│   │
│   ├── commands/                      # Slash commands (user-invoked)
│   │   ├── run-tests.md               # /run-tests
│   │   └── implement-feature.md       # /implement-feature
│   │
│   └── hooks/                         # (optional)
│       ├── session-start.md           # Runs at session start (auto-triggered)
│       └── pre-commit.md              # Runs before git commit (auto-triggered)
│
├── skills/                            # Domain knowledge (optional, loaded on-demand)
│   ├── {{SKILL_NAME}}/
│   │   ├── SKILL.md                   # Main skill file
│   │   └── references/                # Extended examples
│   └── README.md                      # Skill system overview
│
└── src/                               # Source code
    └── ...
```

## Component Comparison Table

| Component | Location | Auto-Read by Claude | User Must Invoke | Auto-Triggered | Primary Purpose |
|-----------|----------|---------------------|------------------|----------------|-----------------|
| **CLAUDE.md** | Root | **YES** | No | No | Mandatory project instructions |
| **Skills** | `skills/` | No | Yes (or via commands) | No | Domain-specific knowledge |
| **Slash Commands** | `.claude/commands/` | No | **YES** (user types `/command`) | No | Task automation |
| **Hooks** | `.claude/hooks/` | No | No | **YES** (event-based) | Automatic context loading |
| **Settings** | `.claude/settings.json` | **YES** | No | No | Claude Code configuration |

## Detailed Explanation

### 1. CLAUDE.md (Auto-Read, Prescriptive)

**What it is**: The PRIMARY instruction file that Claude reads at the start of every session.

**Use for**:
- Mandatory rules and behaviors
- References to important documentation
- Code style enforcement
- Security requirements

**Example content**:
```markdown
# {{PROJECT_NAME}} Project Instructions

## MANDATORY: Before Implementing
1. Read relevant documentation
2. Follow coding standards
3. Run tests before committing
```

**Why it works**: Claude automatically reads this file, so instructions here are followed without user intervention.

---

### 2. Skills (On-Demand, Domain Knowledge)

**What it is**: Specialized knowledge files for specific domains (Python, FastAPI, etc.)

**Use for**:
- Code patterns and best practices
- Security considerations
- API references
- Implementation examples

**How to load**:
1. User explicitly asks Claude to read them
2. CLAUDE.md instructs Claude to read them
3. Slash commands load them automatically
4. Hooks load them at session start

---

### 3. Slash Commands (User-Invoked, Task Automation)

**What it is**: Custom commands that users can invoke with `/command-name`

**Use for**:
- Loading skill sets for specific tasks
- Automating repetitive workflows
- Providing task-specific context

**Example**: `/run-tests` runs all tests automatically

**How they work**:
1. User types `/run-tests`
2. Claude reads `.claude/commands/run-tests.md`
3. Command file contains instructions to execute
4. Claude follows those instructions

---

### 4. Hooks (Auto-Triggered, Event-Based)

**What it is**: Scripts that run automatically at specific events

**Use for**:
- Loading context at session start
- Running checks before commits
- Validating code before save

**Available hooks**:
- `session-start`: Runs when Claude Code session begins
- `pre-commit`: Runs before git commits
- `post-save`: Runs after file saves

---

## Use Case Matrix

| Use Case | Best Solution | Why |
|----------|---------------|-----|
| Enforce rules for ALL tasks | CLAUDE.md | Auto-read, always active |
| Load skills for specific task | Slash command | User control, task-specific |
| Auto-load project context on start | Session-start hook | Automatic, no user action |
| Ensure checks before commit | Pre-commit hook | Automatic enforcement |
| Provide domain knowledge | Skills | On-demand, detailed |

## Recommended Setup

### Minimum Viable Setup
1. **CLAUDE.md** with project instructions

### Recommended Setup
1. **CLAUDE.md** with project rules
2. **Slash commands** for common tasks

### Full Setup
1. **CLAUDE.md** with comprehensive rules
2. **Skills** directory (if using domain-specific knowledge)
3. **Slash commands** for all task types
4. **Session-start hook** for context loading
5. **Pre-commit hook** for validation

## How Claude Decides What to Read

```
Session Start
    │
    ▼
┌─────────────┐
│ CLAUDE.md   │ ◄── Always read first
└─────────────┘
    │
    ▼
┌─────────────┐
│ Hooks       │ ◄── Auto-triggered if configured
└─────────────┘
    │
    ▼
User Request
    │
    ├─► If user types `/command` ──► Load command file
    │
    ├─► If CLAUDE.md says "read X" ──► Read X
    │
    └─► If user says "read X" ──► Read X
```

## Key Insight

**The hierarchy of enforcement**:

1. **Strongest**: CLAUDE.md instructions (always followed)
2. **Strong**: Hooks (automatic, no user action)
3. **Medium**: Slash commands (user must invoke)
4. **Weakest**: Documentation (must be referenced)

To ensure something is ALWAYS done, put the requirement in CLAUDE.md.
