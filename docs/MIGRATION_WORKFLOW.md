# Database Migration Workflow

## Preventing Migration Head Conflicts

Migration head conflicts occur when multiple migration branches exist, preventing Alembic from determining which migration to apply. This typically happens when:

- Multiple developers create migrations on different branches
- Migrations are created without pulling latest changes first
- Merge migrations aren't created when branches diverge

## Best Practices

### 1. Before Creating a New Migration

**Always check the current head first:**

```bash
flask db heads
```

This should show **only ONE** head. If you see multiple heads, resolve them before creating new migrations.

### 2. Feature Branch Workflow

```bash
# 1. Pull latest changes from main
git pull origin main

# 2. Ensure you're on the latest migration
flask db upgrade

# 3. Check heads (should be single)
flask db heads

# 4. Now create your migration
flask db migrate -m "your migration description"
```

### 3. Resolving Multiple Heads

If you encounter multiple heads:

```bash
# 1. Identify the heads
flask db heads

# 2. Create a merge migration
flask db merge -m "merge migration branches" <head1> <head2>

# 3. Update any new migrations to point to the merge migration
# Edit the migration file's down_revision to point to the merge revision
```

### 4. Before Committing

**Always verify before committing:**

```bash
# Check for single head
flask db heads

# Test migration up and down
flask db upgrade
flask db downgrade -1
flask db upgrade  # restore
```

## Automated Checks

### Pre-commit Hook (Optional)

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Check migration heads before committing
if git diff --cached --name-only | grep -q "backend/migrations/versions/.*\.py$"; then
    cd backend
    if ! flask db heads 2>&1 | grep -q "head"; then
        head_count=$(flask db heads 2>&1 | grep -c "head" || echo "0")
        if [ "$head_count" -gt 1 ]; then
            echo "ERROR: Multiple migration heads detected!"
            flask db heads
            exit 1
        fi
    fi
fi
```

### CI/CD Check

A GitHub Actions workflow (`.github/workflows/check-migrations.yml`) automatically checks for multiple heads on PRs.

## Common Scenarios

### Scenario 1: Two developers create migrations simultaneously

**Problem:** Developer A creates migration on branch A, Developer B creates migration on branch B, both from the same parent.

**Solution:**
1. Merge one branch first
2. Create merge migration for the other branch
3. Update the second branch's migration to point to merge

### Scenario 2: Migration created on outdated branch

**Problem:** Migration created from an old head instead of latest.

**Solution:**
1. Update the migration's `down_revision` to point to the latest head
2. Or rebase the branch and recreate the migration

### Scenario 3: Merge migration needed

**Problem:** Two branches have diverged migrations.

**Solution:**
```bash
# Create merge migration
flask db merge -m "merge branches" <head1> <head2>

# Any new migrations should point to the merge revision
```

## Quick Reference

```bash
# Check current migration state
flask db current

# Check for multiple heads
flask db heads

# View migration history
flask db history

# Create new migration
flask db migrate -m "description"

# Apply migrations
flask db upgrade

# Rollback one migration
flask db downgrade -1

# Rollback to specific revision
flask db downgrade <revision>

# Create merge migration
flask db merge -m "merge" <head1> <head2>
```

## Troubleshooting

### "Multiple head revisions" error

1. Check heads: `flask db heads`
2. Identify the branches
3. Create merge migration
4. Update new migrations to point to merge

### Migration file has wrong down_revision

Edit the migration file and update the `down_revision` variable to point to the correct parent revision.

### Need to fix migration after it's been applied

1. Create a new migration to fix the issue (preferred)
2. Or manually edit the migration file if it hasn't been applied to production yet



