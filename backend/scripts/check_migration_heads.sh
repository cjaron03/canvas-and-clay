#!/bin/bash
# Check for multiple migration heads before creating new migrations
# This prevents migration branching conflicts

set -e

cd "$(dirname "$0")/.." || exit 1

echo "Checking migration heads..."

# Check for multiple heads
heads=$(flask db heads 2>&1 | grep -c "head" || echo "0")

if [ "$heads" -gt 1 ]; then
    echo "ERROR: Multiple migration heads detected!"
    echo ""
    echo "Current heads:"
    flask db heads
    echo ""
    echo "To fix:"
    echo "1. Identify the branches: flask db heads"
    echo "2. Create a merge migration: flask db merge -m 'merge branches' <head1> <head2>"
    echo "3. Update any new migrations to point to the merge migration"
    echo ""
    exit 1
fi

echo "✓ Migration head check passed (single head)"
exit 0



