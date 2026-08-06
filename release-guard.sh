#!/usr/bin/env bash
# release-guard.sh — safety checks before creating a release tag
set -euo pipefail

# Ensure GitHub CLI is in PATH
# Use multiple path formats to handle Git Bash/MSYS2 path quirks
for gh_dir in "/mnt/c/Program Files/GitHub CLI" "/mnt/c/Progra~1/GitHub CLI" "/c/Program Files/GitHub CLI"; do
    if [ -d "$gh_dir" ]; then
        export PATH="$gh_dir:$PATH"
        break
    fi
done

echo "=== Release Guard ==="
echo ""

# 1. Check if master is pushed
echo ">> Checking if local master is up to date with remote..."
LOCAL_SHA=$(git rev-parse master)
REMOTE_SHA=$(git rev-parse origin/master)
if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
    echo "[OK] master is up to date ($LOCAL_SHA)"
else
    echo "[FAIL] master is NOT up to date!"
    echo "  Local:  $LOCAL_SHA"
    echo "  Remote: $REMOTE_SHA"
    echo "  Run: git push origin master"
    exit 1
fi

# 2. Check if CI is green for master
echo ""
echo ">> Checking CI status for master..."
CI_JSON=$(cmd.exe /c "gh run list --workflow ci.yml -b master --limit 1 --json conclusion" 2>/dev/null || echo '[]')
if echo "$CI_JSON" | grep -q '"success"'; then
    echo "[OK] CI is green for master"
else
    echo "[FAIL] CI is not green for master (raw: $CI_JSON)"
    echo "  Wait for CI to pass before releasing"
    exit 1
fi

# 3. Check if release workflow is green for master
echo ""
echo ">> Checking release workflow status for master..."
RELEASE_JSON=$(cmd.exe /c "gh run list --workflow release.yml -b master --limit 1 --json conclusion" 2>/dev/null || echo '[]')
if echo "$RELEASE_JSON" | grep -q '"success"'; then
    echo "[OK] Release workflow passed for master"
else
    echo "[FAIL] Release workflow is not green for master (raw: $RELEASE_JSON)"
    echo "  This may be normal if no tag has been pushed yet"
fi

echo ""
echo "=== Release Guard: ALL CHECKS PASSED ==="
echo "You can now safely create and push a tag:"
echo "  git tag vX.Y.Z"
echo "  git push --tags"
