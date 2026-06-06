#!/usr/bin/env bash
# Verify GitHub branch protection matches ADR-018.
# Requires: gh CLI authenticated, jq
#
# shellcheck shell=bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}  ✓${NC} $1"; }
fail() { echo -e "${RED}  ✗${NC} $1"; FAILED=1; }

REPO="umudique/arcanum"
BRANCH="main"
FAILED=0

echo "arcanum — GitHub config verification (ADR-018)"
echo "────────────────────────────────────────────────"

# ── Fetch protection ─────────────────────────────────────────────────────────
PROTECTION=$(gh api "repos/${REPO}/branches/${BRANCH}/protection" 2>/dev/null) || {
    echo "  error: could not fetch branch protection (gh CLI not authenticated?)"
    exit 1
}

# ── Force push disabled ───────────────────────────────────────────────────────
FORCE_PUSH=$(echo "$PROTECTION" | jq -r '.allow_force_pushes.enabled')
if [ "$FORCE_PUSH" = "false" ]; then
    pass "force push disabled"
else
    fail "force push is ENABLED — must be disabled after history rewrites"
fi

# ── PR reviews not required ───────────────────────────────────────────────────
REVIEWS=$(echo "$PROTECTION" | jq -r '.required_pull_request_reviews // "null"')
if [ "$REVIEWS" = "null" ]; then
    pass "PR reviews not required (solo developer)"
else
    REVIEW_COUNT=$(echo "$PROTECTION" | jq -r '.required_pull_request_reviews.required_approving_review_count // 0')
    if [ "$REVIEW_COUNT" = "0" ]; then
        pass "PR reviews not required (solo developer)"
    else
        fail "PR reviews required ($REVIEW_COUNT) — expected 0 for solo developer"
    fi
fi

# ── Required status checks ────────────────────────────────────────────────────
EXPECTED_CHECKS=("fmt" "check" "clippy" "test" "audit" "deny")
ACTUAL_CHECKS=$(echo "$PROTECTION" | jq -r '.required_status_checks.contexts[]' 2>/dev/null | sort)

for check in "${EXPECTED_CHECKS[@]}"; do
    if echo "$ACTUAL_CHECKS" | grep -qx "$check"; then
        pass "required check: $check"
    else
        fail "missing required check: $check"
    fi
done

# Check for unexpected required checks
while IFS= read -r check; do
    found=0
    for expected in "${EXPECTED_CHECKS[@]}"; do
        [ "$check" = "$expected" ] && found=1 && break
    done
    if [ "$found" = "0" ]; then
        fail "unexpected required check: $check (update ADR-018 if intentional)"
    fi
done <<< "$ACTUAL_CHECKS"

# ── Strict status checks ──────────────────────────────────────────────────────
STRICT=$(echo "$PROTECTION" | jq -r '.required_status_checks.strict')
if [ "$STRICT" = "true" ]; then
    pass "strict status checks (branch must be up-to-date)"
else
    fail "strict status checks disabled — branch can be behind main at merge"
fi

# ── Signed commits required ──────────────────────────────────────────────────
SIGNATURES=$(echo "$PROTECTION" | jq -r '.required_signatures.enabled')
if [ "$SIGNATURES" = "true" ]; then
    pass "signed commits required"
else
    fail "signed commits not required — enable in branch protection (ADR-018)"
fi

# ── Linear history required ───────────────────────────────────────────────────
LINEAR=$(echo "$PROTECTION" | jq -r '.required_linear_history.enabled')
if [ "$LINEAR" = "true" ]; then
    pass "linear history required (no merge commits)"
else
    fail "linear history not required — enable in branch protection (ADR-018)"
fi

# ── Deletions forbidden ───────────────────────────────────────────────────────
DELETIONS=$(echo "$PROTECTION" | jq -r '.allow_deletions.enabled')
if [ "$DELETIONS" = "false" ]; then
    pass "branch deletion forbidden"
else
    fail "branch deletion is allowed — should be forbidden"
fi

# ── CI workflow triggers ──────────────────────────────────────────────────────
echo ""
echo "→ CI workflow trigger check (local files)"

check_trigger() {
    local file="$1"
    local label="$2"
    local expected_push_branch="$3"

    if [ ! -f "$file" ]; then
        fail "$label: file not found ($file)"
        return
    fi

    if grep -q 'branches: \[main\]' "$file" || grep -q "branches: \[\"main\"\]" "$file"; then
        pass "$label: scoped to main branch"
    else
        fail "$label: triggers on all branches — expected main-only (ADR-018)"
    fi
}

WORKFLOW_DIR="$(git rev-parse --show-toplevel)/.github/workflows"
check_trigger "$WORKFLOW_DIR/ci-fast.yml"       "ci-fast"       "main"
check_trigger "$WORKFLOW_DIR/security-scan.yml" "security-scan" "main"

echo ""
echo "────────────────────────────────────────────────"
if [ "$FAILED" = "0" ]; then
    echo -e "${GREEN}all checks passed${NC}"
else
    echo -e "${RED}drift detected — review ADR-018 and update GitHub settings${NC}"
    exit 1
fi
