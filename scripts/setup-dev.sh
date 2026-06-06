#!/usr/bin/env bash
# Arcanum development environment setup
# Run once after cloning the repository.
# shellcheck shell=bash

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  !${NC} $1"; }

echo "Arcanum — development environment setup"
echo "════════════════════════════════════════"

# ── Git hooks ────────────────────────────────────────────────────────────────
echo ""
echo "→ Configuring git hooks..."
git config core.hooksPath .githooks
pass "git hooks path set to .githooks"

# ── Rust stable toolchain ────────────────────────────────────────────────────
echo ""
echo "→ Checking stable toolchain..."
if rustup toolchain list | grep -q "stable"; then
    pass "stable toolchain present"
else
    rustup toolchain install stable
    pass "stable toolchain installed"
fi

rustup component add rustfmt clippy
pass "rustfmt and clippy installed"

# ── Nightly toolchain for Miri ───────────────────────────────────────────────
echo ""
echo "→ Installing nightly toolchain for Miri and coverage..."
rustup toolchain install nightly --component miri llvm-tools-preview
pass "nightly + Miri + llvm-tools installed"

# ── llvm-tools for coverage (stable) ────────────────────────────────────────
rustup component add llvm-tools-preview
pass "llvm-tools-preview (stable) installed"

# ── Cargo tools ──────────────────────────────────────────────────────────────
echo ""
echo "→ Installing cargo tools..."

install_cargo_tool() {
    local tool="$1"
    local crate="${2:-$1}"
    if cargo "${tool}" --version &>/dev/null 2>&1; then
        pass "${tool} already installed"
    else
        echo "  installing ${tool}..."
        cargo install "${crate}" --locked
        pass "${tool} installed"
    fi
}

install_cargo_tool "audit"      "cargo-audit"
install_cargo_tool "deny"       "cargo-deny"
install_cargo_tool "geiger"     "cargo-geiger"
install_cargo_tool "machete"    "cargo-machete"
install_cargo_tool "auditable"  "cargo-auditable"

# cargo-nextest (via taiki-e installer for reliability)
if cargo nextest --version &>/dev/null 2>&1; then
    pass "cargo-nextest already installed"
else
    echo "  installing cargo-nextest..."
    curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C "${HOME}/.cargo/bin"
    pass "cargo-nextest installed"
fi

# cargo-llvm-cov
if cargo llvm-cov --version &>/dev/null 2>&1; then
    pass "cargo-llvm-cov already installed"
else
    echo "  installing cargo-llvm-cov..."
    cargo install cargo-llvm-cov --locked
    pass "cargo-llvm-cov installed"
fi

# ── Optional: cargo-fuzz ─────────────────────────────────────────────────────
echo ""
echo "→ Installing cargo-fuzz (optional, requires nightly)..."
if cargo fuzz --version &>/dev/null 2>&1; then
    pass "cargo-fuzz already installed"
else
    cargo +nightly install cargo-fuzz --locked 2>/dev/null || \
        warn "cargo-fuzz install failed — install manually if needed"
fi

# ── Kani: bounded model checking ─────────────────────────────────────────────
echo ""
echo "→ Installing cargo-kani (mathematical verification)..."
if cargo kani --version &>/dev/null 2>&1; then
    pass "cargo-kani already installed"
else
    if cargo install --locked kani-verifier 2>/dev/null && cargo kani setup 2>/dev/null; then
        pass "cargo-kani installed"
    else
        warn "cargo-kani install failed — install manually: cargo install kani-verifier"
    fi
fi

# ── gitleaks: secret scanning ────────────────────────────────────────────────
echo ""
echo "→ Installing gitleaks (secret scanning)..."
if command -v gitleaks &>/dev/null; then
    pass "gitleaks already installed"
else
    GITLEAKS_VERSION="8.21.2"
    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    echo "  downloading gitleaks v${GITLEAKS_VERSION}..."
    if curl -sSfL "${GITLEAKS_URL}" | tar -xz -C "${HOME}/.cargo/bin" gitleaks; then
        pass "gitleaks installed"
    else
        warn "gitleaks install failed — install manually: https://github.com/gitleaks/gitleaks"
    fi
fi

# ── System tools check ───────────────────────────────────────────────────────
echo ""
echo "→ Checking system tools..."

if command -v shellcheck &>/dev/null; then
    pass "shellcheck present ($(shellcheck --version | head -2 | tail -1))"
else
    warn "shellcheck not found — install: sudo dnf install ShellCheck (Fedora) / brew install shellcheck"
fi

if command -v yamllint &>/dev/null; then
    pass "yamllint present"
else
    warn "yamllint not found — install: pip install yamllint / sudo dnf install yamllint"
fi

# ── Verify workspace ─────────────────────────────────────────────────────────
echo ""
echo "→ Verifying workspace..."
cargo check --workspace --all-targets --quiet
pass "workspace compiles"

echo ""
echo "════════════════════════════════════════"
echo -e "${GREEN}Setup complete.${NC}"
echo ""
echo "Quick reference:"
echo "  cargo check-all      — compile check"
echo "  cargo lint           — clippy -D warnings"
echo "  cargo test-all       — all tests"
echo "  cargo nextest run    — fast parallel tests"
echo "  cargo llvm-cov       — coverage report"
echo "  cargo audit-check    — CVE scan"
echo "  cargo machete        — unused deps"
echo "  cargo miri-crypto    — Miri for arcanum-crypto"
echo "  cargo miri-all       — Miri for all crypto crates"
echo "  gitleaks detect      — scan full repo for secrets"
