#!/usr/bin/env bash
# Arcanum development environment setup
# Run once after cloning the repository.

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Arcanum — development environment setup"
echo "════════════════════════════════════════"

# ── Git hooks ────────────────────────────────────────────────────────────────
echo ""
echo "→ Configuring git hooks..."
git config core.hooksPath .githooks
echo -e "${GREEN}  ✓${NC} git hooks path set to .githooks"

# ── Rust stable toolchain ────────────────────────────────────────────────────
echo ""
echo "→ Checking stable toolchain..."
if rustup toolchain list | grep -q "stable"; then
    echo -e "${GREEN}  ✓${NC} stable toolchain present"
else
    rustup toolchain install stable
    echo -e "${GREEN}  ✓${NC} stable toolchain installed"
fi

rustup component add rustfmt clippy
echo -e "${GREEN}  ✓${NC} rustfmt and clippy installed"

# ── Nightly toolchain for Miri ───────────────────────────────────────────────
echo ""
echo "→ Installing nightly toolchain for Miri..."
rustup toolchain install nightly --component miri
echo -e "${GREEN}  ✓${NC} nightly + Miri installed"

# ── Security tools ───────────────────────────────────────────────────────────
echo ""
echo "→ Installing security tools..."

tools=(
    "cargo-audit"
    "cargo-deny"
    "cargo-geiger"
)

for tool in "${tools[@]}"; do
    if cargo "$tool" --version &>/dev/null 2>&1; then
        echo -e "${GREEN}  ✓${NC} $tool already installed"
    else
        echo "  installing $tool..."
        cargo install "$tool" --locked
        echo -e "${GREEN}  ✓${NC} $tool installed"
    fi
done

# ── Optional: cargo-fuzz ─────────────────────────────────────────────────────
echo ""
echo "→ Installing cargo-fuzz (optional, requires nightly)..."
if cargo fuzz --version &>/dev/null 2>&1; then
    echo -e "${GREEN}  ✓${NC} cargo-fuzz already installed"
else
    cargo +nightly install cargo-fuzz --locked 2>/dev/null || \
        echo -e "${YELLOW}  !${NC} cargo-fuzz install failed — install manually if needed"
fi

# ── Kani: bounded model checking ─────────────────────────────────────────────
echo ""
echo "→ Installing cargo-kani (mathematical verification)..."
if cargo kani --version &>/dev/null 2>&1; then
    echo -e "${GREEN}  ✓${NC} cargo-kani already installed"
else
    cargo install --locked kani-verifier 2>/dev/null && cargo kani setup 2>/dev/null || \
        echo -e "${YELLOW}  !${NC} cargo-kani install failed — install manually: cargo install kani-verifier"
fi

# ── Verify setup ─────────────────────────────────────────────────────────────
echo ""
echo "→ Verifying workspace..."
cargo check --workspace --all-targets --quiet
echo -e "${GREEN}  ✓${NC} workspace compiles"

echo ""
echo "════════════════════════════════════════"
echo -e "${GREEN}Setup complete.${NC}"
echo ""
echo "Quick reference:"
echo "  cargo check-all   — compile check"
echo "  cargo lint        — clippy -D warnings"
echo "  cargo test-all    — all tests"
echo "  cargo audit-check — CVE scan"
echo "  cargo miri-crypto — Miri for arcanum-crypto"
echo "  cargo miri-all    — Miri for all crypto crates"
