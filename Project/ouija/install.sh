#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== Compiling & Installing Ouija Security Core ==="
make release

mkdir -p "$HOME/.local/bin"
cp "$PROJECT_DIR/ouija" "$HOME/.local/bin/ouija"
chmod +x "$HOME/.local/bin/ouija"

echo ""
echo "=========================================================="
echo " [OK] OUIJA INSTALLED SUCCESSFULLY!"
echo " Binary path: $HOME/.local/bin/ouija"
echo "=========================================================="
echo "Quick Commands:"
echo "  ouija start    -> Launch daemon & browser gateway (http://127.0.0.1:8765)"
echo "  ouija new id   -> Generate a new SHA-256 validated Ephemeral ID"
echo "  ouija status   -> View Tor Onion address and system status"
echo "  ouija purge    -> Immediately zeroize and wipe all RAM"
echo "=========================================================="
