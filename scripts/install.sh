#!/usr/bin/env bash
# First-time install: venv, Python deps, (optional) Ollama + model.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Creating Python venv"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

echo "==> Installing Python deps"
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

echo
echo "==> Checking Ollama (for LLM detection layer)"

if command -v ollama >/dev/null 2>&1; then
  echo "  ✓ ollama is installed"
else
  echo "  ✗ ollama not found"
  echo
  echo "  The LLM layer catches contextual entities (bare hostnames like DC01,"
  echo "  person names, org names) that regex can't. Without Ollama, the proxy"
  echo "  falls back to regex-only (still catches IPs, hashes, emails, AWS keys,"
  echo "  AD identifiers, and 20+ other patterns)."
  echo
  read -r -p "  Install Ollama now? (recommended) [y/N] " ans
  if [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]; then
    echo "  Installing Ollama via official installer..."
    if curl -fsSL https://ollama.com/install.sh | sh; then
      echo "  ✓ Ollama installed"
    else
      echo "  ⚠  Ollama install failed — continuing in regex-only mode."
      echo "     you can install later: curl -fsSL https://ollama.com/install.sh | sh"
    fi
  else
    echo "  Skipping Ollama. Proxy will run in regex-only mode."
    echo "  Later: curl -fsSL https://ollama.com/install.sh | sh"
  fi
fi

# Pull model if Ollama is present
MODEL="${LLM_MODEL:-qwen3:4b-instruct-2507-q4_K_M}"
if command -v ollama >/dev/null 2>&1; then
  echo
  echo "==> Ensuring model is pulled: $MODEL"
  if ollama list 2>/dev/null | grep -q "$MODEL"; then
    echo "  ✓ model already present"
  else
    echo "  pulling $MODEL (~2.5GB first time)..."
    ollama pull "$MODEL" || echo "  ⚠  pull failed — proxy will still work in regex-only mode"
  fi
fi

# Ensure redact and scripts/vault are executable
chmod +x redact scripts/run.sh scripts/install.sh scripts/vault 2>/dev/null || true

# Install 'redact' into ~/.local/bin so it's globally callable
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
ln -sf "$(pwd)/redact" "$BIN_DIR/redact"
echo
echo "==> Installed 'redact' symlink: $BIN_DIR/redact"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
  echo "  ⚠  $BIN_DIR is NOT on your PATH."
  SHELL_RC="$HOME/.bashrc"
  [[ -n "${ZSH_VERSION:-}" || "${SHELL:-}" == */zsh ]] && SHELL_RC="$HOME/.zshrc"
  echo "     add this line to $SHELL_RC and restart your shell:"
  echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo
echo "✓ Install complete."
echo
echo "Next steps:"
echo "  redact start my-engagement   # start proxy for this client"
echo "  redact claude                # launch Claude Code through the proxy"
echo
echo "Other handy commands:"
echo "  redact status                # is the proxy running?"
echo "  redact vault list            # see what got swapped"
echo "  redact stop                  # stop the proxy"
