#!/usr/bin/env bash
# -------------------------------------------------------------------
# skseal MCP server launcher (tool-agnostic)
#
# Works with: Cursor, Claude Desktop, Claude Code CLI, Windsurf,
#             Aider, Cline, or any MCP client that speaks stdio.
#
# Auto-detects the Python virtualenv and launches the MCP server on
# stdio. No hardcoded paths required in client configs.
#
# Usage:
#   ./skseal/scripts/mcp-serve.sh          (from repo root)
#   bash skseal/scripts/mcp-serve.sh       (explicit bash)
#
# Environment overrides:
#   SKSEAL_VENV=/path/to/venv bash skseal/scripts/mcp-serve.sh
#
# Client configuration examples:
#
#   Cursor (.cursor/mcp.json):
#     {"mcpServers": {"skseal": {
#         "command": "bash", "args": ["skseal/scripts/mcp-serve.sh"]}}}
#
#   Claude Code CLI (.mcp.json at repo root):
#     {"mcpServers": {"skseal": {
#         "command": "bash", "args": ["skseal/scripts/mcp-serve.sh"]}}}
#
#   Claude Desktop (use absolute path):
#     {"mcpServers": {"skseal": {
#         "command": "bash",
#         "args": ["/absolute/path/to/skseal/scripts/mcp-serve.sh"]}}}
# -------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKSEAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Locate the virtualenv ---
# Priority: SKSEAL_VENV env var > first venv with mcp installed
# Candidates: skseal/.venv > skmemory/.venv (shared) > repo .venv
find_venv() {
    if [[ -n "${SKSEAL_VENV:-}" ]] && [[ -f "$SKSEAL_VENV/bin/python" ]]; then
        echo "$SKSEAL_VENV"
        return
    fi

    local candidates=(
        "$SKSEAL_DIR/.venv"
        "$REPO_ROOT/skmemory/.venv"
        "$REPO_ROOT/skcapstone/.venv"
        "$REPO_ROOT/.venv"
    )

    for venv in "${candidates[@]}"; do
        if [[ -f "$venv/bin/python" ]]; then
            if "$venv/bin/python" -c "import mcp" 2>/dev/null; then
                echo "$venv"
                return
            fi
        fi
    done

    # Fallback: return first venv that exists (may need pip install mcp)
    for venv in "${candidates[@]}"; do
        if [[ -f "$venv/bin/python" ]]; then
            echo "$venv"
            return
        fi
    done

    return 1
}

VENV_DIR="$(find_venv)" || {
    echo "ERROR: No Python virtualenv found." >&2
    echo "Create one with:" >&2
    echo "  python -m venv skseal/.venv" >&2
    echo "  skseal/.venv/bin/pip install -e skseal/ mcp pgpy" >&2
    exit 1
}

PYTHON="$VENV_DIR/bin/python"

# --- Ensure skseal is importable ---
export PYTHONPATH="${SKSEAL_DIR}/src${PYTHONPATH:+:$PYTHONPATH}"

# --- Launch MCP server on stdio ---
exec "$PYTHON" -m skseal.mcp_server "$@"
