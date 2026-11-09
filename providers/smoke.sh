#!/usr/bin/env bash
# smoke.sh — confirm your chosen LLM provider answers before the workshop.
#
# Reads .env from the repo root (one level up, where the kickoff setup puts it) or,
# failing that, from this directory. Copy one of the *.env.example files first,
# then asks ATHF to run a tiny hypothesis-generator call in --workshop mode.
# Green = you're ready to hunt at minute 1. Red = fix your key/endpoint now.
#
# Requires: athf installed (`pip install agentic-threat-hunting-framework` + a provider extra). See README.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
if [[ -f "${ROOT}/.env" ]]; then ENV_FILE="${ROOT}/.env"; else ENV_FILE="${HERE}/.env"; fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: no .env found in ${ROOT} or ${HERE}"
  echo "Copy one of the templates first, from the repo root:"
  echo "  cp providers/anthropic.env.example .env"
  echo "  # then edit .env and add your key"
  exit 1
fi

# Load .env (export every assignment).
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

if ! command -v athf >/dev/null 2>&1; then
  echo "ERROR: 'athf' not on PATH. Install it: pip install agentic-threat-hunting-framework"
  echo "Then a provider extra, e.g.: pip install 'agentic-threat-hunting-framework[litellm]'"
  exit 1
fi

echo ">> Provider resolution:"
echo "   ATHF_LLM_PROVIDER=${ATHF_LLM_PROVIDER:-<auto-detect>}"
echo "   ATHF_LLM_MODEL=${ATHF_LLM_MODEL:-<provider default>}"
echo ">> Sending a minimal hypothesis-generator prompt (workshop mode, capped)..."
echo

# The smallest real call the workshop makes. --workshop caps tokens + logs.
if athf agent run hypothesis-generator \
     --threat-intel "smoke test: confirm provider connectivity" \
     --workshop --token-cap 64 \
     --output-format json >/tmp/athf-smoke.json 2>/tmp/athf-smoke.err; then
  echo "PASS: provider answered. You're ready for the workshop."
  echo "      (full response in /tmp/athf-smoke.json)"
  exit 0
else
  echo "FAIL: provider did not answer. Details:"
  sed 's/^/   /' /tmp/athf-smoke.err
  echo
  echo "Common fixes:"
  echo "  • Wrong/expired key in ${ENV_FILE}"
  echo "  • Missing provider extra (pip install 'agentic-threat-hunting-framework[litellm]' etc.)"
  echo "  • Bedrock: model access not enabled in your region"
  echo "  • Ollama: run 'ollama serve' and 'ollama pull \${ATHF_LLM_MODEL}'"
  exit 1
fi
