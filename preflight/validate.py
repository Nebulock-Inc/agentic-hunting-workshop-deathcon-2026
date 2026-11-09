#!/usr/bin/env python3
"""Agentic Threat Hunting workshop preflight validator.

Single-file, stdlib-only environment checker. Attendees run this BEFORE
installing anything else, so it must not import any third-party package.

Usage (from repo root, as the pre-arrival email instructs):
    python preflight/validate.py            # colored green/red checklist
    python preflight/validate.py --json     # machine-readable JSON output

Exit code 0 if no hard failures, 1 otherwise.
"""

import argparse
import importlib.util
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.request
from collections import namedtuple

# ---------------------------------------------------------------------------
# Result model + status constants
# ---------------------------------------------------------------------------

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

CheckResult = namedtuple("CheckResult", ["name", "status", "message"])


# ---------------------------------------------------------------------------
# Color handling (respects NO_COLOR and non-tty)
# ---------------------------------------------------------------------------


def color_enabled() -> bool:
    """Return True if ANSI color output should be used."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


_ANSI = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[color]}{text}{_ANSI['reset']}"


_STATUS_GLYPH = {PASS: ("✓", "green"), FAIL: ("✗", "red"), WARN: ("⚠", "yellow")}


# ---------------------------------------------------------------------------
# Individual checks (each importable + independently testable)
# ---------------------------------------------------------------------------


def check_python_version(version_info=None) -> CheckResult:
    """Check 1: Python >= 3.8 (WARN if < 3.11, HARD FAIL if < 3.8)."""
    vi = version_info if version_info is not None else sys.version_info
    ver = f"{vi[0]}.{vi[1]}.{vi[2]}"
    if (vi[0], vi[1]) < (3, 8):
        return CheckResult("Python version", FAIL, f"Python {ver} < 3.8 (required minimum)")
    if (vi[0], vi[1]) < (3, 11):
        return CheckResult("Python version", WARN, f"Python {ver} works but 3.11+ recommended")
    return CheckResult("Python version", PASS, f"Python {ver}")


def check_athf_installed() -> CheckResult:
    """Check 2: agentic-threat-hunting-framework installed."""
    spec = None
    try:
        spec = importlib.util.find_spec("athf")
    except (ImportError, ValueError, ModuleNotFoundError):
        spec = None
    if spec is not None:
        return CheckResult("ATHF installed", PASS, "athf package importable")
    if shutil.which("athf"):
        return CheckResult("ATHF installed", PASS, "athf CLI found on PATH")
    return CheckResult(
        "ATHF installed",
        FAIL,
        "athf not found. Install: pip install agentic-threat-hunting-framework",
    )


def _load_dotenv(path: str = ".env") -> dict:
    """Best-effort parse of a .env file into a dict. Never raises.

    Attendees are told to put their key in .env (see providers/README.md), so
    preflight must honor that path, not just the exported shell environment.
    """
    values: dict = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :]
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'").strip('"')
                if key:
                    values[key] = val
    except OSError:
        pass
    return values


def _ollama_reachable(url: str = "http://localhost:11434", timeout: float = 2.0) -> bool:
    """Best-effort probe of a local Ollama server. Catches everything."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return resp.status < 500
    except Exception:
        return False


def _provider_credential_missing(pinned: str, resolve, probe):
    """Return a FAIL message if ATHF_LLM_PROVIDER=`pinned` lacks its credential.

    Returns None when the pinned provider has what it needs (or when it's an
    unrecognized string we shouldn't second-guess). Provider names follow
    providers/README.md.
    """
    if pinned in ("openai", "openai-compatible"):
        if not resolve("OPENAI_API_KEY"):
            return (
                f"ATHF_LLM_PROVIDER={pinned} but OPENAI_API_KEY is not set. "
                "Set the key or unset ATHF_LLM_PROVIDER to auto-detect."
            )
    elif pinned in ("anthropic", "litellm"):
        if not resolve("ANTHROPIC_API_KEY"):
            return (
                f"ATHF_LLM_PROVIDER={pinned} but ANTHROPIC_API_KEY is not set. "
                "Set the key or unset ATHF_LLM_PROVIDER to auto-detect."
            )
    elif pinned == "bedrock":
        has_bedrock = (
            resolve("AWS_BEARER_TOKEN_BEDROCK")
            or (resolve("AWS_ACCESS_KEY_ID") and resolve("AWS_SECRET_ACCESS_KEY"))
            or resolve("AWS_PROFILE")
        )
        if not has_bedrock:
            return (
                "ATHF_LLM_PROVIDER=bedrock but no AWS credentials found "
                "(AWS_BEARER_TOKEN_BEDROCK / AWS_ACCESS_KEY_ID+AWS_SECRET_ACCESS_KEY / AWS_PROFILE). "
                "Set AWS credentials or unset ATHF_LLM_PROVIDER to auto-detect."
            )
    elif pinned == "ollama" and not probe():
        return (
            "ATHF_LLM_PROVIDER=ollama but Ollama is not reachable at localhost:11434. "
            "Start Ollama or unset ATHF_LLM_PROVIDER to auto-detect."
        )
    return None


def check_llm_path(ollama_probe=None, dotenv=None) -> CheckResult:
    """Check 3: at least one usable LLM path present (env keys, .env, or Ollama).

    If ATHF_LLM_PROVIDER is set it overrides auto-detection, so the pinned
    provider must have its own matching credential — otherwise the run fails
    with an "Error during LLM analysis" placeholder even though a *different*
    provider's key is present. That mismatch is checked first.
    """
    dotenv = dotenv if dotenv is not None else _load_dotenv()

    def resolve(name: str):
        # Exported shell env wins; .env is the fallback attendees are told to use.
        return os.environ.get(name) or dotenv.get(name)

    def where(name: str) -> str:
        return " (from .env)" if not os.environ.get(name) and dotenv.get(name) else ""

    raw_probe = ollama_probe if ollama_probe is not None else _ollama_reachable
    probe_result = None

    def probe():
        # Probe Ollama at most once per check so a mid-check state change can't
        # flip a pinned-provider PASS into a fallback FAIL.
        nonlocal probe_result
        if probe_result is None:
            probe_result = raw_probe()
        return probe_result

    pinned = (resolve("ATHF_LLM_PROVIDER") or "").strip().lower()
    if pinned:
        mismatch = _provider_credential_missing(pinned, resolve, probe)
        if mismatch is not None:
            return CheckResult("LLM access", FAIL, mismatch)

    if resolve("OPENAI_API_KEY"):
        return CheckResult("LLM access", PASS, f"OPENAI_API_KEY set{where('OPENAI_API_KEY')}")
    if resolve("ANTHROPIC_API_KEY"):
        return CheckResult("LLM access", PASS, f"ANTHROPIC_API_KEY set{where('ANTHROPIC_API_KEY')}")
    if resolve("AWS_BEARER_TOKEN_BEDROCK"):
        return CheckResult(
            "LLM access", PASS, f"AWS_BEARER_TOKEN_BEDROCK set{where('AWS_BEARER_TOKEN_BEDROCK')}"
        )
    if resolve("AWS_ACCESS_KEY_ID") and resolve("AWS_SECRET_ACCESS_KEY"):
        return CheckResult("LLM access", PASS, "AWS credentials set (Bedrock)")
    if resolve("AWS_PROFILE"):
        return CheckResult("LLM access", PASS, f"AWS_PROFILE set (Bedrock){where('AWS_PROFILE')}")
    if probe():
        return CheckResult("LLM access", PASS, "Ollama reachable at localhost:11434")
    return CheckResult(
        "LLM access",
        FAIL,
        "No LLM path. Set OPENAI_API_KEY / ANTHROPIC_API_KEY / AWS creds or AWS_PROFILE "
        "(in your shell or a .env file), or run Ollama.",
    )


def check_text_editor() -> CheckResult:
    """Check 4: a text editor is on PATH (WARN only)."""
    editors = ["code", "vim", "nvim", "nano", "emacs", "subl", "idea"]
    found = [e for e in editors if shutil.which(e)]
    if found:
        return CheckResult("Text editor", PASS, f"Found: {', '.join(found)}")
    return CheckResult("Text editor", WARN, "No known editor on PATH (code/vim/nano/...)")


def check_web_browser() -> CheckResult:
    """Check 5: a web browser is present (WARN only)."""
    system = platform.system()
    if system == "Darwin":
        apps = [
            "/Applications/Google Chrome.app",
            "/Applications/Firefox.app",
            "/Applications/Safari.app",
            "/Applications/Microsoft Edge.app",
            "/Applications/Chromium.app",
        ]
        found = [os.path.basename(a).replace(".app", "") for a in apps if os.path.exists(a)]
        # Safari always ships with macOS but the .app path check keeps this honest.
        if found:
            return CheckResult("Web browser", PASS, f"Found: {', '.join(found)}")
        return CheckResult("Web browser", WARN, "No browser found in /Applications")
    # Linux (and other): probe PATH
    browsers = ["google-chrome", "google-chrome-stable", "firefox", "chromium", "chromium-browser"]
    found = [b for b in browsers if shutil.which(b)]
    if found:
        return CheckResult("Web browser", PASS, f"Found: {', '.join(found)}")
    return CheckResult("Web browser", WARN, "No browser on PATH (chrome/firefox/chromium)")


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """Attempt a TCP connect. Returns True on success."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_splunk_reach(tcp_probe=None) -> CheckResult:
    """Check 6: network reach to workshop Splunk host (WARN only).

    Only probes when WORKSHOP_SPLUNK_HOST is set. Hosted deliveries (DEATHcon)
    hand attendees a web URL, so there is no default host worth warning about.
    """
    target = os.environ.get("WORKSHOP_SPLUNK_HOST")
    if not target:
        return CheckResult(
            "Splunk reach",
            PASS,
            "Skipped: log in at the Splunk URL you were given (set WORKSHOP_SPLUNK_HOST=host:port to test reach)",
        )
    if ":" in target:
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            host, port = target, 8089
    else:
        host, port = target, 8089
    probe = tcp_probe if tcp_probe is not None else _tcp_reachable
    if probe(host, port):
        return CheckResult("Splunk reach", PASS, f"Reached {host}:{port}")
    return CheckResult(
        "Splunk reach",
        WARN,
        f"Could not reach {host}:{port} (check the host/port you were given)",
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_all_checks() -> list:
    """Run every check and return a list of CheckResult."""
    return [
        check_python_version(),
        check_athf_installed(),
        check_llm_path(),
        check_text_editor(),
        check_web_browser(),
        check_splunk_reach(),
    ]


def has_hard_failure(results) -> bool:
    """True if any result is a hard FAIL."""
    return any(r.status == FAIL for r in results)


def render_text(results, use_color=None) -> str:
    """Render results as a colored checklist + summary string."""
    enabled = color_enabled() if use_color is None else use_color
    lines = []
    header = _colorize("Agentic Threat Hunting Workshop Preflight Check", "bold", enabled)
    lines.append(header)
    lines.append("=" * 40)
    for r in results:
        glyph, clr = _STATUS_GLYPH[r.status]
        mark = _colorize(glyph, clr, enabled)
        lines.append(f"{mark} {r.name}: {r.message}")
    lines.append("=" * 40)
    n_fail = sum(1 for r in results if r.status == FAIL)
    n_warn = sum(1 for r in results if r.status == WARN)
    n_pass = sum(1 for r in results if r.status == PASS)
    summary = f"{n_pass} passed, {n_warn} warnings, {n_fail} failed"
    if n_fail:
        summary = _colorize(summary + "  — FIX FAILURES BEFORE THE WORKSHOP", "red", enabled)
    else:
        summary = _colorize(summary + "  — you're ready!", "green", enabled)
    lines.append(summary)
    return "\n".join(lines)


def render_json(results) -> str:
    """Render results as JSON."""
    payload = {
        "checks": [
            {"name": r.name, "status": r.status, "message": r.message} for r in results
        ],
        "hard_failure": has_hard_failure(results),
    }
    return json.dumps(payload, indent=2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Workshop preflight validator")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = parser.parse_args(argv)

    results = run_all_checks()

    if args.json:
        print(render_json(results))
    else:
        print(render_text(results))

    return 1 if has_hard_failure(results) else 0


if __name__ == "__main__":
    sys.exit(main())
