# MCP client setup (do this during pause point 0, not in Module 4)

Module 4 and Module 5 talk to your hunt repo through `athf-mcp-server`. Wire it up now, while you're in setup mode. Takes two minutes; debugging it mid-lab eats the whole module.

## 1. Install the MCP extra

```bash
pip install 'agentic-threat-hunting-framework[mcp]'     # already included if you installed [all]
```

## 2. Point your client at your workspace

`ATHF_WORKSPACE` is the directory where you ran `athf init` (the one with `hunts/` in it).

**Claude Code** (supported default) — add to `~/.claude/mcp-servers.json`:

```json
{
  "athf": {
    "command": "athf-mcp",
    "env": { "ATHF_WORKSPACE": "/absolute/path/to/your/workshop-workspace" }
  }
}
```

Or from the shell, in your workspace directory:

```bash
claude mcp add athf -- athf-mcp
```

**Cursor / Copilot / other MCP clients:** same command (`athf-mcp`) and the same `ATHF_WORKSPACE` env var, in your client's MCP config UI. The stdio transport opens no socket.

## 3. Confirm the handshake

Start your client in the workspace directory and ask:

```text
What have I hunted before?
```

If it answers with your H-0004…H-0009 hunts, you're done. The agent now has `search_hunts_by_text`, `find_similar_hunts`, `list_coverage_gaps`, `propose_next_query`, and `generate_hunt_hypothesis`.

## If it doesn't connect

- `which athf-mcp` must resolve inside the same venv your client launches from. Activate the venv before starting the client, or put the venv's absolute `bin/athf-mcp` in `command`.
- `ATHF_WORKSPACE` must be absolute, and must contain `hunts/`.
- Still stuck? Every Module 4 step has a CLI fallback in the workbook (`athf similar`, `athf hunt coverage --detailed`) — same data, no agent. Keep hunting and bring the error to the live Q&A.

Reference: [ATHF README → MCP Server](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework#mcp-server-new-in-v0110).
