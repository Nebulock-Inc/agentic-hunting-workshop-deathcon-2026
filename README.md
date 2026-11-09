# Agentic Threat Hunting — DEATHcon 2026

**Hunt with memory. Hunt with agents.**

This repo is the home for the DEATHcon 2026 workshop. The most up-to-date information will be here: if something in the video or a PDF disagrees with this repo, the repo wins.

The workshop is a **60-minute video** plus a **~90-minute self-paced lab**. You hunt a seeded supply-chain compromise in Splunk and climb the ATHF **Five Levels of Agentic Hunting**: L0 Ad-hoc, L1 Documented, L2 Searchable, L3 Generative, L4 Agentic. You leave with your own workspace of documented hunts.

**Start here:** [`DEATHcon-2026-Materials-Guide.pdf`](DEATHcon-2026-Materials-Guide.pdf). It covers what you get, what to install, and how to get unstuck.

## What's here

| Path | What it is |
|------|------------|
| `DEATHcon-2026-Materials-Guide.pdf` | Everything you need to get set up, in one PDF |
| `PRE_READ.md` | 10-minute primer: hunting vs. detection, the levels, LOCK, ABLE |
| `slides/` | The full deck, as PDF and as a self-contained HTML file (download it, open it in a browser) |
| `labs/lab-workbook.pdf` | Every lab's guiding questions and queries. No answers. |
| `labs/complete-answer-key.pdf` | Full solutions. It's here on purpose: ask your repo first, then check. |
| `commands/` | Every ATHF command from the labs, as `.sh` and `.ps1`. Run the file; don't retype it. |
| `templates/` | Hunt files for H-0004 … H-0009 if you'd rather not type flags |
| `queries/` | Every SPL query from each lab, in order. Copy from here, not the PDF. |
| `providers/` | One `.env.example` per LLM provider, a smoke test, and `mcp.md` for MCP setup |
| `preflight/validate.py` | The setup checker. All green means you're ready. |

## Setup (pause point 0)

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install 'agentic-threat-hunting-framework[all]'
cp providers/<your-provider>.env.example .env          # paste your API key
python preflight/validate.py                           # all green = ready
```

Then wire up your MCP client now, not in Module 4: [`providers/mcp.md`](providers/mcp.md).

You need Python 3.8+ (3.11+ recommended), one LLM API key (OpenAI or Anthropic is the supported path; Bedrock, Ollama, and OpenAI-compatible endpoints also work), an MCP client for Modules 4–5, and basic SPL.

## Splunk

- Log in with the URL and credentials DEATHcon gave you. Read-only.
- All data is in `index=thrunt`.
- **Time range: All time. Every search. Every time.** The data is fixed at Oct 23 – Oct 30, 2026 and doesn't move with the calendar, so "Last 24 hours" returns nothing.

## Stuck?

Ask in the **workshop Discord channel**. Bring your H-0009 and whatever stumped you.

## The scenario

The victim, **Sudo Shipping**, and the attacker, **CRON GOBLIN**, are fictional. Every host, domain, IP, and event in the dataset is synthetic. Nothing here describes a real intrusion or a real customer.

**Framework:** [Agentic Threat Hunting Framework (ATHF)](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework), open source.

## Who built this

Built and run by **Sydney Marrone**. Kudos to **Eric Brown** and **Jarrett Polcari** for helping build the data and infrastructure, and to **Josh Hines**, **Alex Hurtado**, and **Brandon Schwartz** for running every lab cold before you did.

## License

MIT. See [LICENSE](LICENSE).
