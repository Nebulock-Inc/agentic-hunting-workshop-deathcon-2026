# LLM Providers for the Workshop

ATHF is **vendor-neutral** — it supports all five providers below, and the labs work
identically whichever you bring. For this workshop, **OpenAI and Anthropic are the
supported day-of path** (smoothest setup, what staff run and can help with); Bedrock,
Ollama, and OpenAI-compatible endpoints also work if that's what you already have.

## How ATHF picks a provider

`athf` resolves your provider in this order (first match wins):

1. Explicit config in `.athfconfig.yaml` (`llm:` section)
2. Env vars `ATHF_LLM_PROVIDER` + `ATHF_LLM_MODEL`
3. **Auto-detection** by which API key is present:
   | Key present | Provider used | Default model |
   |-------------|---------------|---------------|
   | `ANTHROPIC_API_KEY` | LiteLLM (Anthropic) | `anthropic/claude-sonnet-4-6` |
   | `OPENAI_API_KEY` | OpenAI-compatible | `gpt-4o` |
   | `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` | Bedrock | `us.anthropic.claude-sonnet-4-6` |
   | Local Ollama running | Ollama | `llama3` |

Set `ATHF_LLM_MODEL` any time you want a specific model regardless of provider.

## Pick your file

> Simplest path: `pip install 'agentic-threat-hunting-framework[all]'` covers every provider **plus** the
> `similar` command's scikit-learn dependency in one install. The per-provider
> extras below are the minimal alternative — but pair them with `agentic-threat-hunting-framework[similarity]`
> or you'll hit a scikit-learn error in Module 2.

Copy the matching `.env.example` to `.env` in your hunt workspace and fill in your key:

| You have… | Use | Install extra |
|-----------|-----|---------------|
| An Anthropic API key | `anthropic.env.example` | `pip install 'agentic-threat-hunting-framework[litellm]'` |
| An OpenAI API key | `openai.env.example` | `pip install 'agentic-threat-hunting-framework[openai]'` |
| AWS creds w/ Bedrock access | `bedrock.env.example` | `pip install 'agentic-threat-hunting-framework[bedrock]'` |
| A local Ollama install | `ollama.env.example` | (none — just run `ollama serve`) |
| A self-hosted / proxy OpenAI-compatible endpoint | `openai-compatible.env.example` | `pip install 'agentic-threat-hunting-framework[openai]'` |

## MCP client (Modules 4–5)

See [`mcp.md`](mcp.md) — point Claude Code (or your MCP client) at `athf-mcp` during setup, not in Module 4.

## Verify before you arrive

From the repo root:

```bash
cp providers/anthropic.env.example .env   # or whichever matches you
# edit .env, add your key
./providers/smoke.sh                      # confirms the provider answers a 1-token prompt
```

A green smoke check is the difference between hunting at minute 1 and debugging
env vars while the room moves on. The **workshop uses `--workshop` mode**, which
caps token spend per call and logs to `.athf/session.log` — so a shared classroom
budget stays bounded no matter which provider you bring.

## Cost note

Labs are sized for **cents, not dollars**, per attendee. `--workshop` caps each
call at ~1024 output tokens. Ollama is free (local). If you're cost-sensitive,
Ollama or a small OpenAI model is plenty for every lab.
