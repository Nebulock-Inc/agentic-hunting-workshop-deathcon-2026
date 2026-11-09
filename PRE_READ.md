# Pre-Read — Before You Press Play

> ~10 minutes. Read this once before the video so Module 1 starts hunting at minute one instead of explaining vocabulary. You don't need to memorize anything — you need the ideas below to feel familiar when they come up on screen. **Never hunted before? Start with Idea 0.**

---

## What you're walking into

Sixty minutes of video, ninety minutes of hands-on, at your own pace. You'll hunt a real supply-chain compromise inside a fake company (Sudo Shipping) against a Splunk instance we've pre-seeded. It's all synthetic — no real customer data, no real IOCs. You'll use **ATHF** (the Agentic Threat Hunting Framework, open source, `pip install agentic-threat-hunting-framework`) and your own LLM provider.

You'll leave with **six documented hunts in your own workspace.** That's the deal: not slides, actual reusable hunt records.

Come with: a laptop, Python 3.11+, ATHF installed, an LLM API key (any provider — see the providers folder), your MCP client pointed at `athf-mcp` (`providers/mcp.md`), and the preflight script run green. The first slide of the video is the checklist.

---

## Idea 0 — Hunting vs. detection, in three sentences

**No alert fired.** A detection waits for something it already knows to look for; a hunt assumes the adversary is already in and goes looking with a *hypothesis* — "if an attacker did X here, the evidence would be Y in Z." You run the query, triage what comes back, and write down what you found *and* what you ruled out — a hypothesis that came back empty is still a result, because the next hunter now knows where not to look.

That's the whole loop. Everything below is how to make it repeatable, and then how to let an agent help.

---

## Idea 1 — The Five Levels of Agentic Hunting (L0–L4)

This is the spine of the day. Each module unlocks one level. It's a **stack, not a ladder** — you don't abandon lower levels, you build on them.

- **L0 — Ad-hoc.** Hunting in a search bar. Queries live in browser tabs; when you close the laptop, the hunt is gone. Where most of the field lives today.
- **L1 — Documented.** You write the hunt down — hypothesis, scope, what you ruled out — so it survives you and someone else can re-run it.
- **L2 — Searchable.** You find the *next* hunt by reusing the *behavior* documented in the last one, not the indicators. Behavior transfers across hosts and time; indicators don't.
- **L3 — Generative.** An AI agent reads threat intel and hands you hypotheses you wouldn't have written alone. You still decide what's real.
- **L4 — Agentic.** The agent has tools. It reads your hunt repo, tells you which parts of the kill chain you *haven't* covered, and proposes the next query.

The punchline of the whole workshop: at L4, the agent can only find your blind spots because L1–L3 wrote the hunts down. **Memory is the edge.** (ATHF's docs number these L0–L4 — five levels, zero-indexed. Same thing as "five levels.")

## Idea 2 — LOCK: the shape of a hunt

Every hunt you write follows **LOCK**:

- **L — Learn:** what triggered this hunt? Intel, an anomaly, a coverage gap.
- **O — Observe:** the hypothesis and the query — what behavior would this actor leave behind?
- **C — Check:** run it, triage the hits, rule things out.
- **K — Keep:** the finding, the exact query, the verdict, and the branches you ruled out.

One thing to internalize now: **a ruled-out hypothesis is a finding.** The hunt that found nothing still tells the next hunter where not to look. Dead ends get written down too.

## Idea 3 — ABLE: how you scope a hypothesis

ABLE is the vocabulary that goes *inside* the Observe step. A good hypothesis names four things:

- **A — Actor:** who (real or hypothesized)?
- **B — Behavior:** what do they *do*? (Not what tool — what action.)
- **L — Location:** where in your environment would it show up?
- **E — Evidence:** what data proves or disproves it?

Example you'll actually write on day one: *"CRON GOBLIN (actor) uses a package-manager post-install script to spawn a shell that runs recon (behavior) on developer workstations (location); evidence is a `node → cmd.exe → whoami` process chain in EDR events (evidence)."* If you can write that sentence, you can hunt it.

## Idea 4 — Behavior over indicators

The core hunting mindset. Think of the Pyramid of Pain: hashes and IPs are trivial for an adversary to change; TTPs are expensive. The compromise you'll hunt uses a **signed** binary with a **clean hash** and **no CVE** — so indicator-based detection is useless by design. The only way in is behavior: the *shape* of what the adversary does, which stays constant even when the hash, domain, and hostname all change.

Everything you find will be behavioral. When you write hunts, describe the behavior — that's the part that transfers to the next host, the next campaign, the next module.

---

## What the ATHF workspace looks like

When you run `athf init`, you get a small, legible workspace:

- **`hunts/`** — your hunt records live here as Markdown (`H-XXXX.md`). This directory *is* your memory. It's what `athf similar` searches and what the MCP coverage tools reason over.
- **`AGENTS.md`** — context that tells an AI agent how your workspace is shaped and how to behave in it.
- **`.athf/`** — working state: research docs (`.athf/research/`), session logs (`.athf/session.log` in workshop mode), and MCP logs.

A handful of commands you'll use (don't memorize — you'll have the labs):

- `athf hunt new …` — scaffold a hunt (L1).
- `athf hunt list` / `athf hunt coverage` — see what you've done and what you haven't (L2).
- `athf similar --hunt H-XXXX` — find related prior hunts (L2).
- `athf research new --topic "…"` — generate research from intel (L3).
- `athf agent run … --workshop` — run an agent with a token cap for shared-classroom use (L3/L4).

---

## One mindset note

You'll hit walls on purpose. Every module has a designed moment where the manual approach dead-ends and an ATHF capability unsticks it. That's not you failing — that's the lesson. When you're stuck for more than a few minutes, flag a staffer; we have tiered hints and using them keeps the whole room on pace.

During the labs you'll work from the **Lab Workbook** — each lab leads with a guiding
question, then the query to run. Don't worry about capturing the answers in the moment:
after the workshop we release the **Complete Answer Key** (expected findings,
model answers, and the dead-ends to watch for) so you can replay any module on your own.
Hunt first, self-study later.

See you there. Come ready to hunt.
