# P9 — AI / LLM application security (OWASP LLM Top 10 2025)

Applies when the app calls an LLM (chatbot, RAG, agent, summarizer, copilot). These are
fast-growing, frequently-missed risks — a real differentiator for an audit.

## OWASP LLM Top 10 (2025) checklist

| # | Risk | Check |
|---|---|---|
| LLM01 | Prompt Injection | user input (direct) or retrieved content (indirect/RAG) overriding instructions or producing attacker-controlled output |
| LLM02 | Sensitive Information Disclosure | model leaking secrets/PII/system prompt/other users' data |
| LLM03 | Supply Chain | vulnerable model libs, untrusted models/plugins, poisoned datasets |
| LLM04 | Data & Model Poisoning | training/fine-tune/RAG-store poisoning |
| LLM05 | Improper Output Handling | **LLM output rendered/executed without sanitization** → XSS, SQLi, SSRF, RCE |
| LLM06 | Excessive Agency | tools/functions the LLM can call with too much privilege or no confirmation |
| LLM07 | System Prompt Leakage | secrets/logic embedded in the system prompt, extractable |
| LLM08 | Vector/Embedding Weaknesses | RAG retrieval of unauthorized docs, cross-tenant leakage |
| LLM09 | Misinformation | over-trust in unverified model output for decisions |
| LLM10 | Unbounded Consumption | no token/cost/rate limits → cost-exhaustion / DoW (denial-of-wallet) |

> Also map **agent**-specific risks to the **OWASP Top 10 for Agentic Applications (2026)**
> and the **OWASP Agentic AI — Threats & Mitigations** guide when the app is an autonomous
> agent (plans, calls tools, has memory). Its threat taxonomy: Agent Design · Agent Memory ·
> Planning & Autonomy · Tool Use · Deployment & Operations. See §Agentic and §MCP below.

## Highest-frequency findings (check these first)

1. **Improper output handling (LLM05) — the big one.** If the app renders LLM output as
   HTML/markdown without sanitization (`marked.parse()` / `innerHTML` / `v-html` with no
   DOMPurify), an attacker who influences the output (directly, or **indirectly via a
   poisoned RAG document**) gets stored/reflected **XSS**. Combined with a missing
   `HttpOnly` cookie → full account takeover. *(This is exactly the class in the kit's
   example reports — trace LLM response → render sink in the client code.)*
   Fix: `DOMPurify.sanitize(marked.parse(x))`, strict CSP, treat model output as
   untrusted user input everywhere (also SQL/shell/URL contexts, not just HTML).
2. **Indirect prompt injection via RAG.** A malicious instruction hidden in an uploaded
   document affects every user who queries that document — no interaction needed. Check
   whether retrieved content is trusted/executed and whether uploads are sanitized.
3. **Excessive agency (LLM06).** LLM-invoked tools that read/write DB, send email, make
   HTTP requests (SSRF), or run code — need allowlists, per-tool authz, human
   confirmation for high-impact actions, and least privilege.
4. **Unbounded consumption (LLM10).** No per-user token/request caps → an attacker runs
   up the API bill. Check rate limits, max tokens, and monitoring.
5. **System prompt / model disclosure.** Health/debug endpoints leaking provider + model
   names (`gpt-4o-mini`, etc.) give attackers targeting info; system prompts containing
   secrets or bypassable guardrails.

## Indirect prompt-injection vectors (check every untrusted input path)

Direct injection (user types the attack) is the obvious case; **indirect** injection is the
2025–2026 growth area — the payload rides in on content the model later reads. Trace every
source that reaches the prompt/context and confirm it is treated as untrusted data, not
instructions:

- **RAG / retrieved documents** — a malicious instruction hidden in an uploaded/indexed doc
  fires for *every* user who queries it. No interaction needed.
- **Tool / function outputs** — an API/DB/webpage the agent fetches returns attacker text
  that the model obeys (feeds §Agentic tool-injection).
- **Multimodal** — instructions embedded in an image, PDF, or screenshot the model OCRs/reads.
- **Invisible / smuggled text** — Unicode **tag** characters (U+E0000–U+E007F "ASCII
  smuggling"), zero-width/BiDi chars, white-on-white or 1px HTML, HTML comments, `alt`/`title`
  attributes. Flag any pipeline that ingests HTML/rich text without stripping these.
- **Filenames, metadata, email subjects, calendar invites** — any field the agent summarizes.

Fix: strong system/user/tool **message-role separation**, spotlighting/delimiting untrusted
content, input **and** output guardrails, stripping invisible Unicode, and never letting
retrieved/tool text change the agent's authorization or tool scope.

## §Agentic — autonomous-agent security (OWASP Agentic Apps 2026)

When the target is an **agent** (plans multi-step, calls tools, keeps memory), add:

- **Goal / instruction hijack** — untrusted content (RAG, tool output, a webpage) rewrites the
  agent's objective. Agents can't reliably tell legitimate instructions from injected ones →
  isolate task instructions from ingested data; re-assert the goal from a trusted channel.
- **Excessive agency / tool over-scope (LLM06)** — tools with broad privilege (DB write, email,
  shell, HTTP, payments) and no per-action authz. Require **per-action authorization via a
  central policy engine**, least-privilege tool credentials, and **human-in-the-loop for
  high-impact / irreversible actions**.
- **Memory poisoning** — persistent injection written into the agent's long-term memory / vector
  store that re-triggers on later runs or leaks across tenants. Separate the agent's session
  from durable memory; erase/validate between tasks; scope memory per user/tenant.
- **Tool-call / parameter injection** — model-generated arguments flow unsanitized into a sink
  (SQL, shell, URL, file path). Validate tool arguments server-side exactly like user input.
- **Multi-agent trust** — one agent trusting another's output without verification; privilege
  bleed across agents. Isolate agent identities/contexts; authorize cross-agent calls.
- **Autonomy loops / cost** — runaway plan-execute loops (ties to LLM10). Cap steps, tokens,
  wall-clock, and spend; monitor.

## §MCP — Model Context Protocol server/client security

MCP is the dominant 2025–2026 way to give agents tools; it has its own risk class (**OWASP
MCP Top 10, 2025**). If the app is an MCP host/client or ships an MCP server, check:

- **Tool poisoning** — malicious instructions hidden in a **tool description / metadata** that
  the model reads but the user never sees. Most clients accept server-provided metadata without
  validation. Review every tool description as untrusted; surface it to the user/approver.
- **Rug-pull tool definitions** — a tool approved once, then silently updated to malicious
  behavior with no re-approval. Pin/verify tool definitions; alert on description/schema change.
- **Confused deputy / token passthrough** — the MCP server holds broad OAuth tokens/credentials
  and acts on behalf of any caller. Scope tokens per user, don't pass tokens through blindly.
- **MCP server supply chain** — untrusted third-party MCP servers = arbitrary code + data
  egress. Treat installing an MCP server like adding a dependency (provenance, review, pin).
- **Prompt injection via tool results** — server returns attacker text the agent obeys (§Agentic).
- **Over-broad permissions / no sandboxing** — tool execution not sandboxed or rate-limited.

## How to test safely

- Prefer **code review** — a live LLM call costs money and may be rate-limited. Read the
  client render path, the server prompt-assembly/tool-dispatch code, MCP tool definitions, and
  the memory/RAG access-control layer.
- If a live probe is needed and authorized: a single benign request checking whether
  `<img src=x onerror=...>` in the model's output renders as HTML or escaped text. Never
  attempt to actually steal data.
- Check `references/vuln-catalog.md` §LLM for the full class list.

## Deliverable

Findings mapped to LLM01–LLM10 (+ OWASP Agentic Apps 2026 / MCP Top 10 where relevant) +
CWE (LLM05→CWE-79/89/78 depending on sink), with the render/tool-dispatch/tool-definition
`file:line` and the sanitization/authz/least-privilege/limit fix.
