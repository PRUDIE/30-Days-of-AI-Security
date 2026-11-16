# Day 3: What AI Systems Leak (Sensitive Information Disclosure)

*Prompt injection is how attackers get in. Today is about what they walk out with.*

Originally published on [CyberwithP](https://cyberwithprudie.substack.com), Nov 13, 2026.

**OWASP mapping:** LLM02:2026 Sensitive Information Disclosure, and LLM08:2026 Hidden Context Exposure (formerly LLM07:2025 System Prompt Leakage)

## Why sensitive information

On Day 1 I drew the architecture of an AI app and identified six trust boundaries. On Day 2 I looked at prompt injection, the number one risk on the OWASP Top 10 for AI applications. Today I dive into Sensitive Information Disclosure.

OWASP released the [Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) in August. Eight of the ten risks moved, but the top two stayed put: **LLM01 Prompt Injection** and **LLM02 Sensitive Information Disclosure**. That tells us something. Getting the model to misbehave is step one. Getting it to expose data is usually the actual goal.

Here's the part that clicked for me. In my work, a data leak usually means a broken API or a misconfigured bucket. In an AI app, the model can leak data **while working exactly as designed**. It just repeats what was put in front of it. So the real question isn't "can the model keep a secret?" It's "why did we hand it the secret in the first place?"

## The 6 terms that made it to my sticky notes today

**1: Sensitive information:** Anything that would hurt or expose something personal about someone if the wrong person saw it. Personal data (names, emails, card numbers, health records), secrets (API keys, passwords), and business data (source code, contracts, internal rules).

*Why it matters:* AI apps pull data from everywhere: databases, documents, tools, chat history. If the application never sorted what's sensitive, the model can't either.

**2: System prompt:** The hidden instructions the developer gives the model before the user says anything. Example: "You are HelpBot. Be polite. Never discuss refunds over $500."

*Why it matters:* Developers treat it like a safe but it isn't. The [2026 OWASP guidance](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) says to assume hidden context like the system prompt will be discovered. So no credentials, tokens or secrets should be placed in it, and never use it as your only control for who can do what.

**3: Hidden context exposure:** The model revealing anything the user wasn't meant to see: system instructions, tool definitions, retrieved policy text, internal rules. In the 2025 list this was LLM07 "System Prompt Leakage". The 2026 list renamed it **LLM08 Hidden Context Exposure** and widened it beyond the system prompt.

*Why it matters:* Assume hidden context will eventually be found. Then ask: what would an attacker learn from it? Limits, roles and credentials are a roadmap for the next attack.

**4: Memorization:** A model can remember pieces of its training data and repeat them word for word. Think of a kid who memorized a page of a book and recites it when you say the first line.

*Why it matters:* If personal data or secrets went into training or fine tuning, the right prompt can pull them back out. You can't patch a model the way you patch a server.

**5: Cross tenant leak:** One customer's data showing up in another customer's session. Tenant here means a customer account in a shared system.

*Why it matters:* This is broken access control, one of the famous bugs in web apps. In AI apps it often hides in the retrieval step (RAG), where the search returns the best match without checking who's asking.

**6: Data minimization:** Only give the model what it needs for this one request. Nothing "just in case".

*Why it matters:* It's the most reliable fix on this list. The model can't leak what it never saw.

## Where the leaks happen

I went back to my [Day 1 diagram](../day-01-architecture/) and asked one question at every arrow: *what sensitive data can cross here, and who ends up seeing it?* Every one of the six boundaries can leak data.

| # | Boundary | What leaks | What it looks like |
|---|----------|------------|--------------------|
| 1 | User → App | The user's own data, sent out | Staff paste source code or customer records into a public chatbot |
| 2 | App → Model | Everything placed in the context window | API keys, connection strings or internal rules sitting in the system prompt |
| 3 | Database → App | Documents the user shouldn't see | RAG returns another customer's file because retrieval ignores permissions |
| 4 | Model → Tools | Data sent to places it shouldn't go | An agent includes private data in a web request or email |
| 5 | Tools → Model | Raw tool results with extra fields | An order lookup returns the full card number and a database password |
| 6 | Model → User | Anything above, repeated back | "Sure, my instructions say..." |

Two real incidents made this concrete for me.

**Boundary 1: Samsung, 2023.** Weeks after Samsung's semiconductor division allowed ChatGPT, staff entered confidential information into it at least three times. Two cases involved source code, one involved meeting notes ([NHIMG breach analysis](https://nhimg.org/samsung-chatgpt-source-code-leak-2023-shadow-ai)). Nobody hacked anything. People were just trying to do their jobs faster. Samsung then restricted generative AI tools ([KED Global](https://amp.kedglobal.com/newsAmp/ked202305020022)).

**Boundary 6: ChatGPT, March 2023.** A bug in an open source Redis client let some users see titles from other users' chat history ([OpenAI](https://openai.com/index/march-20-chatgpt-outage)). The same bug may have exposed payment details, including the last four card digits, for 1.2% of ChatGPT Plus subscribers active in a nine-hour window ([The Hacker News](https://thehackernews.com/2023/03/openai-reveals-redis-bug-behind-chatgpt.html)).

That second one stuck with me. It wasn't a clever prompt attack. It was a caching bug, the kind of thing I'd find in any web app. **AI security is still application security**, which is exactly what Day 1 taught me.

## Day 3 build: a leak checker for the context window

If the context window is the new perimeter, I wanted something that checks it *before* the request goes to the model. So I built [`leakcheck.py`](leakcheck.py), a small Python script with no dependencies and no model calls. You hand it everything the app put together for one request: system prompt, retrieved documents, tool results and chat history. It asks three questions:

1. **Are there secrets in here?** API keys, tokens, private keys, passwords in connection strings.
2. **Is there personal data in here?** Emails, phone numbers, card numbers (with a Luhn checksum to cut false positives).
3. **Does this user own everything in here?** Every retrieved document is tagged with its tenant. If it doesn't match the person asking, it gets flagged.

It also does one more trick I recently learnt: a **canary token**. You plant a random string like `CANARY-7f3a91` in the system prompt. If that string ever shows up in a model response, your hidden context leaked. No guessing needed.

| Check | What it looks for |
|-------|-------------------|
| SECRET | AWS keys, `sk-` style API keys, GitHub tokens, JWTs, private key blocks, passwords in connection strings or assignments |
| PII | Emails, phone numbers, US SSNs, card numbers (Luhn-validated) |
| ACCESS | Retrieved documents whose `owner_tenant` doesn't match the requesting user |
| CANARY | The canary token from the system prompt showing up in the model response |

### Run it

Python 3, standard library only:

```bash
cd day-03-sensitive-info
python3 leakcheck.py sample_context.json
python3 leakcheck.py sample_context.json --redact   # also print a redacted copy
```

To check your own app, build a JSON file in the same shape as [`sample_context.json`](sample_context.json): the requesting user, an optional canary, each part of the context window with its source (and `owner_tenant` for retrieved docs), and optionally the model's response.

I tested it on a fake support bot request with problems planted at different boundaries (all values are fake test data). Here's the real output:

```
Requesting user: user_482 (tenant: acme)

[system] system_prompt: 1 issue(s)
    SECRET  AWS access key ID: AKIA****
[rag] kb/refund-policy.md: OK
[rag] kb/escalations-q3.md: 3 issue(s)
    PII     Email address: jane****
    PII     Phone number: +1 4****
    ACCESS  Belongs to tenant 'globex', not 'acme': drop this doc
[tool] lookup_order: 2 issue(s)
    SECRET  Password in connection string: post****
    PII     Card number: 4111****
[history] chat_history: OK

[output] model_response: CANARY FOUND - system prompt leaked

Total issues: 7
Verdict: BLOCK - fix before this goes to the model
```

Seven issues in one request, and the user only asked "where is my order?" Every one of them came from the app, not the user. That's the lesson in one screen.

Two design choices I made on purpose:

- **It masks what it finds.** A leak scanner that prints the full secret into your logs is now a leak. So this scanner shows only the first four characters and redacts the rest.
- **It exits with code 1 when it finds something.** That means you can drop it into a CI pipeline or a pre-send hook and fail the build.

The `--redact` flag prints a cleaned version, so you can see what the model *should* have received:

```
Order 1043 shipped. Paid with card [REDACTED:CARD_NUMBER]. DB: [REDACTED:PASSWORD_IN_CONNECTION_STRING]
```

**What it doesn't do:** Regex catches known patterns. It won't catch a secret it has no pattern for, and it can't judge whether a paragraph is confidential. It's a seatbelt, not a full DLP product. The real fix is still keeping the secret out of the prompt to begin with.

## How to stop the leaks

If you build AI apps, or test them like I do, these are the controls I'd check first. None of them depend on the model behaving.

**For builders**

- **No secrets in the system prompt.** Tools get credentials from a secrets manager at call time. The model only ever sees the tool's name.
- **Enforce access control before retrieval, not after.** Filter the vector search by the user's tenant and permissions. Never ask the model to "only show the user their own data".
- **Trim tool results.** Return the fields the task needs. An order status tool doesn't need the card number (least privilege).
- **Scan inputs and outputs.** A pre-send check like today's build, plus an output filter that doesn't rely on the model following instructions.
- **Treat prompts and logs as sensitive data.** They're full of user data. Limit who can read them and how long you keep them.
- **Keep personal data out of training and fine tuning sets,** or scrub it first. You can't easily unteach a model.
- **Give staff an approved AI tool.** The Samsung lesson: people will use AI anyway. Make the safe option the easy one.

**For testers**

- Ask the model to repeat, summarize, translate or debug its instructions.
- Plant a canary in the system prompt and check whether it ever comes back.
- Log in as tenant A and search for tenant B's documents through the chat.
- Read the raw tool responses, not just the final answer. That's where the extra fields hide.
- Check what the app logs, and who can read those logs.

## Key lessons from today

- **The model is not a vault.** Anything in the context window can come out. If you'd be unhappy seeing it in a response, it doesn't belong in the prompt.
- **Most AI leaks are old bugs in new places.** Broken access control, secrets in config, over sharing APIs, a caching bug. These aren't new vulnerabilities.
- **Controls belong outside the model.** "Please don't reveal this" is a request, not a control. Real controls are filters, permissions and scanners that work even when the model gets fooled.

Next up is number three on the 2026 list: **LLM03 Excessive Agency**, what happens when an AI agent has more permissions than it needs. If Day 3 was about what the model can *say*, Day 4 is about what it can *do*.

See you on Day 4!

## Sources

- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [OWASP LLM07:2025 System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/) (2025 edition, now LLM08 Hidden Context Exposure)
- [OWASP's 2026 LLM Top 10 (Cloud Security Alliance research note)](https://labs.cloudsecurityalliance.org/research/csa-research-note-owasp-genai-top10-2026-agent-control-stand/)
- [Samsung ChatGPT source code leak, 2023 (NHIMG)](https://nhimg.org/samsung-chatgpt-source-code-leak-2023-shadow-ai)
- [Samsung bans ChatGPT and other AI tools (KED Global)](https://amp.kedglobal.com/newsAmp/ked202305020022)
- [March 20 ChatGPT outage: here's what happened (OpenAI)](https://openai.com/index/march-20-chatgpt-outage)
- [OpenAI reveals Redis bug behind ChatGPT data exposure (The Hacker News)](https://thehackernews.com/2023/03/openai-reveals-redis-bug-behind-chatgpt.html)
