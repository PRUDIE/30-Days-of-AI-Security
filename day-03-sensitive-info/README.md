# leakcheck: a pre-flight scanner for LLM context windows

[![day-03 leakcheck](https://github.com/PRUDIE/30-Days-of-AI-Security/actions/workflows/day-03-leakcheck.yml/badge.svg)](https://github.com/PRUDIE/30-Days-of-AI-Security/actions/workflows/day-03-leakcheck.yml)

Day 3 of [30 Days of Building in AI Security](../README.md). Write-up: [Day 3: What AI Systems Leak](https://cyberwithprudie.substack.com/p/day-3-what-ai-systems-leak-sensitive).

**OWASP Top 10 for LLM Applications 2026:** [LLM02 Sensitive Information Disclosure](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), LLM08 Hidden Context Exposure

## Why

An LLM app can leak data while working exactly as designed. The model repeats whatever ends up in its context window, and most of that is put there by the app, not the user: the system prompt, retrieved documents, tool results, chat history.

`leakcheck` runs on that assembled request **before** it is sent to the model and answers three questions:

1. Are there secrets in here?
2. Is there personal data in here?
3. Does the requesting user own every retrieved document?

It also checks the model's response for a canary token planted in the system prompt, which proves hidden context leaked.

## Quick start

Python 3.10+, standard library only.

```bash
cd day-03-sensitive-info
python3 leakcheck.py samples/leaky_request.json
```

```
Requesting user: user_482 (tenant: acme)

[system] system_prompt: 1 issue(s)
    SECRET  AWS access key ID: AKIA****
[rag] kb/refund-policy.md: OK
[rag] kb/escalations-q3.md: 3 issue(s)
    PII     Email address: jane****
    PII     Phone number: +1 4****
    ACCESS  owned by tenant 'globex', requester is 'acme': drop before sending
[tool] lookup_order: 2 issue(s)
    SECRET  Password in connection string: post****
    PII     Card number: 4111****
[history] chat_history: OK
[output] model_response: 1 issue(s)
    CANARY  system prompt canary found in response: CANA****

Total issues: 7
Verdict: BLOCK - fix before this goes to the model
```

The customer only asked "where is my order?" Every one of those seven issues came from the app.

[`samples/clean_request.json`](samples/clean_request.json) is the same request after the fixes (credential moved out of the prompt, the other tenant's document filtered out, the tool result trimmed). It passes:

```bash
python3 leakcheck.py samples/clean_request.json   # Verdict: PASS, exit 0
```

## Usage

```
leakcheck REQUEST [--redact] [--json] [--version]
```

| Flag | What it does |
|------|--------------|
| `--redact` | Also prints a redacted copy of each flagged part, i.e. what the model should have received |
| `--json` | Machine-readable output for pipelines |

| Exit code | Meaning |
|-----------|---------|
| `0` | No findings |
| `1` | Findings, block the request |
| `2` | Bad input (missing file, invalid JSON, missing fields) |

```bash
$ python3 leakcheck.py samples/leaky_request.json --redact | grep redacted
    redacted: Order 1043 shipped. Paid with card [REDACTED:CARD_NUMBER]. DB: [REDACTED:PASSWORD_IN_CONNECTION_STRING]
```

## Request format

One JSON file per model call. See [`samples/leaky_request.json`](samples/leaky_request.json).

```json
{
  "requesting_user": { "id": "user_482", "tenant": "acme" },
  "canary": "CANARY-7f3a91",
  "context_parts": [
    { "source": "system", "name": "system_prompt", "content": "..." },
    { "source": "rag", "name": "kb/refund-policy.md", "owner_tenant": "acme", "content": "..." },
    { "source": "tool", "name": "lookup_order", "content": "..." }
  ],
  "model_response": "..."
}
```

`canary`, `owner_tenant` and `model_response` are optional. Without `owner_tenant` a document is not tenant-checked.

## Using it from code

```python
from leakcheck import check_request

findings = check_request(request)   # same shape as the JSON file
if findings:
    raise BlockedRequest([f.label for f in findings])
```

Each finding is a `Finding(kind, label, location, preview)`, where `preview` is already masked.

## What it checks

| Kind | Detects |
|------|---------|
| `SECRET` | AWS access key IDs, `sk-` API keys, GitHub tokens, JWTs, private key headers, passwords in connection strings, `password=` style assignments |
| `PII` | Email addresses, formatted phone numbers, US SSNs, card numbers (Luhn-validated) |
| `ACCESS` | Retrieved documents whose `owner_tenant` differs from the requester's tenant |
| `CANARY` | The system prompt canary appearing in `model_response` |

## Design decisions

- **Findings are always masked.** A leak scanner that writes the full secret into CI logs is now the leak. Output shows the first four characters at most, and there's a test that fails if a full value ever appears in a report.
- **Fail closed.** Any finding exits `1`, so it can gate a CI job or a pre-send hook without extra glue.
- **Precision over recall on PII.** Card numbers must pass Luhn, and phone numbers need separators, so order numbers and IDs don't trigger it. A noisy scanner gets switched off.
- **Tenant check is metadata, not content.** Content scanning can't tell you a clean-looking document belongs to another customer. Only ownership metadata can, so retrieval should attach it.
- **No dependencies, no model calls.** It's deterministic and runs anywhere, including in the request path.

## Limitations

- Pattern matching only finds what it has patterns for. It won't catch an unknown secret format, or judge that a paragraph is confidential.
- Phone and SSN patterns are US-centric.
- It inspects the request you give it. It can't see data your app never logged.
- It's a seatbelt, not DLP. The real fix is keeping secrets and other tenants' data out of the prompt in the first place.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

21 tests cover detection, known false positives, redaction, tenant and canary checks, exit codes, and masking. CI runs them on Python 3.10, 3.12 and 3.13.

## Layout

```
day-03-sensitive-info/
  leakcheck.py              the scanner (CLI + importable)
  samples/
    leaky_request.json      fake request with leaks planted at several trust boundaries
    clean_request.json      the same request after the fixes
  tests/
    test_leakcheck.py
```

All sample values are fake. The AWS key is AWS's documented example key and the card is a standard test number.
