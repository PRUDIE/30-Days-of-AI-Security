#!/usr/bin/env python3
"""
leakcheck.py - Day 3 of 30 Days of Building in AI Security

A pre-flight check for the context window. Before an AI app sends a prompt to
the model, run everything it assembled (system prompt, retrieved docs, tool
results, chat history) through this script and ask three questions:

  1. Are there secrets in here?             (API keys, passwords, private keys)
  2. Is there personal data in here?        (emails, phone numbers, card numbers)
  3. Does this user own everything in here? (cross-user / cross-tenant leaks)

It can also check a model response for a canary token planted in the system
prompt, which tells you the system prompt (hidden context) leaked.

No dependencies. No model calls. Standard library only.

Usage:
  python3 leakcheck.py sample_context.json
  python3 leakcheck.py sample_context.json --redact    # also print the safe version
"""

import argparse
import json
import re
import sys

# --- 1. Secret patterns -------------------------------------------------------
SECRET_PATTERNS = {
    "AWS access key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Generic API key (sk-...)": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Password in connection string": re.compile(r"\b[a-z]+://[^\s:/@]+:[^\s@]+@[^\s]+", re.I),
    "Password assignment": re.compile(r"\b(password|passwd|pwd|secret)\s*[:=]\s*\S+", re.I),
}

# --- 2. PII patterns ----------------------------------------------------------
PII_PATTERNS = {
    "Email address": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "Phone number": re.compile(r"(?<!\d)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"),
    "US SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Card number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}


def luhn_ok(number: str) -> bool:
    """Card numbers pass the Luhn checksum. Cuts down false positives."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask(value: str) -> str:
    """Show just enough to recognize the finding, never the whole secret."""
    value = value.strip()
    return value[:4] + "****" if len(value) > 8 else "****"


def scan_text(text: str):
    findings = []
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            findings.append(("SECRET", label, m.group(0)))
    for label, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            if label == "Card number" and not luhn_ok(m.group(0)):
                continue
            findings.append(("PII", label, m.group(0)))
    return findings


def redact(text: str) -> str:
    for label, pattern in {**SECRET_PATTERNS, **PII_PATTERNS}.items():
        tag = "[REDACTED:" + label.upper().replace(" ", "_") + "]"
        if label == "Card number":
            text = pattern.sub(lambda m: tag if luhn_ok(m.group(0)) else m.group(0), text)
        else:
            text = pattern.sub(tag, text)
    return text


def main():
    ap = argparse.ArgumentParser(description="Scan an assembled context window for leaks.")
    ap.add_argument("context_file", help="JSON file describing the request (see sample_context.json)")
    ap.add_argument("--redact", action="store_true", help="print a redacted copy of each part")
    args = ap.parse_args()

    with open(args.context_file) as f:
        ctx = json.load(f)

    user = ctx["requesting_user"]
    canary = ctx.get("canary")
    parts = ctx["context_parts"]
    total = 0

    print(f"Requesting user: {user['id']} (tenant: {user['tenant']})\n")

    for part in parts:
        name, text = part["name"], part["content"]
        issues = [(kind, label, mask(val)) for kind, label, val in scan_text(text)]

        # --- 3. Ownership check: retrieved docs must belong to this user's tenant
        owner = part.get("owner_tenant")
        if owner and owner != user["tenant"]:
            issues.append(("ACCESS", f"Belongs to tenant '{owner}', not '{user['tenant']}'", "drop this doc"))

        status = "OK" if not issues else f"{len(issues)} issue(s)"
        print(f"[{part['source']}] {name}: {status}")
        for kind, label, detail in issues:
            print(f"    {kind:<7} {label}: {detail}")
        if args.redact and issues:
            print("    redacted ->", redact(text)[:160].replace("\n", " "))
        total += len(issues)

    # --- Canary check on the model's response (hidden context exposure)
    response = ctx.get("model_response")
    if canary and response is not None:
        leaked = canary in response
        print(f"\n[output] model_response: {'CANARY FOUND - system prompt leaked' if leaked else 'no canary'}")
        total += int(leaked)

    print(f"\nTotal issues: {total}")
    print("Verdict:", "BLOCK - fix before this goes to the model" if total else "PASS")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
