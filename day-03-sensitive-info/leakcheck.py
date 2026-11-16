#!/usr/bin/env python3
"""leakcheck: pre-flight scanner for an LLM request's context window.

Run it on everything an app has assembled for one model call (system prompt,
retrieved documents, tool results, chat history) before the call is made.
It reports:

    SECRET  credentials and keys
    PII     personal data
    ACCESS  retrieved documents owned by a different tenant than the requester
    CANARY  a canary token from the system prompt appearing in the model response

Findings are masked in all output. Exit codes: 0 clean, 1 findings, 2 bad input.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Iterable

__version__ = "0.2.0"

EXIT_CLEAN, EXIT_FINDINGS, EXIT_BAD_INPUT = 0, 1, 2

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS access key ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "API key (sk- prefix)": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Password in connection string": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@]+@\S+", re.I),
    "Password assignment": re.compile(r"\b(?:password|passwd|pwd|secret)\s*[:=]\s*\S+", re.I),
}

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "Email address": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    # Separators are required so order numbers and IDs don't match.
    "Phone number": re.compile(r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"),
    "US SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "Card number": re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
}


@dataclass(frozen=True)
class Finding:
    kind: str       # SECRET | PII | ACCESS | CANARY
    label: str      # what was found
    location: str   # which part of the request
    preview: str    # masked value, never the full thing


class InputError(ValueError):
    """The request file is missing or malformed."""


def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        checksum += d
    return checksum % 10 == 0


def mask(value: str, keep: int = 4) -> str:
    value = value.strip()
    return value[:keep] + "****" if len(value) > keep * 2 else "****"


def _matches(text: str) -> Iterable[tuple[str, str, re.Match[str]]]:
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            yield "SECRET", label, m
    for label, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            if label == "Card number" and not luhn_valid(m.group()):
                continue
            yield "PII", label, m


def scan_text(text: str, location: str) -> list[Finding]:
    return [Finding(kind, label, location, mask(m.group())) for kind, label, m in _matches(text)]


def redact(text: str) -> str:
    """Replace every finding with a [REDACTED:LABEL] tag, right to left so offsets stay valid."""
    spans = sorted(((m.start(), m.end(), label) for _, label, m in _matches(text)), reverse=True)
    last_start = len(text) + 1
    for start, end, label in spans:
        if end > last_start:  # overlaps a span already replaced
            continue
        tag = "[REDACTED:" + re.sub(r"\W+", "_", label).strip("_").upper() + "]"
        text = text[:start] + tag + text[end:]
        last_start = start
    return text


def load_request(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            req = json.load(f)
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON (line {e.lineno}): {e.msg}")

    user = req.get("requesting_user")
    if not isinstance(user, dict) or not {"id", "tenant"} <= user.keys():
        raise InputError("'requesting_user' must be an object with 'id' and 'tenant'")
    parts = req.get("context_parts")
    if not isinstance(parts, list) or not parts:
        raise InputError("'context_parts' must be a non-empty list")
    for i, part in enumerate(parts):
        missing = {"source", "name", "content"} - set(part)
        if missing:
            raise InputError(f"context_parts[{i}] is missing: {', '.join(sorted(missing))}")
    return req


def check_request(req: dict) -> list[Finding]:
    tenant = req["requesting_user"]["tenant"]
    findings: list[Finding] = []

    for part in req["context_parts"]:
        location = f"{part['source']}:{part['name']}"
        findings += scan_text(part["content"], location)
        owner = part.get("owner_tenant")
        if owner and owner != tenant:
            findings.append(Finding("ACCESS", f"owned by tenant '{owner}', requester is '{tenant}'",
                                    location, "drop before sending"))

    canary, response = req.get("canary"), req.get("model_response")
    if canary and response and canary in response:
        findings.append(Finding("CANARY", "system prompt canary found in response",
                                "output:model_response", mask(canary)))
    return findings


def print_report(req: dict, findings: list[Finding], show_redacted: bool) -> None:
    user = req["requesting_user"]
    print(f"Requesting user: {user['id']} (tenant: {user['tenant']})\n")

    by_location: dict[str, list[Finding]] = {}
    for f in findings:
        by_location.setdefault(f.location, []).append(f)

    locations = [f"{p['source']}:{p['name']}" for p in req["context_parts"]]
    if "output:model_response" in by_location:
        locations.append("output:model_response")

    for loc in locations:
        items = by_location.get(loc, [])
        source, _, name = loc.partition(":")
        print(f"[{source}] {name}: {'OK' if not items else f'{len(items)} issue(s)'}")
        for f in items:
            print(f"    {f.kind:<7} {f.label}: {f.preview}")
        if show_redacted and items and source != "output":
            part = next(p for p in req["context_parts"] if f"{p['source']}:{p['name']}" == loc)
            print(f"    redacted: {redact(part['content'])}")

    print(f"\nTotal issues: {len(findings)}")
    print("Verdict:", "BLOCK - fix before this goes to the model" if findings else "PASS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leakcheck",
        description="Scan an assembled LLM request for secrets, PII and cross-tenant data.",
    )
    parser.add_argument("request", help="request file (JSON, see samples/)")
    parser.add_argument("--redact", action="store_true", help="show a redacted copy of each flagged part")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        req = load_request(args.request)
    except InputError as e:
        print(f"leakcheck: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    findings = check_request(req)
    if args.json:
        print(json.dumps({"verdict": "block" if findings else "pass",
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print_report(req, findings, args.redact)
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
