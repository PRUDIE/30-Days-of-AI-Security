#!/usr/bin/env python3
"""agencycheck: find excessive agency in an LLM agent, then gate its tool calls.

An agent manifest lists what the agent is for (its "needs") and the tools it
has been given (their "grants"). agencycheck compares the two.

    audit   design-time review of the manifest. Reports the three root causes
            of excessive agency (OWASP LLM03:2026):

              FUNCTION    tools the purpose doesn't need, or open-ended tools
              PERMISSION  grants broader than the need (scope, limits, credential)
              AUTONOMY    high-impact actions with no human approval or hard limit

    replay  runtime check. Replays the tool calls an agent tried to make and
            decides ALLOW, HOLD (needs human approval) or DENY for each one,
            enforcing what the agent needs rather than what its tools can do.

Exit codes: 0 clean, 1 findings or denied calls, 2 bad input.

Standard library only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass

__version__ = "0.1.0"

EXIT_CLEAN, EXIT_FINDINGS, EXIT_BAD_INPUT = 0, 1, 2

# Scopes from narrowest to broadest.
SCOPE_RANK = {"own": 0, "tenant": 1, "all": 2}

# Actions that change something outside the conversation. A wrong call here is
# a wrong action, not just a wrong answer.
HIGH_IMPACT_ACTIONS = {"create", "update", "write", "delete", "cancel", "send", "execute", "transfer"}

APPROVALS = {"none", "human"}
CREDENTIALS = {"user", "service"}


@dataclass(frozen=True)
class Finding:
    kind: str     # FUNCTION | PERMISSION | AUTONOMY
    tool: str     # tool name, or "agent" for agent-level settings
    message: str


@dataclass(frozen=True)
class Decision:
    index: int
    tool: str
    decision: str          # ALLOW | HOLD | DENY
    reasons: tuple[str, ...]


class InputError(ValueError):
    """A manifest or session file is missing or malformed."""


def is_high_impact(capability: str) -> bool:
    return capability.rpartition(".")[2] in HIGH_IMPACT_ACTIONS


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------

def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON (line {e.lineno}): {e.msg}")
    if not isinstance(data, dict):
        raise InputError(f"{path} must contain a JSON object")
    return data


def _check_capability(entry: object, where: str) -> None:
    if not isinstance(entry, dict):
        raise InputError(f"{where} must be an object")
    cap = entry.get("capability")
    if not isinstance(cap, str) or "." not in cap:
        raise InputError(f"{where}.capability must look like 'resource.action', e.g. 'orders.read'")
    if entry.get("scope") not in SCOPE_RANK:
        raise InputError(f"{where}.scope must be one of: {', '.join(SCOPE_RANK)}")
    limit = entry.get("max_amount")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, (int, float)) or limit < 0):
        raise InputError(f"{where}.max_amount must be a non-negative number")


def validate_manifest(m: dict) -> dict:
    if not isinstance(m.get("agent"), str) or not m["agent"]:
        raise InputError("'agent' must be a non-empty string")

    needs = m.get("needs")
    if not isinstance(needs, list) or not needs:
        raise InputError("'needs' must be a non-empty list: what does the agent actually have to do?")
    seen = set()
    for i, need in enumerate(needs):
        _check_capability(need, f"needs[{i}]")
        if need["capability"] in seen:
            raise InputError(f"needs[{i}]: capability '{need['capability']}' is listed twice")
        seen.add(need["capability"])

    tools = m.get("tools")
    if not isinstance(tools, list) or not tools:
        raise InputError("'tools' must be a non-empty list")
    names = set()
    for i, tool in enumerate(tools):
        where = f"tools[{i}]"
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise InputError(f"{where} must be an object with a 'name'")
        if tool["name"] in names:
            raise InputError(f"{where}: tool name '{tool['name']}' is used twice")
        names.add(tool["name"])
        grants = tool.get("grants")
        if not isinstance(grants, list) or not grants:
            raise InputError(f"{where}.grants must be a non-empty list")
        for j, grant in enumerate(grants):
            _check_capability(grant, f"{where}.grants[{j}]")
        if tool.get("approval", "none") not in APPROVALS:
            raise InputError(f"{where}.approval must be one of: {', '.join(sorted(APPROVALS))}")
        if tool.get("credential", "user") not in CREDENTIALS:
            raise InputError(f"{where}.credential must be one of: {', '.join(sorted(CREDENTIALS))}")
    return m


def load_manifest(path: str) -> dict:
    return validate_manifest(_read_json(path))


def load_session(path: str) -> dict:
    s = _read_json(path)
    user = s.get("requesting_user")
    if not isinstance(user, dict) or not isinstance(user.get("id"), str):
        raise InputError("'requesting_user' must be an object with an 'id'")
    calls = s.get("calls")
    if not isinstance(calls, list) or not calls:
        raise InputError("'calls' must be a non-empty list")
    for i, call in enumerate(calls):
        if not isinstance(call, dict) or not isinstance(call.get("tool"), str):
            raise InputError(f"calls[{i}] must be an object with a 'tool'")
        if not isinstance(call.get("args", {}), dict):
            raise InputError(f"calls[{i}].args must be an object")
    return s


# --------------------------------------------------------------------------
# audit: design-time review
# --------------------------------------------------------------------------

def _limit_text(value: float | int | None) -> str:
    return "no limit" if value is None else f"a limit of {value:g}"


def audit(manifest: dict) -> list[Finding]:
    needs = {n["capability"]: n for n in manifest["needs"]}
    findings: list[Finding] = []

    for tool in manifest["tools"]:
        name = tool["name"]
        grants = tool["grants"]
        used = [(g, needs[g["capability"]]) for g in grants if g["capability"] in needs]

        if tool.get("open_ended"):
            findings.append(Finding("FUNCTION", name,
                "open-ended tool: its arguments can do anything, so no policy can check them. "
                "Replace it with narrow tools for the specific operations needed"))

        if not used:
            findings.append(Finding("FUNCTION", name,
                "not needed for the agent's purpose: remove it"))
            continue  # removing the tool fixes everything else about it

        for g in grants:
            if g["capability"] not in needs:
                findings.append(Finding("PERMISSION", name,
                    f"grants '{g['capability']}', which the purpose doesn't need"))

        for g, need in used:
            cap = g["capability"]
            if SCOPE_RANK[g["scope"]] > SCOPE_RANK[need["scope"]]:
                findings.append(Finding("PERMISSION", name,
                    f"'{cap}' reaches scope '{g['scope']}', the purpose only needs '{need['scope']}'"))
            if "max_amount" in need:
                granted = g.get("max_amount")
                if granted is None or granted > need["max_amount"]:
                    findings.append(Finding("PERMISSION", name,
                        f"'{cap}' has {_limit_text(granted)}, the purpose needs at most {need['max_amount']:g}"))

        if tool.get("credential", "user") == "service" and any(n["scope"] == "own" for _, n in used):
            findings.append(Finding("PERMISSION", name,
                "runs with a shared service credential, so the downstream system can't enforce "
                "the user's own permissions. Use the requesting user's delegated credential"))

        if tool.get("approval", "none") != "human":
            for g, need in used:
                if is_high_impact(g["capability"]) and need.get("max_amount") is None:
                    findings.append(Finding("AUTONOMY", name,
                        f"'{g['capability']}' is a high-impact action with no human approval "
                        f"and no hard limit"))

    if manifest.get("max_steps") is None:
        findings.append(Finding("AUTONOMY", "agent",
            "no step budget (max_steps): a manipulated agent can keep calling tools indefinitely"))
    return findings


# --------------------------------------------------------------------------
# replay: runtime gate
# --------------------------------------------------------------------------

def gate_call(manifest: dict, user_id: str, call: dict, index: int = 0) -> Decision:
    """Decide one tool call. Enforces the agent's needs, not its tools' grants."""
    needs = {n["capability"]: n for n in manifest["needs"]}
    tools = {t["name"]: t for t in manifest["tools"]}
    name, args = call["tool"], call.get("args", {})

    tool = tools.get(name)
    if tool is None:
        return Decision(index, name, "DENY", ("tool is not in the manifest",))
    if tool.get("open_ended"):
        return Decision(index, name, "DENY",
                        ("open-ended tool: arguments can't be checked against policy",))
    used = [needs[g["capability"]] for g in tool["grants"] if g["capability"] in needs]
    if not used:
        return Decision(index, name, "DENY", ("tool is not needed for the agent's purpose",))

    reasons: list[str] = []
    for need in used:
        if need["scope"] == "own":
            owner = args.get("owner")
            if owner is None:
                reasons.append("no 'owner' argument, can't prove the call only touches the user's own data")
            elif owner != user_id:
                reasons.append(f"acts on data owned by '{owner}', requester is '{user_id}'")
        if "max_amount" in need:
            amount = args.get("amount")
            if isinstance(amount, bool) or not isinstance(amount, (int, float)):
                reasons.append("no numeric 'amount' argument to check against the limit")
            elif amount > need["max_amount"]:
                reasons.append(f"amount {amount:g} is over the limit of {need['max_amount']:g}")
    reasons = list(dict.fromkeys(reasons))  # de-duplicate, keep order

    if reasons:
        return Decision(index, name, "DENY", tuple(reasons))
    if tool.get("approval", "none") == "human":
        return Decision(index, name, "HOLD", ("high-impact action, waiting for human approval",))
    return Decision(index, name, "ALLOW", ())


def replay(manifest: dict, session: dict) -> list[Decision]:
    user_id = session["requesting_user"]["id"]
    budget = manifest.get("max_steps")
    decisions = []
    for i, call in enumerate(session["calls"], start=1):
        if budget is not None and i > budget:
            decisions.append(Decision(i, call["tool"], "DENY", (f"step budget of {budget} exhausted",)))
        else:
            decisions.append(gate_call(manifest, user_id, call, i))
    return decisions


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _need_text(need: dict) -> str:
    extra = f", max {need['max_amount']:g}" if "max_amount" in need else ""
    return f"{need['capability']} ({need['scope']}{extra})"


def print_audit(manifest: dict, findings: list[Finding]) -> None:
    print(f"Agent: {manifest['agent']}")
    if manifest.get("purpose"):
        print(f"Purpose: {manifest['purpose']}")
    print("Needs:", ", ".join(_need_text(n) for n in manifest["needs"]), end="\n\n")

    by_tool: dict[str, list[Finding]] = {}
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)

    for name in [t["name"] for t in manifest["tools"]] + ["agent"]:
        items = by_tool.get(name, [])
        if name == "agent" and not items:
            continue
        label = "[agent settings]" if name == "agent" else f"[tool] {name}"
        print(f"{label}: {'OK' if not items else f'{len(items)} issue(s)'}")
        for f in items:
            print(f"    {f.kind:<10} {f.message}")

    counts = {k: sum(f.kind == k for f in findings) for k in ("FUNCTION", "PERMISSION", "AUTONOMY")}
    print(f"\nTotal issues: {len(findings)} "
          f"(function {counts['FUNCTION']}, permission {counts['PERMISSION']}, autonomy {counts['AUTONOMY']})")
    print("Verdict:", "EXCESSIVE AGENCY - reduce before deploying" if findings else "PASS - least privilege")


def print_replay(session: dict, decisions: list[Decision]) -> None:
    print(f"Requesting user: {session['requesting_user']['id']}\n")
    for d, call in zip(decisions, session["calls"]):
        args = ", ".join(f"{k}={v!r}" for k, v in call.get("args", {}).items())
        if len(args) > 60:
            args = args[:57] + "..."
        print(f"{d.index:>2}. {d.decision:<5} {d.tool}({args})")
        for r in d.reasons:
            print(f"           {r}")
    tally = {k: sum(d.decision == k for d in decisions) for k in ("ALLOW", "HOLD", "DENY")}
    print(f"\nAllowed {tally['ALLOW']}, held for approval {tally['HOLD']}, denied {tally['DENY']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agencycheck",
        description="Find excessive agency in an LLM agent manifest and gate its tool calls.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="review a manifest for excessive agency")
    p_audit.add_argument("manifest", help="agent manifest (JSON, see samples/)")
    p_audit.add_argument("--json", action="store_true", help="machine-readable output")

    p_replay = sub.add_parser("replay", help="decide ALLOW/HOLD/DENY for each tool call in a session")
    p_replay.add_argument("manifest", help="agent manifest (JSON)")
    p_replay.add_argument("session", help="recorded tool calls (JSON, see samples/)")
    p_replay.add_argument("--json", action="store_true", help="machine-readable output")

    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        session = load_session(args.session) if args.command == "replay" else None
    except InputError as e:
        print(f"agencycheck: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.command == "audit":
        findings = audit(manifest)
        if args.json:
            print(json.dumps({"verdict": "excessive" if findings else "pass",
                              "findings": [asdict(f) for f in findings]}, indent=2))
        else:
            print_audit(manifest, findings)
        return EXIT_FINDINGS if findings else EXIT_CLEAN

    decisions = replay(manifest, session)
    denied = any(d.decision == "DENY" for d in decisions)
    if args.json:
        print(json.dumps({"verdict": "denied" if denied else "pass",
                          "decisions": [asdict(d) for d in decisions]}, indent=2))
    else:
        print_replay(session, decisions)
    return EXIT_FINDINGS if denied else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
