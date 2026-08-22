"""awbac CLI — check and explain.

`explain` exists because "denied" with no reason is what makes people disable
authorization rather than fix the grant.

Exit codes: 0 allowed, 1 denied, 2 could not judge (bad policy file).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import Policy


def load(path: str) -> Policy:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    p = Policy()
    for name, spec in (data.get("roles") or {}).items():
        p.role(name, spec.get("grants", []), spec.get("inherits", []))
    for subject, roles in (data.get("subjects") or {}).items():
        p.assign(subject, *roles)
    return p


def main(argv: list[str] | None = None) -> int:
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    ap = argparse.ArgumentParser(prog="awbac", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("check", "allow/deny"), ("explain", "allow/deny with the reason")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("policy")
        s.add_argument("subject")
        s.add_argument("permission")

    args = ap.parse_args(argv)
    try:
        policy = load(args.policy)
    except (OSError, ValueError) as exc:
        # Unreadable policy is DEAD, not deny-and-carry-on: a caller that treats
        # "denied" as routine would silently run with no policy at all.
        print(f"DEAD: cannot read policy {args.policy}: {exc}", file=sys.stderr)
        return 2

    d = policy.check(args.subject, args.permission)
    if args.cmd == "explain":
        print(("ALLOW" if d.allowed else "DENY") + ": " + d.reason)
    else:
        print("allow" if d.allowed else "deny")
    return 0 if d.allowed else 1


if __name__ == "__main__":
    sys.exit(main())
