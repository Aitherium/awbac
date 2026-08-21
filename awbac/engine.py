"""The decision, and why.

Two properties everything here is built around:

**Fail closed on every path.** Unknown role, missing subject, malformed policy,
cycle in the inheritance graph, exception mid-evaluation — all of them DENY. An
authorization function that returns True on an error path is the single most
expensive bug this shape of code has, and it is invisible: the happy path works,
the tests pass, and the hole only opens when something else breaks.

**Every decision carries a reason.** A deny nobody can explain gets worked
around; an allow nobody can attribute cannot be audited. `Decision.reason` names
the grant that allowed it or the specific thing that was missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .match import covers_any


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    #: The grant string that permitted this, when one did. None on every deny.
    via: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Role:
    name: str
    grants: list[str] = field(default_factory=list)
    #: Roles this one absorbs. Resolved transitively, cycle-safe.
    inherits: list[str] = field(default_factory=list)


class Policy:
    """Roles, and which subjects hold them."""

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}
        self._subjects: dict[str, list[str]] = {}

    # ── building ────────────────────────────────────────────────────────────
    def role(self, name: str, grants: list[str] | None = None,
             inherits: list[str] | None = None) -> "Policy":
        self._roles[name] = Role(name, list(grants or []), list(inherits or []))
        return self

    def assign(self, subject: str, *roles: str) -> "Policy":
        self._subjects.setdefault(subject, []).extend(roles)
        return self

    # ── resolution ──────────────────────────────────────────────────────────
    def effective_grants(self, role: str) -> list[str]:
        """All grants of `role`, following `inherits`.

        Cycle-safe by construction: a role already seen is skipped rather than
        recursed into. An inheritance cycle is a configuration mistake, and the
        correct response is to resolve what is resolvable — NOT to raise, which
        would turn one bad role into a total authorization outage, and not to
        recurse forever, which turns it into a hang.
        """
        seen: set[str] = set()
        out: list[str] = []
        stack = [role]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            r = self._roles.get(name)
            if r is None:
                continue          # unknown role contributes NOTHING, never everything
            out.extend(r.grants)
            stack.extend(r.inherits)
        return out

    def grants_for(self, subject: str) -> list[str]:
        out: list[str] = []
        for role in self._subjects.get(subject, []):
            out.extend(self.effective_grants(role))
        return out

    # ── the question ────────────────────────────────────────────────────────
    def check(self, subject: str, permission: str) -> Decision:
        try:
            if not subject:
                return Decision(False, "no subject — anonymous callers are denied")
            if not permission:
                return Decision(False, "no permission requested")
            roles = self._subjects.get(subject)
            if not roles:
                return Decision(False, f"subject {subject!r} holds no roles")

            grants = self.grants_for(subject)
            if not grants:
                return Decision(
                    False,
                    f"subject {subject!r} holds role(s) {', '.join(roles)} but they "
                    f"carry no grants (unknown role names contribute nothing)",
                )
            hit = covers_any(grants, permission)
            if hit:
                return Decision(True, f"granted by {hit!r}", via=hit)
            return Decision(
                False,
                f"none of {len(grants)} grant(s) cover {permission!r}",
            )
        except Exception as exc:  # noqa: BLE001 — deliberate catch-all
            # Fail CLOSED. Anything unexpected is a denial with the cause named,
            # never an allow and never a raise that a caller might treat as one.
            return Decision(False, f"evaluation failed, denying: {type(exc).__name__}: {exc}")
