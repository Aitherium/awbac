"""Permission matching, segment-aware.

This is the whole package's load-bearing part, and the reason it is its own
module with its own tests: **the obvious implementation fails OPEN.**

Permissions here look like `workspace:read:*` — colon-separated segments with
`*` as a wildcard. The tempting matcher is `granted.startswith(prefix)`, and it
is wrong in a way that grants access rather than refusing it:

    "workspace:read".startswith("workspace:read")      -> True   (correct)
    "workspace:readwrite".startswith("workspace:read") -> True   (WRONG)

A grant of `workspace:read` silently covers `workspace:readwrite`. Nothing
errors, no test that only checks the happy path notices, and the mistake is
invisible until someone writes to something they could only read.

This exact shape has already cost this codebase twice: a licence resolver that
prefix-matched returned `commercial_ok=True` for any model whose name merely
started with a licensed one, and the site's own route guard needed a
segment-boundary matcher for the same reason. So matching happens on SEGMENTS,
never on characters.

`*` matches exactly one segment. `**` matches one or more trailing segments, and
only in the final position — a `**` in the middle would make
`a:**:d` match `a:b:c:d` *and* `a:b:d`, which reads as a typo far more often
than it reads as intent.
"""

from __future__ import annotations

SEP = ":"
ONE = "*"
REST = "**"


def split(perm: str) -> list[str]:
    return [s for s in perm.split(SEP)]


def matches(granted: str, requested: str) -> bool:
    """Does `granted` cover `requested`?

    Both are segment lists. The comparison is per-segment and exact, except for
    the two wildcards — so no amount of shared prefix grants anything the
    segments do not.
    """
    if not granted or not requested:
        # An empty permission grants nothing and is never satisfied. Returning
        # True for either would be the fail-open default this module exists to
        # avoid.
        return False

    g = split(granted)
    r = split(requested)

    for i, gseg in enumerate(g):
        if gseg == REST:
            if i != len(g) - 1:
                # `**` anywhere but last is refused rather than interpreted.
                # Guessing here is how a typo becomes a grant.
                return False
            return len(r) > i          # must cover at least one real segment
        if i >= len(r):
            return False               # granted is more specific than requested
        if gseg == ONE:
            continue
        if gseg != r[i]:
            return False

    # Every granted segment matched. Equal length is a hit; a LONGER request
    # means the grant is narrower than what was asked for -> deny.
    return len(g) == len(r)


def covers_any(granted: list[str], requested: str) -> str | None:
    """The first grant that covers `requested`, or None.

    Returns the matching grant rather than a bool so a decision can say WHICH
    grant allowed it — an allow nobody can attribute is as hard to audit as a
    deny nobody can explain.
    """
    for g in granted:
        if matches(g, requested):
            return g
    return None
