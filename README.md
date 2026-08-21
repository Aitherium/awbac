# awbac

Role-based access control that **fails closed** and **explains itself**.

```bash
pip install awbac
```

```python
from awbac import Policy

p = (Policy()
     .role("reader", ["doc:read:*"])
     .role("editor", ["doc:write:*"], inherits=["reader"])
     .assign("david", "editor"))

d = p.check("david", "doc:read:handbook")
if d:
    ...
print(d.reason)     # granted by 'doc:read:*'
```

```bash
awbac check   policy.json david doc:read:handbook   # 0 allow · 1 deny · 2 could not judge
awbac explain policy.json david doc:write:secret
# DENY: none of 2 grant(s) cover 'doc:write:secret'
```

## The bug this package is shaped around

Permissions are colon-separated: `workspace:read:*`. The obvious matcher is
`granted.startswith(requested)`, and it **fails open**:

```python
"workspace:readwrite".startswith("workspace:read")   # True
```

A grant of `workspace:read` silently covers `workspace:readwrite`. Nothing
raises, no happy-path test notices, and it stays invisible until someone writes
to something they could only read.

So matching is on **segments**, never characters. `*` matches exactly one
segment; `**` matches one or more trailing segments and is **refused anywhere
but last**, because a mid-position `**` reads as a typo far more often than as
intent.

| granted | requested | result |
|---|---|---|
| `workspace:read` | `workspace:readwrite` | **deny** |
| `doc:read:*` | `doc:read:handbook` | allow |
| `doc:*` | `doc:read:handbook` | **deny** — `*` is one segment |
| `doc:**` | `doc:read:handbook` | allow |
| `doc:read` | `doc:read:handbook` | **deny** — grant is narrower |

## Fails closed on every path

Unknown role, unknown subject, anonymous caller, empty permission, malformed
policy, inheritance cycle, an exception mid-evaluation — **every one denies**,
with the cause named:

- an **unknown role contributes nothing**, not everything
- an **inheritance cycle** resolves what it can rather than raising (one bad
  role must not take down all authorization) or looping forever
- an exception returns a denial that says so, instead of propagating to a caller
  who might treat a raise as an allow
- an **unreadable policy file** exits **2**, not 1 — "denied" is routine and
  would be shrugged off, so a missing policy has to look different from a
  refused request

## Every decision carries a reason

A deny nobody can explain gets worked around. An allow nobody can attribute
cannot be audited. So `Decision` carries `reason`, and an allow also carries
`via` — the exact grant that permitted it.

## Tests

15 tests, and they run in **both directions**: a suite that only asserts denials
passes on a policy that denies everything, and one that only asserts allows
passes on a policy that allows everything. There is a test whose whole job is to
fail if the policy were replaced by a deny-all.

```bash
pip install -e ".[dev]" && pytest
```

## Where it sits

| package | question |
|---|---|
| `awiam` | who is this caller? |
| **`awbac`** | **may this subject do X to Y?** |
| [`awseal`](https://github.com/Aitherium/awseal) | what proves it? |

Deliberately three packages. An identity service that also owns authorization
has nobody to check it, and one that owns its own key material has nobody to
attest it.

Apache-2.0.
