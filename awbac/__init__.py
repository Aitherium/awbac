"""awbac — role-based access control that fails closed and explains itself.

    from awbac import Policy

    p = (Policy()
         .role("reader", ["doc:read:*"])
         .role("editor", ["doc:write:*"], inherits=["reader"])
         .assign("david", "editor"))

    d = p.check("david", "doc:read:handbook")
    if d:
        ...
    print(d.reason)        # "granted by 'doc:read:*'"

Part of the `aw` family. `awiam` answers who a caller is; this answers what they
may do; `awseal` holds what proves it.
"""

from .engine import Decision, Policy, Role
from .match import covers_any, matches

__version__ = "0.1.0"
__all__ = ["Policy", "Role", "Decision", "matches", "covers_any"]
