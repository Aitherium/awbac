"""Every fail-open shape this package exists to prevent, asserted as a denial.

An authorization test suite that only checks denials passes trivially on a
policy that denies everything, and one that only checks allows passes on a
policy that allows everything. Both directions are here for that reason.
"""

import pytest

from awbac import Policy, matches


# ── the matcher: the thing that fails OPEN if written the obvious way ────────

def test_prefix_is_not_a_match():
    """The whole reason match.py exists.

    `startswith` says True here, and that is a silent grant of write to someone
    who was given read.
    """
    assert not matches("workspace:read", "workspace:readwrite")
    assert not matches("doc:read", "doc:readwrite:secret")


def test_exact_and_wildcard():
    assert matches("doc:read:handbook", "doc:read:handbook")
    assert matches("doc:read:*", "doc:read:handbook")
    assert not matches("doc:read:*", "doc:write:handbook")


def test_single_wildcard_is_exactly_one_segment():
    assert matches("doc:*:handbook", "doc:read:handbook")
    assert not matches("doc:*", "doc:read:handbook"), "* must not span segments"


def test_double_wildcard_is_trailing_only():
    assert matches("doc:**", "doc:read:handbook")
    assert matches("doc:**", "doc:read")
    assert not matches("doc:**", "doc"), "** must cover at least one segment"
    # Mid-position ** is refused rather than guessed at.
    assert not matches("a:**:d", "a:b:c:d")


def test_narrower_grant_does_not_cover_broader_request():
    assert not matches("doc:read", "doc:read:handbook")


def test_empty_never_matches():
    assert not matches("", "doc:read")
    assert not matches("doc:read", "")


# ── the engine: every error path denies ──────────────────────────────────────

def policy() -> Policy:
    return (Policy()
            .role("reader", ["doc:read:*"])
            .role("editor", ["doc:write:*"], inherits=["reader"])
            .assign("david", "editor")
            .assign("guest", "nosuchrole"))


def test_allow_names_the_grant():
    d = policy().check("david", "doc:read:handbook")
    assert d and d.via == "doc:read:*"
    assert "granted by" in d.reason


def test_inheritance_is_transitive():
    assert policy().check("david", "doc:write:handbook")
    assert policy().check("david", "doc:read:handbook"), "editor inherits reader"


def test_unknown_role_grants_nothing_not_everything():
    d = policy().check("guest", "doc:read:handbook")
    assert not d
    assert "no grants" in d.reason


def test_anonymous_is_denied():
    assert not policy().check("", "doc:read:handbook")


def test_unknown_subject_is_denied():
    d = policy().check("stranger", "doc:read:handbook")
    assert not d and "holds no roles" in d.reason


def test_empty_permission_is_denied():
    assert not policy().check("david", "")


def test_inheritance_cycle_does_not_hang_or_open():
    """A cycle is a config mistake. It must not raise (one bad role would take
    down all authorization) and must not loop forever."""
    p = (Policy()
         .role("a", ["x:1"], inherits=["b"])
         .role("b", ["y:1"], inherits=["a"])
         .assign("u", "a"))
    assert p.check("u", "x:1")
    assert p.check("u", "y:1")
    assert not p.check("u", "z:1")


def test_evaluation_error_denies_rather_than_raising():
    p = policy()
    p._subjects["boom"] = None          # corrupt state on purpose
    d = p.check("boom", "doc:read:x")
    assert not d, "an exception mid-evaluation must DENY"
    assert "denying" in d.reason or "holds no roles" in d.reason


def test_deny_all_policy_would_fail_the_allow_tests():
    """Guards against a suite that passes on a policy denying everything."""
    empty = Policy()
    assert not empty.check("david", "doc:read:handbook")
    with pytest.raises(AssertionError):
        assert empty.check("david", "doc:read:handbook")
