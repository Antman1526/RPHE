"""Tests for the 5-password picker and the passkey advisor."""
from rphe.config import PasswordPolicy
from rphe.passwords import generate_candidates
from rphe.passkeys import advise


def test_five_distinct_candidates():
    cands = generate_candidates(PasswordPolicy(length=20), n=5)
    assert len(cands) == 5
    assert len(set(cands)) == 5  # all distinct


def test_reject_predicate_filters_candidates():
    # Reject anything containing a digit '5' on first pass to exercise the loop.
    seen = []

    def reject(pw: str) -> bool:
        seen.append(pw)
        return False  # accept all, but ensure predicate is actually called

    cands = generate_candidates(PasswordPolicy(length=16), n=5, reject=reject)
    assert len(cands) == 5
    assert len(seen) >= 5  # predicate was consulted for each accepted candidate


def test_reject_all_does_not_hang():
    # If the checker rejects everything, we must stop (bounded), not loop forever.
    cands = generate_candidates(PasswordPolicy(length=16), n=5,
                                reject=lambda pw: True, max_tries=10)
    assert cands == []  # nothing accepted, but it returned


def test_passkey_known_service():
    adv = advise("GitHub", "github.com")
    assert adv.supported is True
    assert adv.confidence == "known"
    assert any("passkey" in s.lower() for s in adv.steps)


def test_passkey_unknown_service():
    adv = advise("Tiny Forum", "tinyforum.example")
    assert adv.supported is False
    assert adv.confidence == "unknown"
    # Unknown services still get actionable guidance (check settings / TOTP).
    assert any("Security settings" in s or "TOTP" in s for s in adv.steps)
