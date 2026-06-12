"""Tests for the password generator — the most security-critical pure module."""
import re
import string

import pytest

from rphe.config import PasswordPolicy
from rphe.passwords import (estimate_strength, generate_passphrase,
                            generate_password)


def test_length_respected():
    pw = generate_password(PasswordPolicy(length=32))
    assert len(pw) == 32


def test_all_classes_present():
    pw = generate_password(PasswordPolicy(length=40, avoid_ambiguous=False))
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in pw)


def test_avoid_ambiguous_excludes_lookalikes():
    pw = generate_password(PasswordPolicy(length=200, avoid_ambiguous=True))
    for bad in "O0Il1|":
        assert bad not in pw


def test_uniqueness_across_runs():
    policy = PasswordPolicy(length=24)
    seen = {generate_password(policy) for _ in range(200)}
    assert len(seen) == 200  # CSPRNG: collisions are astronomically unlikely


def test_too_short_for_all_classes_raises():
    with pytest.raises(ValueError):
        generate_password(PasswordPolicy(length=2))  # needs >= 4 classes


def test_no_classes_enabled_raises():
    with pytest.raises(ValueError):
        generate_password(PasswordPolicy(
            length=10, use_upper=False, use_lower=False,
            use_digits=False, use_symbols=False))


def test_passphrase_word_count_and_separator():
    policy = PasswordPolicy(passphrase_mode=True, passphrase_words=6,
                            passphrase_separator="-")
    phrase = generate_passphrase(policy)
    parts = phrase.split("-")
    assert len(parts) == 7  # 6 words + trailing 2-digit number
    assert re.fullmatch(r"\d{2}", parts[-1])


def test_entropy_estimate_reasonable():
    bits = estimate_strength(PasswordPolicy(length=24))
    assert bits > 120  # 24 chars over ~85-char alphabet
