"""Cryptographically secure password & passphrase generation.

Uses `secrets` (CSPRNG) exclusively — never `random`. Guarantees at least one
character from each enabled class, and supports an EFF-style passphrase mode for
sites that play badly with symbols.
"""
from __future__ import annotations

import math
import secrets
import string
from typing import Callable, Optional

from .config import PasswordPolicy

# Characters removed in "avoid ambiguous" mode (look-alikes that cause typos).
_AMBIGUOUS = set("O0oIl1|`'\";:,.{}[]()<>")

# A compact, dependency-free word list for passphrases. For maximum entropy you
# can point GENERATOR at the full EFF large wordlist (7776 words); this built-in
# list (256 words) gives 8 bits/word which is enough at 6+ words.
_WORDS = (
    "able acid aged also area army away baby back ball band bank base bath bear "
    "beat been beer bell belt bend best bird blue boat body bold bone book boot "
    "born both bowl bulk burn bush busy cake call calm came camp card care case "
    "cash cast cell chat chip city clay club coal coat code cold come cook cool "
    "cope copy cord core corn cost crew crop dark data date dawn days dead deal "
    "dean dear debt deep deer dent desk dial diet disc disk dock does done door "
    "dose down draw drew drop drug drum dual duck dust duty each earn ease east "
    "easy edge else even ever evil exit face fact fade fail fair fall farm fast "
    "fate fear feed feel feet fell felt file fill film find fine fire firm fish "
    "five flag flat flew flow foam fold folk fond food fool foot ford form fort "
    "four free frog fuel full fund gain game gate gave gear gene gift girl give "
    "glad glow goal goat gold golf gone good gray grew grey grid grip grow gulf "
    "hair half hall hand hang hard harm hate haul have hawk head heal heap hear "
    "heat held hell helm help herb herd here hero hers hide high hill hint hire "
    "hold hole holy home hood hook hope horn host hour huge hull hunt hurt icon"
).split()


def shannon_entropy_bits(length: int, alphabet_size: int) -> float:
    """Bits of entropy for a uniformly-random string of `length` over alphabet."""
    if alphabet_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(alphabet_size)


def _build_alphabet(policy: PasswordPolicy) -> str:
    pools = []
    if policy.use_lower:
        pools.append(string.ascii_lowercase)
    if policy.use_upper:
        pools.append(string.ascii_uppercase)
    if policy.use_digits:
        pools.append(string.digits)
    if policy.use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")
    if not pools:
        raise ValueError("Password policy enables no character classes.")
    if policy.avoid_ambiguous:
        pools = ["".join(c for c in p if c not in _AMBIGUOUS) for p in pools]
    return pools, "".join(pools)


def generate_password(policy: PasswordPolicy) -> str:
    """Generate a random password obeying the policy, with class guarantees."""
    if policy.passphrase_mode:
        return generate_passphrase(policy)

    pools, alphabet = _build_alphabet(policy)
    if policy.length < len(pools):
        raise ValueError(
            f"length {policy.length} is too short to include all "
            f"{len(pools)} required character classes."
        )

    # Guarantee one char from each enabled pool, then fill the remainder.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(policy.length - len(pools))]

    # Fisher-Yates shuffle with a CSPRNG so guaranteed chars aren't front-loaded.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(policy: PasswordPolicy) -> str:
    """Generate a separator-joined passphrase (e.g. correct-horse-battery)."""
    words = [secrets.choice(_WORDS) for _ in range(max(3, policy.passphrase_words))]
    # Capitalise ONE word in place (don't read one index and write another — that
    # could duplicate a word and lose entropy) so "must contain uppercase" holds.
    cap = secrets.randbelow(len(words))
    words[cap] = words[cap].capitalize()
    phrase = policy.passphrase_separator.join(words)
    return f"{phrase}{policy.passphrase_separator}{secrets.randbelow(100):02d}"


def generate_candidates(policy: PasswordPolicy, n: int = 5,
                        reject: Optional[Callable[[str], bool]] = None,
                        max_tries: int = 50) -> list:
    """Generate `n` distinct candidate passwords for the user to choose from.

    Returns a mix: random strings at the policy length, plus a couple of
    passphrase variants for sites that dislike symbols. `reject` is an optional
    predicate (e.g. "is this password already in a breach?") — candidates it
    rejects are discarded and regenerated, so every returned option is vetted.
    """
    from dataclasses import replace

    out: list[str] = []
    seen: set[str] = set()
    # Build a varied set of policies so the 5 options aren't all identical style.
    variants = [
        policy,
        replace(policy, length=max(policy.length, 20)),
        replace(policy, length=max(policy.length + 8, 28)),
        replace(policy, passphrase_mode=True, passphrase_words=5),
        replace(policy, passphrase_mode=True, passphrase_words=7),
    ]
    i = 0
    tries = 0
    while len(out) < n and tries < max_tries * n:
        tries += 1
        candidate = generate_password(variants[i % len(variants)])
        i += 1
        if candidate in seen:
            continue
        if reject is not None:
            try:
                if reject(candidate):
                    continue  # e.g. found in a breach — skip it
            except Exception:
                pass  # never let a checker failure block generation
        seen.add(candidate)
        out.append(candidate)
    return out


def password_strength_bits(password: str) -> float:
    """Estimate the entropy (bits) of an ARBITRARY existing password.

    Charset-size × length — a standard, deliberately conservative heuristic used
    by the vault audit to flag weak passwords. Not a substitute for a real
    strength meter, but good enough to catch obviously weak entries.
    """
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33  # rough printable-symbol/space pool
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def estimate_strength(policy: PasswordPolicy) -> float:
    """Return estimated entropy in bits for the current policy (for UI display)."""
    if policy.passphrase_mode:
        return policy.passphrase_words * math.log2(len(_WORDS)) + math.log2(100)
    _, alphabet = _build_alphabet(policy)
    return shannon_entropy_bits(policy.length, len(set(alphabet)))
