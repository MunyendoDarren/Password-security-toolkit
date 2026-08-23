"""
Cracker Demo — Educational Only
--------------------------------
Demonstrates WHY weak passwords are dangerous by generating SHA-256
hashes of a few sample passwords locally, then timing how long a
dictionary attack takes to recover each one.

IMPORTANT / SCOPE:
  - This script only ever attacks hashes it generates itself, in memory,
    in this same run. It does NOT accept or crack hashes from any other
    source, and is not intended (or suitable) for attacking real
    accounts, exported hash dumps, or systems you don't own.
  - The point is purely to visualize the *time difference* between
    cracking a weak/common password vs. a strong random one, using a
    small local wordlist — not to build a general-purpose cracking tool.

Usage:
    python crack_demo.py
"""

import hashlib
import itertools
import os
import string
import time

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
COMMON_PASSWORDS_PATH = os.path.join(DATA_DIR, "common_passwords.txt")

# Passwords we will hash ourselves and then try to crack back.
# Mix of weak/common and strong/random examples for comparison.
SAMPLE_PASSWORDS = [
    "123456",       # extremely common
    "password1",    # common + trivial mutation
    "Summer2024",   # common word + year pattern
    "xK9$mQ2#vL7p", # strong, random
]


def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_wordlist() -> list:
    """Load base dictionary and expand it with common leetspeak / suffix mutations."""
    try:
        with open(COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as f:
            base_words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        base_words = ["password", "123456", "qwerty"]

    mutations = []
    suffixes = ["", "1", "12", "123", "1!", "2024", "2025", "!"]
    leet_map = {"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"}

    for word in base_words:
        capitalized = word.capitalize()
        for suffix in suffixes:
            mutations.append(word + suffix)
            mutations.append(capitalized + suffix)  # e.g. "Summer" + "2024"
        # one simple leetspeak variant per word
        leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
        if leet_word != word:
            mutations.append(leet_word)

    # De-duplicate while preserving order
    seen = set()
    wordlist = []
    for w in mutations:
        if w not in seen:
            seen.add(w)
            wordlist.append(w)
    return wordlist


def dictionary_attack(target_hash: str, wordlist: list, timeout_seconds: float = 5.0):
    """
    Try each candidate in wordlist against target_hash.
    Returns (found_password_or_None, attempts_tried, elapsed_seconds).
    """
    start = time.perf_counter()
    for attempts, candidate in enumerate(wordlist, start=1):
        if sha256_hash(candidate) == target_hash:
            elapsed = time.perf_counter() - start
            return candidate, attempts, elapsed
        if time.perf_counter() - start > timeout_seconds:
            elapsed = time.perf_counter() - start
            return None, attempts, elapsed
    elapsed = time.perf_counter() - start
    return None, len(wordlist), elapsed


def brute_force_estimate(password: str) -> str:
    """
    Rather than actually brute-forcing (infeasible for strong passwords in
    a demo), estimate time-to-crack at a stated guesses/second rate so the
    comparison with the dictionary attack is honest and fast to run.
    """
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    pool = max(pool, 1)

    combinations = pool ** len(password)

    # Assume a modern offline attacker doing ~10 billion guesses/sec
    # (representative order-of-magnitude for fast hash + GPU cracking rigs).
    guesses_per_second = 10_000_000_000
    seconds = combinations / guesses_per_second

    return format_duration(seconds)


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "< 1 second"
    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"~{value:,.1f} {name}"
    return "< 1 second"


def run_demo():
    print("=" * 60)
    print(" Password Cracking Demo (educational, self-contained)")
    print("=" * 60)
    print(
        "This hashes a few sample passwords locally, then times how long\n"
        "a small dictionary attack takes to recover each one — no real\n"
        "accounts, systems, or third-party data are involved.\n"
    )

    wordlist = load_wordlist()
    print(f"Loaded a mutated wordlist of {len(wordlist):,} candidates.\n")

    for password in SAMPLE_PASSWORDS:
        target_hash = sha256_hash(password)
        masked = password[0] + "*" * (len(password) - 1)
        print(f"Target: {masked}  (SHA-256: {target_hash[:16]}...)")

        found, attempts, elapsed = dictionary_attack(target_hash, wordlist)

        if found:
            print(f"  -> Cracked in {attempts:,} attempts / {elapsed:.4f} seconds.")
        else:
            print(f"  -> Not found in dictionary after {attempts:,} attempts ({elapsed:.4f}s).")
            estimate = brute_force_estimate(password)
            print(f"  -> Estimated brute-force time at 10B guesses/sec: {estimate}")
        print("-" * 60)

    print(
        "\nTakeaway: common or lightly-mutated passwords fall to a small\n"
        "dictionary in milliseconds, while a long, random password pushes\n"
        "the estimated crack time into years or centuries — even against\n"
        "a fast offline attacker.\n"
    )


if __name__ == "__main__":
    run_demo()
