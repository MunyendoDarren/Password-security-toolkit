"""
Password Strength Checker
--------------------------
Scores a password on entropy, length, character diversity, and common
weakness patterns (repeated chars, sequential runs, keyboard walks,
dictionary/common-password matches).

Usage:
    python strength_checker.py                # interactive prompt
    python strength_checker.py "MyP@ssw0rd!"   # check a single password
"""

import math
import re
import sys
import os

COMMON_PASSWORDS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "common_passwords.txt"
)

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def load_common_passwords(path: str = COMMON_PASSWORDS_PATH) -> set:
    """Load the common/weak password list into a set for O(1) lookups."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits: log2(pool_size) * length.
    Pool size is derived from which character classes are present,
    which approximates (but doesn't guarantee) true randomness.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approx. printable special characters

    if pool == 0 or len(password) == 0:
        return 0.0

    return len(password) * math.log2(pool)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detect ascending or descending sequential runs, e.g. 'abc', '321'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i : i + run_length]
        codes = [ord(c) for c in window]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Detect the same character repeated run_length+ times in a row, e.g. 'aaa'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i : i + run_length])) == 1:
            return True
    return False


def has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    """Detect keyboard-adjacent sequences, e.g. 'qwer', 'asdf'."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i : i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def is_common_password(password: str, common_set: set) -> bool:
    return password.lower() in common_set


def score_password(password: str, common_set: set = None) -> dict:
    """
    Score a password from 0-100 and return a detailed breakdown.

    Weighting:
      - Length:            up to 25 pts
      - Character variety: up to 25 pts
      - Entropy:           up to 30 pts
      - Pattern penalties: deductions for weak patterns
      - Common password:   heavy penalty / auto-fail
    """
    if common_set is None:
        common_set = load_common_passwords()

    result = {
        "password_length": len(password),
        "entropy_bits": round(calculate_entropy(password), 2),
        "issues": [],
        "score": 0,
        "rating": "",
    }

    if len(password) == 0:
        result["rating"] = "Invalid"
        result["issues"].append("Password is empty.")
        return result

    score = 0

    # --- Length scoring (up to 25 pts) ---
    length = len(password)
    if length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 12
    elif length >= 5:
        score += 5
    else:
        result["issues"].append("Too short (under 5 characters).")

    # --- Character variety (up to 25 pts, ~6.25 per class) ---
    classes_present = sum(
        [
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"[0-9]", password)),
            bool(re.search(r"[^a-zA-Z0-9]", password)),
        ]
    )
    score += classes_present * 6.25
    if classes_present < 3:
        result["issues"].append(
            "Low character variety — mix uppercase, lowercase, numbers, and symbols."
        )

    # --- Entropy scoring (up to 30 pts) ---
    entropy = result["entropy_bits"]
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 22
    elif entropy >= 40:
        score += 14
    elif entropy >= 25:
        score += 6
    else:
        result["issues"].append("Very low entropy — easily brute-forced.")

    # --- Pattern penalties ---
    if has_repeated_chars(password):
        score -= 10
        result["issues"].append("Contains repeated character runs (e.g. 'aaa').")

    if has_sequential_chars(password):
        score -= 10
        result["issues"].append("Contains sequential characters (e.g. 'abc', '321').")

    if has_keyboard_walk(password):
        score -= 10
        result["issues"].append("Contains a keyboard-walk pattern (e.g. 'qwerty', 'asdf').")

    # --- Common password check (severe penalty) ---
    if is_common_password(password, common_set):
        score = min(score, 5)
        result["issues"].append(
            "This password appears in common/breached password lists — do not use it."
        )

    score = max(0, min(100, round(score)))
    result["score"] = score

    if score >= 85:
        result["rating"] = "Very Strong"
    elif score >= 65:
        result["rating"] = "Strong"
    elif score >= 45:
        result["rating"] = "Moderate"
    elif score >= 25:
        result["rating"] = "Weak"
    else:
        result["rating"] = "Very Weak"

    if not result["issues"]:
        result["issues"].append("No significant weaknesses detected.")

    return result


def print_report(password: str, result: dict) -> None:
    masked = password[0] + "*" * max(0, len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)
    print("\n" + "=" * 50)
    print(f" Password Strength Report — {masked}")
    print("=" * 50)
    print(f" Length:        {result['password_length']} characters")
    print(f" Entropy:       {result['entropy_bits']} bits")
    print(f" Score:         {result['score']} / 100")
    print(f" Rating:        {result['rating']}")
    print(" Issues:")
    for issue in result["issues"]:
        print(f"   - {issue}")
    print("=" * 50 + "\n")


def main():
    common_set = load_common_passwords()

    if len(sys.argv) > 1:
        password = sys.argv[1]
        result = score_password(password, common_set)
        print_report(password, result)
        return

    print("Password Strength Checker (Ctrl+C to quit)")
    while True:
        try:
            password = input("\nEnter a password to check: ")
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break
        result = score_password(password, common_set)
        print_report(password, result)


if __name__ == "__main__":
    main()
