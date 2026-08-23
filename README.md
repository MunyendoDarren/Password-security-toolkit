# Password Security Toolkit

A small, self-contained Python toolkit that (1) scores password strength
using entropy and pattern analysis, and (2) demonstrates *why* weak
passwords fail fast, by timing a dictionary attack against hashes it
generates locally.

Built as a hands-on project while studying cybersecurity fundamentals —
covers entropy math, common attack patterns (dictionary attacks,
mutation rules, keyboard walks), and secure coding practices like never
storing passwords in plaintext.

## Why this project

Most "password strength meters" just check length and character
classes. This one goes a step further:

- **Entropy-based scoring** — estimates real bit-strength, not just a
  checklist.
- **Pattern detection** — catches sequential runs (`abc`, `321`),
  repeated characters (`aaa`), and keyboard walks (`qwerty`, `asdf`)
  that naive checkers miss.
- **Common password matching** — flags passwords found in known
  breach/weak-password lists, regardless of how "complex" they look.
- **A working crack-time demo** — instead of just claiming weak
  passwords are dangerous, it hashes sample passwords with SHA-256 and
  times how long a small mutated dictionary takes to recover each one.

## ⚠️ Scope & ethics

The cracking demo **only ever attacks hashes it generates itself, in
memory, within the same script run.** It does not accept external
hashes, does not target real accounts or systems, and is not a
general-purpose cracking tool. It exists purely to visualize the time
difference between cracking a weak password and a strong one. Do not
repurpose this code against systems or accounts you don't own or have
explicit permission to test.

## Project structure

```
password-security-toolkit/
├── src/
│   ├── strength_checker.py   # Entropy + pattern-based strength scorer
│   └── crack_demo.py         # Self-contained dictionary-attack timing demo
├── data/
│   └── common_passwords.txt  # ~100 common/weak passwords used for checks & demo
├── tests/
│   └── test_strength_checker.py
├── examples/
│   └── sample_output.md      # Example runs / output for the README & portfolio
├── requirements.txt
└── README.md
```

## Getting started

```bash
git clone https://github.com/<your-username>/password-security-toolkit.git
cd password-security-toolkit
python3 src/strength_checker.py
```

No external dependencies are required — everything uses Python's
standard library (`hashlib`, `math`, `re`, `time`).

### Check a single password

```bash
python3 src/strength_checker.py "MyP@ssw0rd!"
```

```
==================================================
 Password Strength Report — M**********!
==================================================
 Length:        12 characters
 Entropy:       78.53 bits
 Score:         71 / 100
 Rating:        Strong
 Issues:
   - No significant weaknesses detected.
==================================================
```

### Run the crack-time demo

```bash
python3 src/crack_demo.py
```

This hashes a few sample passwords (weak → strong) and shows how many
attempts and how much time it takes a small mutated dictionary to
recover each one, plus an estimated brute-force time for anything that
survives the dictionary.

### Run the tests

```bash
python3 -m unittest discover tests -v
```

## How the scoring works

| Component            | Weight     | What it checks                                          |
|-----------------------|-----------|----------------------------------------------------------|
| Length                | up to 25  | Longer passwords score higher, with diminishing returns  |
| Character variety     | up to 25  | Presence of lowercase, uppercase, digits, symbols         |
| Entropy               | up to 30  | `length × log2(character pool size)`                      |
| Pattern penalties     | −10 each  | Sequential runs, repeated chars, keyboard walks           |
| Common password match | severe    | Caps score at 5 if found in the common-password list      |

Final score (0–100) maps to a rating: **Very Weak → Weak → Moderate →
Strong → Very Strong**.

## Possible extensions

- Swap the bundled 100-word list for a real breach corpus (e.g. a
  trimmed `rockyou.txt`) for a more realistic common-password check.
- Add a simple Flask/CLI front end so non-technical users can check a
  password without touching the terminal.
- Integrate [zxcvbn](https://github.com/dropbox/zxcvbn) for a
  second, industry-standard entropy estimate to compare against.
- Add Have I Been Pwned's k-anonymity API to check against real
  breached-password hash ranges (no plaintext ever leaves your
  machine).

## License

MIT — see [LICENSE](LICENSE).
