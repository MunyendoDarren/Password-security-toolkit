# Sample Output

Real output captured from running the toolkit locally. Useful for a
GitHub README, portfolio writeup, or LinkedIn post.

## Strength checker — weak, moderate, and strong examples

```
$ python3 src/strength_checker.py "password"

==================================================
 Password Strength Report — p******d
==================================================
 Length:        8 characters
 Entropy:       37.6 bits
 Score:         5 / 100
 Rating:        Very Weak
 Issues:
   - Low character variety — mix uppercase, lowercase, numbers, and symbols.
   - This password appears in common/breached password lists — do not use it.
==================================================
```

```
$ python3 src/strength_checker.py "Summer2024"

==================================================
 Password Strength Report — S********4
==================================================
 Length:        10 characters
 Entropy:       59.54 bits
 Score:         45 / 100
 Rating:        Moderate
 Issues:
   - No significant weaknesses detected.
==================================================
```

```
$ python3 src/strength_checker.py "xK9\$mQ2#vL7pR4z!"

==================================================
 Password Strength Report — x**************!
==================================================
 Length:        16 characters
 Entropy:       104.87 bits
 Score:         80 / 100
 Rating:        Strong
 Issues:
   - No significant weaknesses detected.
==================================================
```

## Crack-time demo

```
$ python3 src/crack_demo.py

============================================================
 Password Cracking Demo (educational, self-contained)
============================================================
This hashes a few sample passwords locally, then times how long
a small dictionary attack takes to recover each one — no real
accounts, systems, or third-party data are involved.

Loaded a mutated wordlist of 1,614 candidates.

Target: 1*****  (SHA-256: 8d969eef6ecad3c2...)
  -> Cracked in 1 attempts / 0.0000 seconds.
------------------------------------------------------------
Target: p********  (SHA-256: 0b14d501a594442a...)
  -> Cracked in 36 attempts / 0.0000 seconds.
------------------------------------------------------------
Target: S*********  (SHA-256: adfab358825331b1...)
  -> Cracked in 903 attempts / 0.0005 seconds.
------------------------------------------------------------
Target: x***********  (SHA-256: b24532dd3e9ad560...)
  -> Not found in dictionary after 1,614 attempts (0.0008s).
  -> Estimated brute-force time at 10B guesses/sec: ~15,091.3 centuries
------------------------------------------------------------

Takeaway: common or lightly-mutated passwords fall to a small
dictionary in milliseconds, while a long, random password pushes
the estimated crack time into years or centuries — even against
a fast offline attacker.
```

**Key takeaway to highlight in a portfolio/README:** the first three
passwords — including one that "looks" reasonably complex
(`Summer2024`) — all fall to a dictionary of ~1,600 mutated common
words in under a millisecond. Only the fully random 16-character
password survives, with an estimated brute-force time in the
centuries.
