# CuNi Exactness Skill — Review Note

## What it does

You hand it CuNi source code. It builds that code for every programming
language it can run on this machine, runs each one, and compares what they
print — byte for byte. Then it gives you one of two answers:

- **EXACT** — every language printed exactly the same output. The answer
  comes with proof: a fingerprint (SHA-256) of your source, the list of
  languages that ran, and a fingerprint of the identical output.
- **REFUSE** — something didn't match, or the code wouldn't build. You get
  the reason in plain words, and when outputs diverged, a side-by-side diff
  showing which language differed and how. It also refuses cleanly on bad
  input instead of crashing.

If you ask for a language whose tools aren't installed here (like Go), it
doesn't fake it — it tells you that seat was skipped and judges only the
seats that actually ran.

## How to call it

```python
from cuni_exactness import submit

verdict = submit('say(1 + 2)\nsay("hello")\n')
verdict.status        # "EXACT" or "REFUSE"
verdict.proof         # fingerprints + the common output (when EXACT)
verdict.diff          # side-by-side diff (when outputs diverged)
verdict.detail        # plain-words explanation, always present
```

Optional: `submit(source, seats=["py", "js"], timeout=30)` to pick
languages or change the per-language time limit.

## What the tests prove (all measured, nothing assumed)

10 tests, all passing (`pytest test_exactness.py` — 10 passed, ~3 seconds):

- A small program across Python + JavaScript comes back **EXACT**, and the
  test recomputes both fingerprints itself rather than trusting the skill.
- A decimal-money program across Python, JavaScript, Ruby, and Lua comes
  back **EXACT** with matching fingerprints — real money math, identical
  in four languages.
- Forced divergence (one seat printing `HELLO` instead of `hello`) comes
  back **REFUSE**, names the divergent seat, and the diff shows the exact
  differing line.
- Garbage input comes back **REFUSE** with the compiler's own parse error
  surfaced — no crash, and the message tells you what went wrong.
- Requesting Go (no toolchain here) reports it skipped and still judges
  the seats that ran.
- A hanging program is cut off at the timeout (2s in the test) and
  reported, instead of hanging the whole run.

Live smoke test just now: the sample program across all six local seats
(Python, JavaScript, Ruby, Lua, C, C++) — **EXACT, byte-identical
everywhere.**

## Honest limits

- It can only verify languages whose tools are installed where it runs.
  Here that's six; the full CuNi catalog is bigger.
- It compares program output, not behavior over time — a program that
  reads the clock or the network can differ run to run for reasons that
  aren't bugs. Deterministic programs are the sweet spot.
- The skill needs the CuNi compiler present at its known location; if
  it's missing you get a clean REFUSE explaining that.
