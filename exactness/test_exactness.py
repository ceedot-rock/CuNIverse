"""Tests for the CuNi exactness skill. All run against the real compiler."""

import hashlib
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cuni_exactness import Verdict, submit
from cuni_exactness import skill as skill_mod

MINI_PROGRAM = 'say(1 + 2)\nsay("hello")\n'

DECIMAL_PROGRAM = """\
def fee(amount: dec, rate: dec) -> dec do
    ret amount * rate
end
say(fee(100.00dec, 0.0050dec))
say(fee(7.50dec, 0.10dec))
"""


def test_exact_end_to_end_py_js():
    v = submit(MINI_PROGRAM, seats=["py", "js"], timeout=30)
    assert v.status == "EXACT", v.detail
    assert v.exact is True
    # Proof hashes recomputed independently in the test, not trusted from the skill.
    assert v.proof["source_sha256"] == hashlib.sha256(MINI_PROGRAM.encode()).hexdigest()
    assert v.proof["seats_run"] == ["py", "js"]
    assert v.proof["output_sha256"] == hashlib.sha256(b"3\nhello\n").hexdigest()
    assert v.proof["stdout"] == "3\nhello\n"
    assert v.skipped == []


def test_exact_decimal_program_four_seats():
    v = submit(DECIMAL_PROGRAM, seats=["py", "js", "rb", "lua"], timeout=30)
    assert v.status == "EXACT", v.detail
    assert v.proof["seats_run"] == ["py", "js", "rb", "lua"]
    # Independent recomputation of the expected stdout.
    expected = b"0.5\n0.75\n"
    assert v.proof["output_sha256"] == hashlib.sha256(expected).hexdigest()


def test_refuse_on_divergent_output():
    """Synthetic divergence: monkeypatched runners, real verdict logic."""
    real_emit = skill_mod._emit
    real_run = skill_mod._run_emitted

    def fake_emit(cuni_bin, source_file, seat, out_file):
        out_file.write_bytes(b"# fake")
        return True, ""

    def fake_run(seat, emitted, workdir, timeout):
        from cuni_exactness.skill import SeatResult

        out = b"3\nhello\n" if seat == "py" else b"3\nHELLO\n"
        return SeatResult(seat=seat, ok=True, stdout=out, exit_code=0)

    skill_mod._emit = fake_emit
    skill_mod._run_emitted = fake_run
    try:
        v = submit(MINI_PROGRAM, seats=["py", "js"], timeout=30)
    finally:
        skill_mod._emit = real_emit
        skill_mod._run_emitted = real_run

    assert v.status == "REFUSE"
    assert v.reason == "divergent_output"
    assert "js" in v.detail  # names the divergent seat
    assert "divergent(js)" in v.diff
    assert "-hello" in v.diff and "+HELLO" in v.diff
    assert v.divergent["js"] == "3\nHELLO\n"


def test_refuse_on_invalid_source():
    v = submit("garbage ((( not cuni", seats=["py"], timeout=30)
    assert v.status == "REFUSE"
    assert v.reason == "emit_failed"
    assert "parse error" in v.detail  # compiler's own words, surfaced


def test_refuse_on_empty_source():
    v = submit("   ", seats=["py"])
    assert v.status == "REFUSE"
    assert v.reason == "empty_source"


def test_seat_without_toolchain_is_skipped_not_faked():
    v = submit(MINI_PROGRAM, seats=["py", "go"], timeout=30)
    # "go" has no local toolchain: skipped, verdict computed over py alone.
    assert "go" in v.skipped
    assert v.status == "EXACT"
    assert v.proof["seats_run"] == ["py"]


def test_unknown_seat_is_skipped():
    v = submit(MINI_PROGRAM, seats=["py", "klingon"], timeout=30)
    assert "klingon" in v.skipped
    assert v.status == "EXACT"


def test_timeout_is_handled_not_hung():
    workdir = Path("/tmp")
    sleeper = workdir / "exactness_sleeper.py"
    sleeper.write_text("import time\ntime.sleep(60)\n")
    start = time.monotonic()
    try:
        res = skill_mod._run_emitted("py", sleeper, workdir, timeout=2)
    finally:
        sleeper.unlink(missing_ok=True)
    elapsed = time.monotonic() - start
    assert res.timed_out is True
    assert res.ok is False
    assert elapsed < 20, f"timeout handling took too long: {elapsed:.1f}s"


def test_unified_diff_builder():
    d = skill_mod._unified_diff_text(b"a\nb\n", b"a\nc\n", "ref", "other")
    assert "--- ref" in d and "+++ other" in d
    assert "-b" in d and "+c" in d


def test_verdict_exact_property():
    assert Verdict(status="EXACT").exact is True
    assert Verdict(status="REFUSE").exact is False
