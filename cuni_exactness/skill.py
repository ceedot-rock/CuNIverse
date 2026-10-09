"""Core of the CuNi exactness skill: submit() and the Verdict type."""

from __future__ import annotations

import difflib
import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Absolute path to the real CuNi compiler binary.
CUNI_BIN = Path.home() / "workspace" / "cuni-langs" / "target" / "debug" / "cuni"

# Seats this skill can actually run: only seats whose toolchain exists on
# this machine. Verified present: python3, node, ruby, lua, gcc, g++.
# Seats without a local toolchain are reported as skipped -- never faked.
_SEAT_TOOLCHAIN = {
    "py": "python3",
    "js": "node",
    "rb": "ruby",
    "lua": "lua",
    "c": "gcc",
    "cpp": "g++",
}

# Default run order (stable, so the reference seat is deterministic).
DEFAULT_SEATS = ["py", "js", "rb", "lua", "c", "cpp"]

# File extension the compiler writes per seat.
_SEAT_EXT = {"py": "py", "js": "js", "rb": "rb", "lua": "lua", "c": "c", "cpp": "cpp"}


@dataclass
class SeatResult:
    seat: str
    ok: bool
    stdout: bytes = b""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False


@dataclass
class Verdict:
    """The skill's answer.

    status is "EXACT" or "REFUSE".
    EXACT: every seat that ran printed byte-identical stdout. `proof` holds
        {source_sha256, seats_run, output_sha256, stdout}.
    REFUSE: something diverged or failed. `reason` is a short machine-usable
        tag; `detail` is human/agent-readable; `diff` holds unified diffs of
        each divergent seat vs the reference seat; `divergent` maps seat ->
        that seat's stdout text.
    `skipped` lists requested seats with no local toolchain.
    """

    status: str
    reason: str = ""
    detail: str = ""
    proof: dict = field(default_factory=dict)
    diff: str = ""
    divergent: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)

    @property
    def exact(self) -> bool:
        return self.status == "EXACT"


def _toolchain_available(seat: str) -> bool:
    tool = _SEAT_TOOLCHAIN.get(seat)
    return bool(tool) and shutil.which(tool) is not None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _emit(cuni_bin: Path, source_file: Path, seat: str, out_file: Path) -> tuple[bool, str]:
    """Emit one seat. Returns (ok, compiler_output)."""
    proc = subprocess.run(
        [str(cuni_bin), str(source_file), "--emit", seat, str(out_file)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0 and out_file.exists(), output.strip()


def _run_emitted(seat: str, emitted: Path, workdir: Path, timeout: int) -> SeatResult:
    """Run one emitted program; capture stdout bytes. Never raises."""
    res = SeatResult(seat=seat, ok=False)
    try:
        if seat in ("py", "js", "rb", "lua"):
            cmd = [_SEAT_TOOLCHAIN[seat], str(emitted)]
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=workdir)
        elif seat in ("c", "cpp"):
            compiler = _SEAT_TOOLCHAIN[seat]
            binary = workdir / f"run_{seat}"
            comp = subprocess.run(
                [compiler, "-O2", "-o", str(binary), str(emitted)],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=workdir,
            )
            if comp.returncode != 0:
                res.stderr = f"compile failed: {(comp.stderr or '').strip()[:2000]}"
                res.exit_code = comp.returncode
                return res
            proc = subprocess.run([str(binary)], capture_output=True, timeout=timeout, cwd=workdir)
        else:  # pragma: no cover - guarded by caller
            res.stderr = f"no runner for seat {seat!r}"
            return res
        res.exit_code = proc.returncode
        res.stdout = proc.stdout or b""
        if proc.returncode != 0:
            res.stderr = (proc.stderr or b"").decode("utf-8", "replace")[:2000]
            return res
        res.ok = True
        return res
    except subprocess.TimeoutExpired:
        res.timed_out = True
        res.stderr = f"seat {seat!r} exceeded the {timeout}s timeout"
        return res
    except OSError as exc:  # toolchain vanished mid-run, etc.
        res.stderr = f"seat {seat!r} could not run: {exc}"
        return res


def _unified_diff_text(reference: bytes, other: bytes, ref_name: str, other_name: str) -> str:
    ref_lines = reference.decode("utf-8", "replace").splitlines(keepends=True)
    other_lines = other.decode("utf-8", "replace").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            ref_lines,
            other_lines,
            fromfile=ref_name,
            tofile=other_name,
        )
    )


def submit(
    source: str,
    seats: list[str] | None = None,
    timeout: int = 30,
) -> Verdict:
    """Submit CuNi source; get back EXACT or REFUSE.

    source: CuNi source code text.
    seats: language seats to verify (default: all seats with a local
        toolchain). Unknown seats or seats without a toolchain are
        reported in `skipped`, never faked.
    timeout: per-seat run timeout in seconds.
    """
    if not isinstance(source, str) or not source.strip():
        return Verdict(
            status="REFUSE",
            reason="empty_source",
            detail="No CuNi source was submitted. Provide CuNi source code text.",
        )
    if not CUNI_BIN.exists():
        return Verdict(
            status="REFUSE",
            reason="compiler_missing",
            detail=f"The CuNi compiler was not found at {CUNI_BIN}.",
        )

    requested = list(seats) if seats else list(DEFAULT_SEATS)
    runnable = [s for s in requested if s in _SEAT_TOOLCHAIN and _toolchain_available(s)]
    skipped = [s for s in requested if s not in runnable]
    if not runnable:
        return Verdict(
            status="REFUSE",
            reason="no_seats",
            detail=(
                "No requested seat has a usable toolchain on this machine. "
                f"Skipped: {', '.join(skipped) or 'none'}."
            ),
            skipped=skipped,
        )

    source_bytes = source.encode("utf-8")
    source_hash = _sha256_hex(source_bytes)

    with tempfile.TemporaryDirectory(prefix="cuni_exactness_") as tmp:
        workdir = Path(tmp)
        source_file = workdir / "source.cuni"
        source_file.write_bytes(source_bytes)

        results: list[SeatResult] = []
        for seat in runnable:
            emitted = workdir / f"out.{_SEAT_EXT[seat]}"
            ok, compiler_output = _emit(CUNI_BIN, source_file, seat, emitted)
            if not ok:
                return Verdict(
                    status="REFUSE",
                    reason="emit_failed",
                    detail=(
                        f"CuNi refused to emit seat {seat!r}. Compiler said: "
                        f"{compiler_output[:2000] or '(no output)'}"
                    ),
                    skipped=skipped,
                )
            results.append(_run_emitted(seat, emitted, workdir, timeout))

        failed = [r for r in results if not r.ok]
        if failed:
            r = failed[0]
            why = "timed out" if r.timed_out else f"exited with code {r.exit_code}"
            return Verdict(
                status="REFUSE",
                reason="run_failed",
                detail=(
                    f"Seat {r.seat!r} {why}. Stderr: {r.stderr[:2000] or '(empty)'}"
                ),
                skipped=skipped,
            )

        reference = results[0]
        divergent = [r for r in results[1:] if r.stdout != reference.stdout]
        if not divergent:
            out = reference.stdout
            return Verdict(
                status="EXACT",
                reason="byte_identical",
                detail=(
                    f"All {len(results)} seats printed byte-identical stdout "
                    f"({len(out)} bytes)."
                ),
                proof={
                    "source_sha256": source_hash,
                    "seats_run": [r.seat for r in results],
                    "output_sha256": _sha256_hex(out),
                    "stdout": out.decode("utf-8", "replace"),
                },
                skipped=skipped,
            )

        diffs = []
        div_map = {}
        for r in divergent:
            div_map[r.seat] = r.stdout.decode("utf-8", "replace")
            diffs.append(
                _unified_diff_text(
                    reference.stdout, r.stdout,
                    f"reference({reference.seat})", f"divergent({r.seat})",
                )
            )
        return Verdict(
            status="REFUSE",
            reason="divergent_output",
            detail=(
                f"{len(divergent)} of {len(results)} seats printed different "
                f"stdout than the reference seat {reference.seat!r}. "
                f"Divergent: {', '.join(r.seat for r in divergent)}."
            ),
            diff="\n".join(diffs),
            divergent=div_map,
            skipped=skipped,
        )
