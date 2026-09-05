"""The exit code reports whether the TOOL ran, not whether the report is suspect.

Measured across 557 curl reports: the best threshold on any metric scored
Youden J = 0.155 (J = 0 is a coin flip). There is no gate to tune, so exit 0
means "produced a report" and exit 2 means "could not run".
"""
import subprocess
import pytest

from slopcheck.cli import main


def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "p"; r.mkdir()
    git(r, "init", "-q"); git(r, "config", "user.email", "t@e.invalid")
    git(r, "config", "user.name", "t")
    (r / "real.c").write_text("int real_function(void){return 0;}\n")
    git(r, "add", "-A"); git(r, "commit", "-q", "-m", "init")
    return r


@pytest.fixture
def bogus_report(tmp_path):
    p = tmp_path / "r.txt"
    p.write_text("Overflow in lib/invented.c line 99999 via totally_made_up_fn()")
    return p


def test_contradictions_alone_do_not_fail(repo, bogus_report, capsys):
    """A report full of contradictions still exits 0. The tool ran."""
    rc = main([str(bogus_report), "--repo", str(repo)])
    assert rc == 0
    assert "CONTRADICTED" in capsys.readouterr().out


def test_opt_in_flag_restores_the_old_gate(repo, bogus_report):
    rc = main([str(bogus_report), "--repo", str(repo), "--fail-on-contradiction"])
    assert rc == 1


def test_opt_in_flag_still_passes_a_clean_report(repo, tmp_path):
    p = tmp_path / "clean.txt"
    p.write_text("Issue in real.c involving real_function()")
    assert main([str(p), "--repo", str(repo), "--fail-on-contradiction"]) == 0


def test_unresolvable_ref_is_a_tool_error(repo, bogus_report, capsys):
    rc = main([str(bogus_report), "--repo", str(repo), "--ref", "no-such-ref"])
    assert rc == 2
    assert "cannot resolve ref" in capsys.readouterr().err


def test_claims_only_exits_zero(repo, bogus_report):
    assert main([str(bogus_report), "--repo", str(repo), "--claims-only"]) == 0
