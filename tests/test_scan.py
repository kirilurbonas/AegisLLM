"""The scan gate must stop a real attack, not just report on clean models."""

from __future__ import annotations

import pytest

from supplychain import convert, scan


@pytest.mark.parametrize("staged", ["malicious_checkpoint"], indirect=True)
def test_malicious_checkpoint_is_blocked(staged):
    report = scan.run(staged)

    assert report["verdict"] == "FAIL"
    assert report["blocking_findings"], "a code-exec payload produced no findings"
    # Both scanners should independently notice this one.
    assert any("system" in f for f in report["blocking_findings"])
    assert report["picklescan"]["infected_files"] >= 1


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_benign_checkpoint_passes(staged):
    report = scan.run(staged)

    assert report["verdict"] == "PASS"
    assert report["blocking_findings"] == []


@pytest.mark.parametrize("staged", ["malicious_checkpoint"], indirect=True)
def test_convert_refuses_a_flagged_model(staged):
    """The gate has to hold across stages — a FAIL verdict blocks conversion."""
    scan.run(staged)

    with pytest.raises(RuntimeError, match="refusing to convert"):
        convert.run(staged)


@pytest.mark.parametrize("staged", ["benign_checkpoint"], indirect=True)
def test_coverage_gaps_do_not_include_archive_members(staged):
    """Tensor streams inside a checkpoint are not scanner blind spots."""
    report = scan.run(staged)

    assert all(":" not in gap for gap in report["coverage_gaps"])
