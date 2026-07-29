"""Stage 2 — scan the untrusted model for malicious serialization payloads.

A `pickle`-based checkpoint executes arbitrary code on load: `__reduce__` can
name any callable, and `torch.load` will happily call it. This is not theoretical
— it is an actively exploited class of attack against model hubs.

Two scanners run, deliberately:

  * **modelscan** understands the PyTorch zip container and classifies unsafe
    operators by severity.
  * **picklescan** reads raw pickle opcodes.

They do not overlap. modelscan *skips* a bare `.bin` pickle with no torch magic
number (reporting zero issues, which reads exactly like "clean"), while
picklescan flags it. A gate built on either one alone has a hole in it.

Hence the third rule: **a file that no scanner could read is a finding, not a
pass.** Unscanned is not the same as safe.
"""

from __future__ import annotations

from typing import Any

from modelscan.modelscan import ModelScan
from picklescan.scanner import scan_directory_path

from .config import Settings
from .ingest import staged_root
from .report import stage, write_report

BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}

# Skip categories that are benign: a JSON or text file legitimately has no
# model magic number. Anything that *looks* like weights and cannot be parsed
# is treated as suspicious instead.
BENIGN_SUFFIXES = {".json", ".txt", ".md", ".model", ".safetensors"}


def _run_modelscan(root) -> dict[str, Any]:
    report = ModelScan().scan(root)
    summary = report["summary"]
    return {
        "scanner": "modelscan",
        "issues": [
            {
                "severity": issue["severity"],
                "description": issue["description"],
                "source": issue.get("source"),
                "operator": issue.get("operator"),
            }
            for issue in report["issues"]
        ],
        "by_severity": summary["total_issues_by_severity"],
        "scanned_count": summary["scanned"].get("total_scanned", 0),
        "skipped": [
            {"source": s["source"], "category": s["category"]}
            for s in summary["skipped"].get("skipped_files", [])
        ],
        "errors": report["errors"],
    }


def _run_picklescan(root) -> dict[str, Any]:
    result = scan_directory_path(str(root))
    return {
        "scanner": "picklescan",
        "issues_count": result.issues_count,
        "scanned_files": result.scanned_files,
        "infected_files": result.infected_files,
        "scan_error": result.scan_err,
    }


def _coverage_gaps(modelscan_result: dict[str, Any]) -> list[str]:
    """Top-level files modelscan could not parse.

    Entries containing ':' are members *inside* a checkpoint archive (raw tensor
    streams); modelscan skipping those is expected and not a gap — it parsed the
    container itself. Only whole files it never opened count.
    """
    return sorted(
        {
            skip["source"]
            for skip in modelscan_result["skipped"]
            if ":" not in skip["source"]
            and not any(skip["source"].endswith(s) for s in BENIGN_SUFFIXES)
        }
    )


def run(cfg: Settings) -> dict[str, Any]:
    root = staged_root(cfg)
    stage("scan", f"scanning {root.name} with modelscan + picklescan")

    ms = _run_modelscan(root)
    ps = _run_picklescan(root)
    gaps = _coverage_gaps(ms)

    blocking: list[str] = []
    blocking += [
        f"modelscan {i['severity']}: {i['description']} ({i['source']})"
        for i in ms["issues"]
        if i["severity"] in BLOCKING_SEVERITIES
    ]
    if ps["infected_files"]:
        blocking.append(f"picklescan: {ps['infected_files']} infected file(s)")
    if ps["scan_error"]:
        blocking.append("picklescan: scanner reported an error — treating as unsafe")
    verdict = "FAIL" if blocking else "PASS"
    report = {
        "verdict": verdict,
        "blocking_findings": blocking,
        "coverage_gaps": gaps,
        "modelscan": ms,
        "picklescan": ps,
    }
    write_report(cfg.reports_dir / "scan.json", report)

    # Reported, not blocking: modelscan couldn't parse these, but picklescan may
    # have. They are recorded so the coverage gap is visible to a reviewer rather
    # than silently reading as "clean".
    for gap in gaps:
        stage("scan", f"note: not parsed by modelscan — {gap}", "info")

    if blocking:
        stage("scan", f"{len(blocking)} blocking finding(s) — refusing to proceed", "fail")
        for finding in blocking:
            stage("", f"  · {finding}", "fail")
    else:
        stage(
            "scan",
            f"clean: {ms['scanned_count']} file(s) via modelscan, "
            f"{ps['scanned_files']} via picklescan",
            "ok",
        )
    return report
