"""Turn a scan result into text for people or machines."""

from __future__ import annotations

import json

from . import __version__
from .models import Severity
from .rules import RULES
from .scanner import ScanResult

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _summary(result: ScanResult) -> str:
    counts = result.counts()
    parts = ", ".join(f"{counts[s.value]} {s.value}" for s in reversed(list(Severity)))
    return (
        f"{len(result.findings)} finding(s) in {result.resources_scanned} resource(s) "
        f"({parts}); {result.resources_skipped} resource(s) of unsupported types skipped"
    )


def to_table(result: ScanResult) -> str:
    if not result.findings:
        return "No findings.\n" + _summary(result) + "\n"
    rows = [("SEVERITY", "RULE", "RESOURCE", "DETAIL")]
    rows += [
        (f.rule.severity.value.upper(), f.rule.id, f.resource.name, f.detail)
        for f in result.findings
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = ["  ".join(r[i].ljust(widths[i]) for i in range(3)) + "  " + r[3] for r in rows]
    return "\n".join(lines) + "\n\n" + _summary(result) + "\n"


def to_markdown(result: ScanResult) -> str:
    out = ["# Azure security posture report", "", _summary(result), ""]
    if not result.findings:
        out.append("No findings.")
        return "\n".join(out) + "\n"
    out += [
        "| Severity | Rule | Resource | Detail | Fix |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in result.findings:
        out.append(
            f"| {f.rule.severity.value} | {f.rule.id} {f.rule.title} | `{f.resource.name}` "
            f"| {f.detail} | {f.rule.remediation} |"
        )
    return "\n".join(out) + "\n"


def to_json(result: ScanResult) -> str:
    payload = {
        "summary": {
            "findings": len(result.findings),
            "resources_scanned": result.resources_scanned,
            "resources_skipped": result.resources_skipped,
            "by_severity": result.counts(),
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def to_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.title,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.remediation},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"severity": r.severity.value, "mitre-attack": r.mitre},
        }
        for r, _ in RULES
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.rule.severity],
            "message": {"text": f"{f.resource.name}: {f.detail}"},
            "locations": [
                {"logicalLocations": [{"fullyQualifiedName": f.resource.id, "kind": "resource"}]}
            ],
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "azposture",
                        "version": __version__,
                        "informationUri": "https://github.com/JerProjects8576/azure-security-posture-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


FORMATS = {"table": to_table, "markdown": to_markdown, "json": to_json, "sarif": to_sarif}
