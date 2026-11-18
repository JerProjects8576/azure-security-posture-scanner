"""Load resources and run every rule against them."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, Resource, Severity
from .rules import evaluate, supported_types


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    resources_skipped: int = 0

    def at_or_above(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.findings if f.rule.severity.rank >= minimum.rank]

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.rule.severity.value] += 1
        return counts


def parse_resources(data: Any) -> list[Resource]:
    """Accept a plain list, or the {"data": [...]} shape of `az graph query`."""
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        data = data["data"]
    if not isinstance(data, list):
        raise ValueError('expected a JSON list of resources or an object with a "data" list')
    return [Resource.from_dict(item) for item in data]


def load_resources(path: str | Path) -> list[Resource]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    return parse_resources(data)


def scan(resources: Iterable[Resource], minimum: Severity = Severity.LOW) -> ScanResult:
    result = ScanResult()
    known = supported_types()
    for resource in resources:
        if resource.type not in known:
            result.resources_skipped += 1
            continue
        result.resources_scanned += 1
        result.findings.extend(
            f for f in evaluate(resource) if f.rule.severity.rank >= minimum.rank
        )
    result.findings.sort(key=lambda f: (-f.rule.severity.rank, f.rule.id, f.resource.id))
    return result
