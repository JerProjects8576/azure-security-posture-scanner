"""Data types shared by the rules, the scanner and the reporters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.lower())
        except ValueError as exc:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity '{value}', choose from: {choices}") from exc


@dataclass(frozen=True)
class Resource:
    """One Azure resource in the shape returned by Azure Resource Graph."""

    id: str
    name: str
    type: str
    properties: dict[str, Any]
    location: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Resource:
        if not isinstance(raw, dict):
            raise ValueError("every resource must be a JSON object")
        missing = [k for k in ("id", "type") if not raw.get(k)]
        if missing:
            raise ValueError(f"resource is missing required field(s): {', '.join(missing)}")
        rid = str(raw["id"])
        return cls(
            id=rid,
            name=str(raw.get("name") or rid.rsplit("/", 1)[-1]),
            type=str(raw["type"]).lower(),
            properties=raw.get("properties") or {},
            location=str(raw.get("location") or ""),
        )


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    resource_type: str
    description: str
    remediation: str
    mitre: str


@dataclass(frozen=True)
class Finding:
    rule: Rule
    resource: Resource
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity.value,
            "resource_id": self.resource.id,
            "resource_name": self.resource.name,
            "resource_type": self.resource.type,
            "detail": self.detail,
            "remediation": self.rule.remediation,
            "mitre_attack": self.rule.mitre,
        }
