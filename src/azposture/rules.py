"""Security rules.

Each rule is a function that receives one resource and returns a list of findings
(usually zero or one). Rules are registered with the ``@rule`` decorator and only run
against resources of their own ``resource_type``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .models import Finding, Resource, Rule, Severity

Check = Callable[[Resource], list[str]]

RULES: list[tuple[Rule, Check]] = []

STORAGE = "microsoft.storage/storageaccounts"
KEY_VAULT = "microsoft.keyvault/vaults"
NSG = "microsoft.network/networksecuritygroups"
WEB_APP = "microsoft.web/sites"
SQL_SERVER = "microsoft.sql/servers"
SQL_FIREWALL = "microsoft.sql/servers/firewallrules"

INTERNET_SOURCES = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", "::/0"}
WEAK_TLS = {"tls1_0", "tls1_1", "1.0", "1.1"}


def rule(
    rule_id: str,
    title: str,
    severity: Severity,
    resource_type: str,
    description: str,
    remediation: str,
    mitre: str,
) -> Callable[[Check], Check]:
    def register(check: Check) -> Check:
        RULES.append(
            (
                Rule(rule_id, title, severity, resource_type, description, remediation, mitre),
                check,
            )
        )
        return check

    return register


def _get(props: dict[str, Any], *path: str, default: Any = None) -> Any:
    """Read a nested property, ignoring the casing of the keys."""
    current: Any = props
    for key in path:
        if not isinstance(current, dict):
            return default
        match = next((k for k in current if k.lower() == key.lower()), None)
        if match is None:
            return default
        current = current[match]
    return current


def _is_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.lower() == "false")


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


# --- Storage accounts -------------------------------------------------------------------


@rule(
    "AZ-STG-001",
    "Storage account allows anonymous blob access",
    Severity.HIGH,
    STORAGE,
    "Containers in this account can be made public, so anyone with the URL can read blobs.",
    "Set allowBlobPublicAccess to false on the storage account.",
    "T1530 Data from Cloud Storage",
)
def storage_public_blob(res: Resource) -> list[str]:
    if _is_true(_get(res.properties, "allowBlobPublicAccess")):
        return ["allowBlobPublicAccess is true"]
    return []


@rule(
    "AZ-STG-002",
    "Storage account accepts unencrypted HTTP",
    Severity.MEDIUM,
    STORAGE,
    "Data can travel over plain HTTP and be read or changed on the way.",
    "Set supportsHttpsTrafficOnly to true.",
    "T1557 Adversary-in-the-Middle",
)
def storage_http(res: Resource) -> list[str]:
    if _is_false(_get(res.properties, "supportsHttpsTrafficOnly")):
        return ["supportsHttpsTrafficOnly is false"]
    return []


@rule(
    "AZ-STG-003",
    "Storage account allows TLS older than 1.2",
    Severity.MEDIUM,
    STORAGE,
    "Old TLS versions have known weaknesses.",
    "Set minimumTlsVersion to TLS1_2.",
    "T1557 Adversary-in-the-Middle",
)
def storage_tls(res: Resource) -> list[str]:
    version = _get(res.properties, "minimumTlsVersion")
    if isinstance(version, str) and version.lower() in WEAK_TLS:
        return [f"minimumTlsVersion is {version}"]
    return []


# --- Key Vault --------------------------------------------------------------------------


@rule(
    "AZ-KV-001",
    "Key Vault purge protection is disabled",
    Severity.MEDIUM,
    KEY_VAULT,
    "A deleted vault or secret can be purged for good, so an attacker can destroy keys.",
    "Enable purge protection (enablePurgeProtection: true). This cannot be turned off later.",
    "T1485 Data Destruction",
)
def keyvault_purge(res: Resource) -> list[str]:
    if not _is_true(_get(res.properties, "enablePurgeProtection")):
        return ["enablePurgeProtection is not enabled"]
    return []


@rule(
    "AZ-KV-002",
    "Key Vault is reachable from the whole internet",
    Severity.HIGH,
    KEY_VAULT,
    "Public network access is on and the firewall does not deny by default.",
    "Disable public network access and use a private endpoint, or set networkAcls.defaultAction "
    "to Deny with explicit allowed networks.",
    "T1555.006 Credentials from Cloud Secrets Management Stores",
)
def keyvault_public(res: Resource) -> list[str]:
    public = str(_get(res.properties, "publicNetworkAccess", default="Enabled"))
    default_action = str(_get(res.properties, "networkAcls", "defaultAction", default="Allow"))
    if public.lower() != "disabled" and default_action.lower() != "deny":
        return [
            f"publicNetworkAccess is {public} and networkAcls.defaultAction is {default_action}"
        ]
    return []


# --- Network security groups ------------------------------------------------------------


def _port_ranges(rule_props: dict[str, Any]) -> list[str]:
    ranges = []
    single = _get(rule_props, "destinationPortRange")
    if single:
        ranges.append(str(single))
    ranges.extend(str(r) for r in _get(rule_props, "destinationPortRanges", default=[]) or [])
    return ranges


def _covers(port_range: str, port: int) -> bool:
    port_range = port_range.strip()
    if port_range == "*":
        return True
    if "-" in port_range:
        low, _, high = port_range.partition("-")
        return low.isdigit() and high.isdigit() and int(low) <= port <= int(high)
    return port_range.isdigit() and int(port_range) == port


def _sources(rule_props: dict[str, Any]) -> list[str]:
    sources = []
    single = _get(rule_props, "sourceAddressPrefix")
    if single:
        sources.append(str(single))
    sources.extend(str(s) for s in _get(rule_props, "sourceAddressPrefixes", default=[]) or [])
    return sources


def _open_inbound_rules(res: Resource) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield (name, properties) of inbound Allow rules that accept traffic from the internet."""
    for sec_rule in _get(res.properties, "securityRules", default=[]) or []:
        props = _get(sec_rule, "properties", default=sec_rule) or {}
        if str(_get(props, "access", default="")).lower() != "allow":
            continue
        if str(_get(props, "direction", default="")).lower() != "inbound":
            continue
        if not any(s.lower() in INTERNET_SOURCES for s in _sources(props)):
            continue
        yield str(_get(sec_rule, "name", default="unnamed")), props


@rule(
    "AZ-NSG-001",
    "SSH or RDP is open to the internet",
    Severity.HIGH,
    NSG,
    "Management ports are exposed to everyone, a common target for password guessing.",
    "Remove the rule and use Azure Bastion or just-in-time VM access, or limit the source "
    "to known IP ranges.",
    "T1021 Remote Services / T1110 Brute Force",
)
def nsg_management_ports(res: Resource) -> list[str]:
    hits = []
    for name, props in _open_inbound_rules(res):
        ranges = _port_ranges(props)
        if "*" in ranges:
            continue  # reported by AZ-NSG-002
        for port, label in ((22, "SSH"), (3389, "RDP")):
            if any(_covers(r, port) for r in ranges):
                hits.append(f"rule '{name}' allows {label} (port {port}) from the internet")
    return hits


@rule(
    "AZ-NSG-002",
    "All inbound ports are open to the internet",
    Severity.CRITICAL,
    NSG,
    "Every port behind this network security group is reachable from anywhere.",
    "Replace the rule with rules for only the ports and sources that are needed.",
    "T1190 Exploit Public-Facing Application",
)
def nsg_any_port(res: Resource) -> list[str]:
    return [
        f"rule '{name}' allows all ports from the internet"
        for name, props in _open_inbound_rules(res)
        if "*" in _port_ranges(props)
    ]


# --- App Service ------------------------------------------------------------------------


@rule(
    "AZ-APP-001",
    "Web app accepts unencrypted HTTP",
    Severity.MEDIUM,
    WEB_APP,
    "Visitors can reach the app over plain HTTP.",
    "Set httpsOnly to true.",
    "T1557 Adversary-in-the-Middle",
)
def webapp_https(res: Resource) -> list[str]:
    if _is_false(_get(res.properties, "httpsOnly")):
        return ["httpsOnly is false"]
    return []


@rule(
    "AZ-APP-002",
    "Web app allows TLS older than 1.2",
    Severity.MEDIUM,
    WEB_APP,
    "Old TLS versions have known weaknesses.",
    "Set siteConfig.minTlsVersion to 1.2 or higher.",
    "T1557 Adversary-in-the-Middle",
)
def webapp_tls(res: Resource) -> list[str]:
    version = _get(res.properties, "siteConfig", "minTlsVersion")
    if isinstance(version, str) and version.lower() in WEAK_TLS:
        return [f"siteConfig.minTlsVersion is {version}"]
    return []


# --- Azure SQL --------------------------------------------------------------------------


@rule(
    "AZ-SQL-001",
    "SQL server allows public network access",
    Severity.MEDIUM,
    SQL_SERVER,
    "The database server accepts connections from public networks.",
    "Set publicNetworkAccess to Disabled and connect through a private endpoint.",
    "T1190 Exploit Public-Facing Application",
)
def sql_public(res: Resource) -> list[str]:
    if str(_get(res.properties, "publicNetworkAccess", default="")).lower() == "enabled":
        return ["publicNetworkAccess is Enabled"]
    return []


@rule(
    "AZ-SQL-002",
    "SQL firewall allows every IP address",
    Severity.HIGH,
    SQL_FIREWALL,
    "A firewall rule opens the server to all IPv4 addresses.",
    "Delete the rule and allow only the IP ranges that need access.",
    "T1190 Exploit Public-Facing Application",
)
def sql_firewall_all(res: Resource) -> list[str]:
    start = _get(res.properties, "startIpAddress")
    end = _get(res.properties, "endIpAddress")
    if start == "0.0.0.0" and end == "255.255.255.255":
        return ["firewall rule covers 0.0.0.0 - 255.255.255.255"]
    return []


def evaluate(resource: Resource) -> list[Finding]:
    findings = []
    for rule_def, check in RULES:
        if rule_def.resource_type == resource.type:
            findings.extend(Finding(rule_def, resource, d) for d in check(resource))
    return findings


def supported_types() -> set[str]:
    return {r.resource_type for r, _ in RULES}
