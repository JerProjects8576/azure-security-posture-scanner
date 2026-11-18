import pytest

from azposture.models import Resource
from azposture.rules import RULES, _covers, evaluate


def res(rtype, props, name="r1"):
    return Resource.from_dict(
        {"id": f"/subscriptions/x/{name}", "name": name, "type": rtype, "properties": props}
    )


def rule_ids(resource):
    return sorted(f.rule.id for f in evaluate(resource))


STORAGE = "Microsoft.Storage/storageAccounts"
KV = "Microsoft.KeyVault/vaults"
NSG = "Microsoft.Network/networkSecurityGroups"
WEB = "Microsoft.Web/sites"


def test_rule_ids_are_unique():
    ids = [r.id for r, _ in RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_has_remediation_and_mitre():
    for r, _ in RULES:
        assert r.remediation and r.mitre.startswith("T")


def test_insecure_storage_triggers_all_storage_rules():
    r = res(
        STORAGE,
        {
            "allowBlobPublicAccess": True,
            "supportsHttpsTrafficOnly": False,
            "minimumTlsVersion": "TLS1_0",
        },
    )
    assert rule_ids(r) == ["AZ-STG-001", "AZ-STG-002", "AZ-STG-003"]


def test_secure_storage_has_no_findings():
    r = res(
        STORAGE,
        {
            "allowBlobPublicAccess": False,
            "supportsHttpsTrafficOnly": True,
            "minimumTlsVersion": "TLS1_2",
        },
    )
    assert rule_ids(r) == []


def test_property_names_are_case_insensitive_and_string_booleans_work():
    r = res(STORAGE, {"AllowBlobPublicAccess": "True"})
    assert rule_ids(r) == ["AZ-STG-001"]


def test_missing_storage_properties_are_not_flagged():
    assert rule_ids(res(STORAGE, {})) == []


def test_keyvault_open_and_without_purge_protection():
    r = res(KV, {"enablePurgeProtection": False, "publicNetworkAccess": "Enabled"})
    assert rule_ids(r) == ["AZ-KV-001", "AZ-KV-002"]


@pytest.mark.parametrize(
    "props",
    [
        {"enablePurgeProtection": True, "publicNetworkAccess": "Disabled"},
        {
            "enablePurgeProtection": True,
            "publicNetworkAccess": "Enabled",
            "networkAcls": {"defaultAction": "Deny"},
        },
    ],
)
def test_keyvault_private_or_firewalled_is_fine(props):
    assert rule_ids(res(KV, props)) == []


def nsg(*rules):
    return res(NSG, {"securityRules": [{"name": n, "properties": p} for n, p in rules]})


def inbound(port, source="*", access="Allow", direction="Inbound", **extra):
    return {
        "access": access,
        "direction": direction,
        "sourceAddressPrefix": source,
        "destinationPortRange": port,
        **extra,
    }


@pytest.mark.parametrize("port,source", [("22", "*"), ("3389", "Internet"), ("20-25", "0.0.0.0/0")])
def test_management_ports_open_to_internet(port, source):
    assert rule_ids(nsg(("r", inbound(port, source)))) == ["AZ-NSG-001"]


def test_both_ssh_and_rdp_in_one_range_give_two_details():
    findings = evaluate(nsg(("wide", inbound("1-4000"))))
    assert [f.rule.id for f in findings] == ["AZ-NSG-001", "AZ-NSG-001"]


def test_port_list_is_checked():
    r = nsg(("list", {**inbound(None), "destinationPortRanges": ["80", "3389"]}))
    assert rule_ids(r) == ["AZ-NSG-001"]


def test_any_port_is_critical_and_not_double_reported():
    assert rule_ids(nsg(("all", inbound("*")))) == ["AZ-NSG-002"]


@pytest.mark.parametrize(
    "rule_props",
    [
        inbound("22", source="10.0.0.0/8"),
        inbound("22", access="Deny"),
        inbound("22", direction="Outbound"),
        inbound("443"),
    ],
)
def test_safe_nsg_rules(rule_props):
    assert rule_ids(nsg(("r", rule_props))) == []


def test_source_prefix_list_is_checked():
    r = nsg(("r", {**inbound("22", source=None), "sourceAddressPrefixes": ["1.2.3.4", "*"]}))
    assert rule_ids(r) == ["AZ-NSG-001"]


@pytest.mark.parametrize(
    "port_range,port,expected",
    [
        ("*", 22, True),
        ("22", 22, True),
        ("21-23", 22, True),
        ("23-30", 22, False),
        ("abc", 22, False),
        ("a-b", 22, False),
    ],
)
def test_covers(port_range, port, expected):
    assert _covers(port_range, port) is expected


def test_web_app_http_and_old_tls():
    r = res(WEB, {"httpsOnly": False, "siteConfig": {"minTlsVersion": "1.1"}})
    assert rule_ids(r) == ["AZ-APP-001", "AZ-APP-002"]


def test_web_app_secure():
    assert rule_ids(res(WEB, {"httpsOnly": True, "siteConfig": {"minTlsVersion": "1.2"}})) == []


def test_sql_public_and_firewall():
    assert rule_ids(res("Microsoft.Sql/servers", {"publicNetworkAccess": "Enabled"})) == [
        "AZ-SQL-001"
    ]
    fw = res(
        "Microsoft.Sql/servers/firewallRules",
        {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"},
    )
    assert rule_ids(fw) == ["AZ-SQL-002"]
    azure_services = res(
        "Microsoft.Sql/servers/firewallRules",
        {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"},
    )
    assert rule_ids(azure_services) == []


def test_unknown_type_is_ignored():
    assert evaluate(res("Microsoft.Compute/virtualMachines", {})) == []
