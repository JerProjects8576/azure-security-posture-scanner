import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from azposture import live
from azposture.cli import main
from azposture.models import Resource, Severity
from azposture.scanner import parse_resources, scan

SAMPLE = Path(__file__).parent.parent / "examples" / "sample-resources.json"


def test_sample_table_report_and_exit_code(capsys):
    code = main(["--input", str(SAMPLE)])
    out = capsys.readouterr().out
    assert code == 1
    assert "AZ-NSG-002" in out and "nsg-demo-vm" in out
    assert "8 resource(s)" in out and "1 resource(s) of unsupported types skipped" in out


def test_json_report_counts(capsys):
    main(["-i", str(SAMPLE), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == 11
    assert data["summary"]["by_severity"] == {"low": 0, "medium": 6, "high": 4, "critical": 1}
    first = data["findings"][0]
    assert first["severity"] == "critical" and first["mitre_attack"].startswith("T1190")


def test_sarif_report_is_valid_shape(tmp_path):
    out = tmp_path / "report.sarif"
    main(["-i", str(SAMPLE), "-f", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert sarif["version"] == "2.1.0"
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert {r["level"] for r in run["results"]} == {"error", "warning"}


def test_markdown_report(capsys):
    main(["-i", str(SAMPLE), "-f", "markdown", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert out.startswith("# Azure security posture report")
    assert "AZ-NSG-002" in out and "AZ-STG-002" not in out


def test_fail_on_critical_only(capsys, tmp_path):
    f = tmp_path / "r.json"
    f.write_text(
        json.dumps(
            [
                {
                    "id": "/s/st",
                    "type": "Microsoft.Storage/storageAccounts",
                    "properties": {"allowBlobPublicAccess": True},
                }
            ]
        )
    )
    assert main(["-i", str(f), "--fail-on", "critical"]) == 0
    assert main(["-i", str(f), "--fail-on", "high"]) == 1


def test_clean_input_reports_no_findings(capsys, tmp_path):
    f = tmp_path / "clean.json"
    f.write_text(
        json.dumps(
            {
                "data": [
                    {
                        "id": "/s/st",
                        "type": "Microsoft.Storage/storageAccounts",
                        "properties": {"allowBlobPublicAccess": False},
                    }
                ]
            }
        )
    )
    assert main(["-i", str(f)]) == 0
    assert "No findings." in capsys.readouterr().out
    assert main(["-i", str(f), "-f", "markdown"]) == 0
    assert "No findings." in capsys.readouterr().out


@pytest.mark.parametrize(
    "content,message",
    [
        ("not json", "not valid JSON"),
        ('{"a": 1}', "expected a JSON list"),
        ('[{"name": "x"}]', "missing required field"),
        ("[1]", "must be a JSON object"),
    ],
)
def test_bad_input_exits_2(tmp_path, capsys, content, message):
    f = tmp_path / "bad.json"
    f.write_text(content)
    assert main(["-i", str(f)]) == 2
    assert message in capsys.readouterr().err


def test_missing_file_and_bad_severity(capsys):
    assert main(["-i", "does-not-exist.json"]) == 2
    assert "cannot read" in capsys.readouterr().err
    assert main(["-i", str(SAMPLE), "--fail-on", "urgent"]) == 2
    assert "unknown severity" in capsys.readouterr().err


def test_no_source_given(capsys):
    assert main([]) == 2
    assert "give --input" in capsys.readouterr().err


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("AZ-") == 11


def test_resource_name_defaults_to_last_id_segment():
    r = Resource.from_dict({"id": "/a/b/my-vault", "type": "x"})
    assert r.name == "my-vault"


def test_scan_sorts_most_severe_first():
    result = scan(parse_resources(json.loads(SAMPLE.read_text())))
    ranks = [f.rule.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)
    assert len(result.at_or_above(Severity.CRITICAL)) == 1


class FakeClient:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def resources(self, request):
        self.requests.append(request)
        return self.pages[len(self.requests) - 1]


def test_live_fetch_follows_pagination():
    row = {"id": "/s/kv", "type": "Microsoft.KeyVault/vaults", "properties": {}}
    client = FakeClient(
        [
            SimpleNamespace(data=[row], skip_token="next"),
            SimpleNamespace(data=[row], skip_token=None),
        ]
    )
    resources = live.fetch_resources(
        ["sub-1"], client=client, make_request=lambda subs, q, token: (subs, q, token)
    )
    assert len(resources) == 2
    assert client.requests[0][2] is None and client.requests[1][2] == "next"
    assert "microsoft.keyvault/vaults" in client.requests[0][1]


def test_live_mode_from_cli(monkeypatch, capsys):
    monkeypatch.setattr(
        live,
        "fetch_resources",
        lambda subs: [
            Resource.from_dict(
                {"id": "/s/app", "type": "Microsoft.Web/sites", "properties": {"httpsOnly": False}}
            )
        ],
    )
    assert main(["--subscription", "sub-1"]) == 0
    assert "AZ-APP-001" in capsys.readouterr().out
