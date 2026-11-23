import json

from absearch.cli import build_parser, main


def test_parser_defaults_and_options():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.format == "json,csv,html"
    assert args.bluetooth is True
    assert args.services is True
    assert args.output == "inventory_reports"
    args = parser.parse_args(["--no-bluetooth", "--no-services", "--camera-ports", "--demo"])
    assert args.bluetooth is False
    assert args.services is False
    assert args.camera_ports is True
    assert args.demo is True


def test_demo_cli_writes_reports(tmp_path, capsys):
    code = main([
        "--demo", "--no-open", "--no-color", "--quiet",
        "--output", str(tmp_path / "reports"),
    ])
    assert code == 0
    output = capsys.readouterr().out
    assert "REPORT" in output or "report.json" in output
    reports = list((tmp_path / "reports").glob("scan-*/report.json"))
    assert reports, output
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["summary"]["total"] == 8
    assert report["meta"]["mode"] == "demo"
    assert (reports[0].parent / "index.html").exists()
    assert (reports[0].parent / "devices.csv").exists()


def test_authorization_refusal_writes_nothing(tmp_path, capsys):
    code = main([
        "--network", "192.0.2.0/24", "--output", str(tmp_path / "reports"),
    ])
    assert code == 2
    assert "Authorization not confirmed" in capsys.readouterr().out
    assert not list((tmp_path / "reports").glob("scan-*"))
