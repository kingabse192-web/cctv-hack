from absearch.history import compare_reports, format_diff, load_baseline


def report(devices):
    return {"meta": {"generated_at": "2026-11-23T10:00:00+00:00"}, "devices": devices}


def device(ip, ports=(80,), category="Computer", hostname=""):
    return {
        "ip": ip,
        "hostname": hostname,
        "vendor": "Example",
        "category": category,
        "ports": [{"port": port, "service": "http"} for port in ports],
    }


def test_compare_reports_detects_changes():
    previous = report([
        device("192.0.2.10", ports=(80,), hostname="old"),
        device("192.0.2.20", ports=(22, 80)),
        device("192.0.2.30"),
    ])
    current = report([
        device("192.0.2.10", ports=(80, 443), hostname="new"),
        device("192.0.2.20", ports=(80,), category="Router"),
        device("192.0.2.40"),
    ])
    diff = compare_reports(previous, current)
    assert diff["summary"] == {"new": 1, "missing": 1, "changed": 2}
    assert diff["new"][0]["ip"] == "192.0.2.40"
    assert diff["missing"][0]["ip"] == "192.0.2.30"
    changed = {item["ip"]: item for item in diff["changed"]}
    assert changed["192.0.2.10"]["added_ports"] == [443]
    assert changed["192.0.2.20"]["category_after"] == "Router"
    text = format_diff(diff)
    assert "1 new" in text and "+ 192.0.2.40" in text


def test_load_baseline_rejects_non_reports(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")
    try:
        load_baseline(path)
    except ValueError:
        return
    raise AssertionError("expected ValueError")
