from pathlib import Path

from absearch.credentials import (
    CredentialStore,
    default_paths,
    load_credential_store,
    parse_credential_text,
)

SAMPLE = """\
POPULAR DEFAULT USERNAMES AND PASSWORDS (WIFI, ROUTERS, & CCTV)
==================================================================
DEFAULT USERNAME          | DEFAULT PASSWORD
------------------------------------------------------------------
admin                     | admin
admin                     | (leave blank)
root                      | root
Note: If these do not work, the device password has likely been changed.
You may need to perform a physical factory reset.
"""


def test_parse_credential_text_skips_headers_and_handles_blank():
    pairs = parse_credential_text(SAMPLE)
    assert [pair.username for pair in pairs] == ["admin", "admin", "root"]
    assert pairs[1].password == ""
    assert pairs[0].display_password == "admin"
    assert pairs[1].display_password == "<blank>"


def test_credential_store_selects_vendor_reference():
    store = CredentialStore(parse_credential_text(SAMPLE))
    reference = store.for_device(type("D", (), {
        "vendor": "Hikvision", "hostname": "IPC", "category": "Possible CCTV camera",
        "notes": [], "ip": "192.168.1.64"
    })())
    assert reference.vendor == "hikvision"
    assert reference.pairs[0].username == "admin"
    assert "never" in reference.note.lower()


def test_default_store_reads_packaged_fallback(tmp_path: Path):
    store = load_credential_store(base_dir=tmp_path)
    assert len(store.pairs) >= 20
    assert any(path.name == "defaults.txt" for path in default_paths(tmp_path))
    pair = next(pair for pair in store.pairs if pair.username == "admin")
    assert pair.password in {"admin", "password", ""}
