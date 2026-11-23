"""Credential *reference* parsing.

This module never authenticates anywhere.  It reads the user's local
``try.txt`` / ``try1.txt`` notes (and a packaged fallback list), normalises
the pairs, and selects a short reference list for a device vendor.  The
dashboard and CLI show a warning that these are for manual login only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import CredentialPair, Device

_HEADER_WORDS = (
    "username", "password", "default user", "default pass", "user name",
    "login", "note:", "warning", "important", "disclaimer",
)
_SEPARATOR_RE = re.compile(r"^[\s=|\-*_+#<>]+$")
_BLANK_RE = re.compile(r"^\(?\s*(?:leave\s+blank|blank|empty|none|no\s+password)\s*\)?$", re.I)
_COLON_RE = re.compile(r"^(?P<user>[^:\s]{1,64}):(?P<password>.+)$")


def _clean_password(value: str) -> str:
    password = value.strip()
    if _BLANK_RE.match(password):
        return ""
    return password.strip().strip("`'\"")


def _clean_username(value: str) -> str:
    return value.strip().strip("`'\"")


def _is_header(line: str) -> bool:
    lowered = line.lower().strip()
    if not lowered:
        return True
    if _SEPARATOR_RE.match(lowered):
        return True
    if lowered.startswith(("note", "warning", "important", "disclaimer", "#", "//")):
        return True
    if any(word in lowered for word in ("do not work", "factory reset", "default username", "default password")):
        return True
    if "username" in lowered and "password" in lowered:
        return True
    return False


def parse_credential_line(line: str) -> CredentialPair | None:
    """Parse one credential row.

    Supported separators are ``|``, tab, and two-or-more spaces.  A line such
    as ``admin:admin`` is also accepted.  Header, separator, and prose lines
    return ``None``.
    """

    line = line.strip()
    if not line or _is_header(line):
        return None
    if line.startswith("#") or line.startswith("//"):
        return None

    if "|" in line:
        parts = [part.strip() for part in line.split("|", 1)]
    elif "\t" in line:
        parts = [part.strip() for part in line.split("\t", 1)]
    else:
        parts = re.split(r"\s{2,}", line, maxsplit=1)
        if len(parts) == 1:
            colon = _COLON_RE.match(line)
            if not colon:
                return None
            # Only accept ``user:pass`` when the password is a single token.
            # This avoids turning prose such as "Note: if these do not work"
            # into a credential pair.
            if re.search(r"\s", colon.group("password").strip()):
                return None
            parts = [colon.group("user"), colon.group("password")]

    if len(parts) != 2:
        return None
    username = _clean_username(parts[0])
    password = _clean_password(parts[1])
    if not username:
        return None
    if username.lower() in {"username", "user", "default username"}:
        return None
    if len(username) > 64 or len(password) > 128:
        return None
    return CredentialPair(username=username, password=password)


def parse_credential_text(text: str) -> list[CredentialPair]:
    pairs: list[CredentialPair] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        pair = parse_credential_line(line)
        if pair is None:
            continue
        key = (pair.username, pair.password)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(pair)
    return pairs


def parse_credential_file(path: Path) -> list[CredentialPair]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_credential_text(text)


VENDOR_PRIORITY: dict[str, list[tuple[str, str]]] = {
    "hikvision": [
        ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
    ],
    "dahua": [
        ("admin", "admin"), ("admin", "888888"), ("admin", "123456"),
    ],
    "axis": [
        ("root", "pass"), ("root", "admin"), ("admin", "admin"),
    ],
    "reolink": [
        ("admin", "admin"), ("admin", "123456"),
    ],
    "tp-link": [
        ("admin", "admin"), ("admin", "1234"), ("admin", "password"),
    ],
    "cisco": [
        ("cisco", "cisco"), ("admin", "admin"),
    ],
    "ubiquiti": [
        ("ubnt", "ubnt"), ("admin", "admin"),
    ],
    "router": [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("root", "admin"), ("root", "root"),
    ],
    "camera": [
        ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
        ("admin", ""),
    ],
}

_VENDOR_KEYWORDS: list[tuple[str, str]] = [
    ("hikvision", "hikvision"),
    ("dahua", "dahua"),
    ("axis", "axis"),
    ("reolink", "reolink"),
    ("tapo", "tp-link"),
    ("tp-link", "tp-link"),
    ("tplink", "tp-link"),
    ("cisco", "cisco"),
    ("ubiquiti", "ubiquiti"),
    ("unifi", "ubiquiti"),
    ("ubnt", "ubiquiti"),
    ("d-link", "router"),
    ("dlink", "router"),
    ("netgear", "router"),
    ("asus", "router"),
    ("linksys", "router"),
    ("huawei", "router"),
    ("zte", "router"),
    ("fritz", "router"),
    ("camera", "camera"),
    ("ipcam", "camera"),
    ("nvr", "camera"),
    ("dvr", "camera"),
]


@dataclass
class CredentialReference:
    vendor: str
    pairs: list[CredentialPair]
    source_files: list[str]

    @property
    def note(self) -> str:
        return (
            "Manual login reference only. AB Search never sends these "
            "credentials or attempts a login."
        )


class CredentialStore:
    """A deduplicated set of default-credential reference pairs."""

    def __init__(self, pairs: list[CredentialPair] | None = None, sources: list[str] | None = None):
        self.pairs: list[CredentialPair] = []
        self.sources: list[str] = []
        self._seen: set[tuple[str, str]] = set()
        if pairs:
            self.add_pairs(pairs)
        if sources:
            self.sources.extend(sources)

    def add_pairs(self, pairs: list[CredentialPair]) -> None:
        for pair in pairs:
            key = (pair.username, pair.password)
            if key in self._seen:
                continue
            self._seen.add(key)
            self.pairs.append(pair)

    def extend(self, other: "CredentialStore") -> None:
        self.add_pairs(other.pairs)
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)

    @classmethod
    def from_paths(cls, paths: list[Path]) -> "CredentialStore":
        store = cls()
        for path in paths:
            if path.is_file():
                pairs = parse_credential_file(path)
                if pairs:
                    store.add_pairs(pairs)
                    store.sources.append(str(path))
        return store

    def vendor_for(self, device: Device | None = None, value: str = "") -> str:
        haystack = value
        if device is not None:
            haystack = " ".join(
                [device.vendor, device.hostname, device.category, " ".join(device.notes)]
            )
        lowered = haystack.lower()
        for needle, key in _VENDOR_KEYWORDS:
            if needle in lowered:
                return key
        if device is not None and device.category == "Possible CCTV camera":
            return "camera"
        return "default"

    def for_device(self, device: Device, limit: int = 12) -> CredentialReference:
        key = self.vendor_for(device)
        if not self.pairs:
            return CredentialReference(key, [], self.sources)

        priority = VENDOR_PRIORITY.get(key, [])
        by_key = {(pair.username, pair.password): pair for pair in self.pairs}
        selected: list[CredentialPair] = []
        selected_keys: set[tuple[str, str]] = set()

        for username, password in priority:
            pair = by_key.get((username, password))
            if pair is not None and (pair.username, pair.password) not in selected_keys:
                selected.append(pair)
                selected_keys.add((pair.username, pair.password))

        # Add a few generic pairs so a device with no vendor match still has a
        # useful reference.  The full list is available in the dashboard.
        for pair in self.pairs:
            if len(selected) >= limit:
                break
            if (pair.username, pair.password) in selected_keys:
                continue
            selected.append(pair)
            selected_keys.add((pair.username, pair.password))

        return CredentialReference(key, selected, self.sources)

    def all_pairs(self, limit: int = 200) -> list[CredentialPair]:
        return self.pairs[:limit]


_DEFAULTS_PATH = Path(__file__).resolve().parent / "data" / "defaults.txt"


def default_paths(base_dir: Path | None = None) -> list[Path]:
    paths: list[Path] = []
    candidates = []
    if base_dir is not None:
        candidates.extend([base_dir / "try.txt", base_dir / "try1.txt"])
    else:
        candidates.extend([Path.cwd() / "try.txt", Path.cwd() / "try1.txt"])
    candidates.append(Path.home() / ".config" / "absearch" / "credentials.txt")
    candidates.append(_DEFAULTS_PATH)
    for path in candidates:
        if path.is_file() and path not in paths:
            paths.append(path)
    return paths


def load_credential_store(
    base_dir: Path | None = None,
    extra_paths: list[Path] | None = None,
) -> CredentialStore:
    paths = default_paths(base_dir)
    for path in extra_paths or []:
        if path not in paths:
            paths.append(path)
    return CredentialStore.from_paths(paths)
