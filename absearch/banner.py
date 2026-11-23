"""AB SEARCH wordmark, rendered as terminal ASCII art.

The logo file shipped with the project is a red "AB SEARCH" wordmark on a
light background.  This module recreates that mark with block characters so
it looks right in a terminal without needing an image library, a font, or
network access.
"""

from __future__ import annotations

import os
import sys

from . import __version__

# A compact, six-row block font.  Every glyph is exactly eight columns wide
# so the wordmark stays aligned when it is printed in a monospace terminal.
_GLYPHS: dict[str, list[str]] = {
    "A": [
        " █████╗ ",
        "██╔══██╗",
        "███████║",
        "██╔══██║",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ],
    "B": [
        "██████╗ ",
        "██╔══██╗",
        "██████╔╝",
        "██╔══██╗",
        "██████╔╝",
        "╚═════╝ ",
    ],
    "S": [
        "███████╗",
        "██╔════╝",
        "███████╗",
        "╚════██║",
        "███████║",
        "╚══════╝",
    ],
    "E": [
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "███████╗",
        "╚══════╝",
    ],
    "R": [
        "██████╗ ",
        "██╔══██╗",
        "██████╔╝",
        "██╔══██╗",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ],
    "C": [
        " ██████╗",
        "██╔════╝",
        "██║     ",
        "██║     ",
        "╚██████╗",
        " ╚═════╝",
    ],
    "H": [
        "██╗  ██╗",
        "██║  ██║",
        "███████║",
        "██╔══██║",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ],
    " ": [
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
    ],
}

BRAND_RED = "#C8342A"


def banner_lines(word: str = "AB SEARCH") -> list[str]:
    """Return the wordmark as a list of six text rows."""

    rows = ["" for _ in range(6)]
    for letter in word.upper():
        glyph = _GLYPHS.get(letter, _GLYPHS[" "])
        for index in range(6):
            rows[index] += glyph[index]
    return [row.rstrip() for row in rows]


def banner_text(word: str = "AB SEARCH") -> str:
    """Return the wordmark as a plain multi-line string."""

    return "\n".join(banner_lines(word))


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def print_banner(console=None, color: bool | None = None, show_tagline: bool = True) -> None:
    """Print the AB SEARCH mark, using rich when it is available."""

    if color is None:
        color = supports_color()

    if console is None:
        try:
            from rich.console import Console

            console = Console(highlight=False)
        except Exception:  # pragma: no cover - rich is optional
            console = None

    text = banner_text()
    if console is not None and color:
        console.print(text, style=f"bold {BRAND_RED}", highlight=False)
        if show_tagline:
            console.print(
                f"  [dim]authorized local-network + CCTV inventory[/dim]  "
                f"[dim]v{__version__}[/dim]"
            )
            console.print(
                "  [dim]No login attempts. No camera streams. Authorized networks only.[/dim]"
            )
        return

    if color:
        red = "\033[1;31m"
        reset = "\033[0m"
        dim = "\033[2m"
        print(f"{red}{text}{reset}")
        if show_tagline:
            print(
                f"  {dim}authorized local-network + CCTV inventory  "
                f"v{__version__}{reset}"
            )
            print(
                f"  {dim}No login attempts. No camera streams. Authorized networks only.{reset}"
            )
        return

    print(text)
    if show_tagline:
        print(f"  authorized local-network + CCTV inventory  v{__version__}")
        print("  No login attempts. No camera streams. Authorized networks only.")
