"""Plugin / theme wordlists loaded lazily from the packaged ``data/`` dir.

These lists are used in aggressive enumeration mode. The packaged list is a
small seed; users can override with their own at ``~/.config/wp-shield/``.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from ..settings import config_dir


def _read_lines(path: Path) -> list[str]:
    out: list[str] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s.lower())
    return out


def _packaged(name: str) -> list[str]:
    try:
        ref = files("wp_shield.data").joinpath(name)
        with ref.open("r", encoding="utf-8") as fh:
            return [
                ln.strip().lower()
                for ln in fh.readlines()
                if ln.strip() and not ln.startswith("#")
            ]
    except (FileNotFoundError, ModuleNotFoundError):
        return []


@lru_cache(maxsize=1)
def load_plugin_wordlist(limit: int | None = None) -> list[str]:
    user = _read_lines(config_dir() / "plugins.txt")
    builtin = _packaged("plugins_popular.txt")
    seen: set[str] = set()
    out: list[str] = []
    for s in user + builtin:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if limit is not None and len(out) >= limit:
            break
    return out


@lru_cache(maxsize=1)
def load_theme_wordlist(limit: int | None = None) -> list[str]:
    user = _read_lines(config_dir() / "themes.txt")
    builtin = _packaged("themes_popular.txt")
    seen: set[str] = set()
    out: list[str] = []
    for s in user + builtin:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if limit is not None and len(out) >= limit:
            break
    return out
