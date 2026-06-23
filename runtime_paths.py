"""Resolve writable data vs bundled resource paths (dev and PyInstaller)."""

from __future__ import annotations

import os
import sys


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def data_root() -> str:
    """Writable app data: database, .env, JSON caches."""
    override = os.environ.get("WPGUARD_DATA_DIR")
    if override:
        return override
    return os.path.abspath(os.path.dirname(__file__))


def resource_root() -> str:
    """Bundled read-only assets: templates, static fonts."""
    if is_frozen():
        return sys._MEIPASS
    return os.path.abspath(os.path.dirname(__file__))


def database_dir() -> str:
    path = os.path.join(data_root(), "database")
    os.makedirs(path, exist_ok=True)
    return path
