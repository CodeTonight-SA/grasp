"""Pluggable storage backends for GRASP records and anchors.

One stable interface (the syscall-doctrine shim shape) over every place a
deployment may keep records or anchor Merkle roots. The activation wizard
picks a backend by NAME; callers never import a concrete adapter.

Honesty contract (feature-complete input domain):

- the registry lists ONLY backends that exist end-to-end in this package —
  never a placeholder name for something unbuilt;
- a backend needing an external runtime dependency (a CLI, a daemon,
  credentials) detects it via ``probe()`` and reports a one-line remedy —
  a present dependency the caller must satisfy, never a hollow stub;
- ``probe()`` results are REAL checks, suitable for live ✓/✗ display in
  the activation wizard's picker.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ProbeResult:
    """One backend's live readiness, in plain language."""

    name: str
    ready: bool
    detail: str
    remedy: str | None = None


@runtime_checkable
class StorageAdapter(Protocol):
    """The contract every storage backend satisfies.

    ``put``/``get`` move record blobs; ``anchor`` commits a Merkle root to
    the backend's witness surface and returns a locator for the proof (or
    ``None`` when the backend cannot anchor right now); ``probe`` reports
    live readiness.
    """

    name: str

    def put(self, record_id: str, blob: bytes) -> str: ...

    def get(self, record_id: str) -> bytes | None: ...

    def anchor(self, merkle_root: str) -> str | None: ...

    def probe(self) -> ProbeResult: ...


# name -> (module, class). Grown ONLY as adapters land end-to-end.
_ADAPTERS: dict[str, tuple[str, str]] = {
    "local": ("grasp.storage.local", "LocalAdapter"),
}


def adapter_names() -> tuple[str, ...]:
    """Registered backend names, wizard display order."""
    return tuple(_ADAPTERS)


def get_adapter(name: str, **config) -> StorageAdapter:
    """Construct the named backend. Unknown names fail with the full menu."""
    try:
        module_name, class_name = _ADAPTERS[name]
    except KeyError:
        available = ", ".join(_ADAPTERS)
        raise ValueError(
            f"unknown storage backend {name!r} — available: {available}"
        ) from None
    cls = getattr(importlib.import_module(module_name), class_name)
    return cls(**config)


def probe_all() -> list[ProbeResult]:
    """Live-probe every registered backend (default config) for the picker."""
    return [get_adapter(name).probe() for name in _ADAPTERS]
