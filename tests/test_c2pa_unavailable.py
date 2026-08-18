# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""The no-c2pa-python degradation path, pinned without the optional dependency.

Simulate the optional dep being absent (monkeypatch grasp.c2pa._c2pa to None)
and assert the monotone behaviour: signing raises C2paUnavailable, binding
verification returns False (never a manufactured pass). Runs on every install,
so the safe fallback is pinned even where the bridge cannot operate.
"""
from __future__ import annotations

import pytest

from grasp import c2pa


@pytest.fixture
def no_c2pa(monkeypatch):
    monkeypatch.setattr(c2pa, "_c2pa", lambda: None)


def test_c2pa_available_false(no_c2pa):
    assert c2pa.c2pa_available() is False


def test_sign_raises_clearly(no_c2pa):
    with pytest.raises(c2pa.C2paUnavailable):
        c2pa.sign_asset("{}", b"x", "png", cert_pem=b"c", key_pem=b"k")


def test_verify_binding_false_not_pass(no_c2pa):
    assert c2pa.verify_binding(b"x", content_addr="sha256:" + "ab" * 32,
                               anchor_root=None) is False
