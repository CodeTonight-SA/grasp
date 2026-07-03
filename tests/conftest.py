# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Hermetic test environment: every test runs against a throwaway GRASP_HOME
and a fixed test signing key — no test ever touches a real ~/.grasp state dir
or a persisted key file."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _grasp_env(tmp_path_factory):
    home = tmp_path_factory.mktemp("grasp-home")
    os.environ["GRASP_HOME"] = str(home)
    os.environ["GRASP_SIGNING_KEY"] = "grasp-test-key"
    yield
