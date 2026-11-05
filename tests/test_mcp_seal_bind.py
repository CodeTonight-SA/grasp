"""The sidecar binds to loopback unless the operator says otherwise.

An outside reviewer (council seal 8b98bbc80e015838) said `--listen :8091` skips the safety flag.
Tested: it does not, because `_cmd_serve` refuses an empty host first, and a test here pins that.
The reviewer was right about one layer down: `_is_loopback("")` said True, and an empty host binds
every interface, so anything else calling that helper would have been misled.
"""
from __future__ import annotations

import pytest

from grasp import mcp_seal as m


@pytest.mark.parametrize("host", ["", " ", "0.0.0.0", "::", "0", "example.com"])
def test_a_host_that_is_not_plainly_loopback_is_refused(host):
    assert m._is_loopback(host) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_hosts_are_accepted(host):
    assert m._is_loopback(host) is True


@pytest.mark.parametrize("listen", [":8091", "0.0.0.0:8091", "[::]:8091"])
def test_serve_refuses_a_wide_bind_without_the_flag(listen, tmp_path, capsys):
    code = m.main(["serve", "--listen", listen, "--upstream", "http://127.0.0.1:9", "--home", str(tmp_path)])
    assert code == 2
    assert "grasp-mcp-seal:" in capsys.readouterr().err
