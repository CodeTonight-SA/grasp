# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""grasp — shell CLI for offline verification + status of the local GRASP ledger.

The skeptic's one command: ``grasp verify`` re-verifies the entire recorded
history offline (every decision signature, the Merkle root, the belief chain)
and EXITS NON-ZERO if anything is BROKEN — so a human, a CI job, or a git hook
can gate on the arithmetic, not on an agent's say-so. ``grasp status`` shows the
ledger location, record counts, and chain head.

A thin shell over the SAME ``tool_verify`` / ``tool_status`` the MCP host calls
(Gemini CLI, Claude Code) — one verification implementation, so the shell and the
MCP surface can never disagree. State lives under ``$GRASP_HOME`` (default
``~/.grasp``).

Run::

    grasp verify          # exit 0 = VERIFIED, non-zero = BROKEN
    grasp status
    python -m grasp.cli verify   # equivalent (no install)
"""
from __future__ import annotations

import argparse
import json
import sys

from grasp.mcp_server import SERVER_NAME, SERVER_VERSION, tool_status, tool_verify


def _emit(out: dict, *, as_json: bool) -> None:
    """Print the result dict: pretty (default) or single-line JSON (``--json``)."""
    print(json.dumps(out) if as_json else json.dumps(out, indent=2, sort_keys=True))


def _cmd_verify(args: argparse.Namespace) -> int:
    out = tool_verify({})
    _emit(out, as_json=args.json)
    return 0 if out.get("ok") else 1


def _cmd_status(args: argparse.Namespace) -> int:
    out = tool_status({})
    _emit(out, as_json=args.json)
    return 0 if out.get("ok") else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grasp",
        description=(
            f"GRASP {SERVER_NAME} {SERVER_VERSION} — offline provenance "
            "verification: the arithmetic is the judge, never the agent."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser(
        "verify",
        help="re-verify the whole ledger offline; exit non-zero if BROKEN",
    )
    verify.add_argument("--json", action="store_true",
                        help="single-line JSON (default: pretty)")
    verify.set_defaults(func=_cmd_verify)
    status = sub.add_parser(
        "status", help="show ledger location, record counts, and chain head")
    status.add_argument("--json", action="store_true",
                        help="single-line JSON (default: pretty)")
    status.set_defaults(func=_cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``grasp`` console script. Returns the process exit
    code (0 = ok/VERIFIED, 1 = BROKEN) so CI and git hooks can gate on it."""
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
