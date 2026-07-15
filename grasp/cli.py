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
    grasp activate        # three-act activation wizard (tier/storage/terms)
    python -m grasp.cli verify   # equivalent (no install)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from grasp.mcp_server import SERVER_NAME, SERVER_VERSION, tool_status, tool_verify


def _emit(out: dict, *, as_json: bool) -> None:
    """Print the result dict: pretty (default) or single-line JSON (``--json``)."""
    print(json.dumps(out) if as_json else json.dumps(out, indent=2, sort_keys=True))


def _verify_failure_reason(out: dict) -> str:
    """A single loud line naming WHICH axis failed, so ``ok=False`` never reads
    as a generic failure. Tamper (BROKEN) and anchoring (unanchored) are
    distinct: a skeptic must not confuse 'a byte was tampered' with 'not rooted
    at an exogenous anchor'."""
    if "broken" in (out.get("decision_chain"), out.get("belief_chain")):
        return "VERIFY FAILED: BROKEN — a signed record was tampered."
    if out.get("anchored") is False:
        n = out.get("unanchored", 0)
        return (
            f"VERIFY INCOMPLETE: {n} decision(s) do not root at an exogenous "
            "anchor (ci:/human:/council:/hypo:). Not tampered, but not "
            "exogenously anchored — see 'unanchored'/'anchored'."
        )
    if "degraded" in (out.get("decision_chain"), out.get("belief_chain")):
        return "VERIFY DEGRADED: a record uses a scheme this build cannot fully check."
    return "VERIFY FAILED."


def _cmd_verify(args: argparse.Namespace) -> int:
    out = tool_verify({})
    _emit(out, as_json=args.json)
    if out.get("ok"):
        return 0
    print(_verify_failure_reason(out), file=sys.stderr)
    return 1


def _cmd_status(args: argparse.Namespace) -> int:
    out = tool_status({})
    _emit(out, as_json=args.json)
    return 0 if out.get("ok") else 1


def _default_licenses_root() -> Path:
    """Where the install's terms live: the checkout root when running from
    a git tree or editable install, else the current directory (wheel
    installs point ``--licenses-root`` at their terms explicitly)."""
    from grasp.activate import license_files
    checkout = Path(__file__).resolve().parent.parent
    return checkout if license_files(checkout) else Path.cwd()


def _cmd_activate(args: argparse.Namespace) -> int:
    # Lazy import: the wizard pulls the storage adapters; `grasp verify`
    # must stay importable even if an adapter dependency misbehaves.
    from grasp.activate import ActivationError
    from grasp.wizard import WizardCancelled, WizardIO, run_wizard

    root = Path(args.licenses_root) if args.licenses_root else _default_licenses_root()
    home = Path(args.home) if args.home else None
    try:
        run_wizard(WizardIO(), licenses_root=root, home=home)
    except WizardCancelled:
        return 1  # the wizard already told the operator why
    except ActivationError as exc:
        print(f"Activation refused: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nActivation interrupted.", file=sys.stderr)
        return 130
    return 0


def _cmd_honesty(args: argparse.Namespace) -> int:
    """The private provider-honesty scoreboard (operator/admin surface)."""
    from grasp.honesty import public_shame_card, scoreboard, scoreboard_card
    if args.json:
        print(json.dumps(scoreboard(), sort_keys=True))
        return 0
    print(scoreboard_card())
    shame = public_shame_card()
    if shame:
        print()
        print(shame)
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    """GRASP proves GRASP — re-verify this deployment's own configuration.
    Exit 0 only when every check holds, so cron/CI can gate on it."""
    from grasp.honesty import self_attestation
    root = Path(args.licenses_root) if args.licenses_root else _default_licenses_root()
    result = self_attestation(root)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        from grasp.card import render_card
        print(render_card("grasp_attest", result))
    return 0 if result.get("attested") else 1


def _cmd_open(args: argparse.Namespace) -> int:
    """Open a per-response prove-it artifact by (prefix of) its id — the
    footer's fallback when a terminal does not auto-link the fineprint URL."""
    from grasp.footer import artifact_dir

    directory = artifact_dir()
    matches = sorted(directory.glob(f"{args.artifact_id}*.html"))
    if not matches:
        print(f"no prove-it artifact matching {args.artifact_id!r} under "
              f"{directory}", file=sys.stderr)
        return 1
    path = matches[0]
    print(path)
    if not args.no_browser:
        import webbrowser
        webbrowser.open(path.as_uri())
    return 0


def _add_ledger_commands(sub) -> None:
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


def _add_activation_commands(sub) -> None:
    activate = sub.add_parser(
        "activate",
        help="three-act activation wizard: tier, storage backends, terms")
    activate.add_argument(
        "--licenses-root", metavar="PATH",
        help="directory holding the LICENSE*/TERMS* files to accept "
             "(default: the install root, else the current directory)")
    activate.add_argument(
        "--home", metavar="PATH",
        help="GRASP state directory (default: $GRASP_HOME or ~/.grasp)")
    activate.set_defaults(func=_cmd_activate)
    open_cmd = sub.add_parser(
        "open",
        help="open a per-response prove-it artifact by id (footer fallback)")
    open_cmd.add_argument("artifact_id",
                          help="artifact id (or unique prefix) from the footer")
    open_cmd.add_argument("--no-browser", action="store_true",
                          help="print the path only; do not launch a browser")
    open_cmd.set_defaults(func=_cmd_open)


def _add_honesty_commands(sub) -> None:
    honesty = sub.add_parser(
        "honesty",
        help="provider floor-hold scoreboard from the private honesty ledger")
    honesty.add_argument("--json", action="store_true",
                         help="single-line JSON (default: card)")
    honesty.set_defaults(func=_cmd_honesty)
    attest = sub.add_parser(
        "attest",
        help="self-attestation: prove this deployment abides by its own "
             "configuration; exit non-zero if any check fails")
    attest.add_argument("--json", action="store_true",
                        help="single-line JSON (default: card)")
    attest.add_argument("--licenses-root", metavar="PATH",
                        help="directory holding the accepted terms files")
    attest.set_defaults(func=_cmd_attest)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grasp",
        description=(
            f"GRASP {SERVER_NAME} {SERVER_VERSION} — offline provenance "
            "verification: the arithmetic is the judge, never the agent."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_ledger_commands(sub)
    _add_activation_commands(sub)
    _add_honesty_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``grasp`` console script. Returns the process exit
    code (0 = ok/VERIFIED, 1 = BROKEN) so CI and git hooks can gate on it."""
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
