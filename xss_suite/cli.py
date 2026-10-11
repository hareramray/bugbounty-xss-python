"""Command-line interface. Import the browser engine only when it is needed."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import ConfigError, load_config, validate_config
from .payloads import PAYLOADS
from .reports import write_reports


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="xss-suite", description="Scope-restricted XSS testing for authorized targets."
    )
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate configuration without making requests")
    validate.add_argument("--config", type=Path, required=True)
    scan = commands.add_parser("scan", help="Run configured probes")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--dry-run", action="store_true", help="Print planned probes without making requests")
    _scan_arguments(scan)
    commands.add_parser("payloads", help="List harmless marker payload templates")
    demo = commands.add_parser("demo", help="Start the loopback-only practice server")
    demo.add_argument("--scan", action="store_true", help="Scan a temporary local demo server and exit")
    demo.add_argument("--port", type=int, default=None, help="Listen port (8765 for server; random for --scan)")
    _scan_arguments(demo)
    return result


def _scan_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--allow-writes", action="store_true", help="Permit explicit POST and form workflows")
    command.add_argument("--http-only", action="store_true", help="Record HTTP reflections without browser execution confirmation")
    command.add_argument("--headed", action="store_true", help="Show Chromium while probing")
    command.add_argument("--out", type=Path, default=Path("reports/xss-report"), help="Report path prefix (writes .json and .html)")
    command.add_argument("--fail-on-confirmed", action="store_true", help="Exit 1 if any probe confirms execution")


async def _scan(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    from .engine import scan

    return await scan(config, allow_writes=args.allow_writes, http_only=args.http_only, headed=args.headed)


def _plan(config: dict[str, Any]) -> Any:
    from .engine import plan

    return plan(config)


def _safe_error(error: BaseException) -> str:
    # Even the first Playwright diagnostic line can contain credentials or URLs.
    if isinstance(error, ConfigError):
        return str(error)
    return f"{type(error).__name__}: operation failed; sensitive details omitted"


def _report_and_exit(report: dict[str, Any], args: argparse.Namespace) -> int:
    json_path, html_path = write_reports(report, args.out)
    print(json.dumps(report.get("counts", {}), ensure_ascii=False, indent=2))
    print(f"JSON report: {json_path.resolve()}")
    print(f"HTML report: {html_path.resolve()}")
    results = report.get("results", [])
    if args.fail_on_confirmed and any(item.get("status") == "confirmed" for item in results):
        return 1
    if report.get("stopped") or report.get("incomplete") or any(item.get("status") == "inconclusive" for item in results):
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "payloads":
            for payload in PAYLOADS:
                print(f"{payload.id}: {payload.context}\n  {payload.template}")
            return 0
        if args.command == "demo":
            from .demo import demo_config, serve, serving

            if args.port is not None and not 0 <= args.port <= 65535:
                raise ConfigError("--port must be between 0 and 65535")
            if args.scan:
                with serving(port=0 if args.port is None else args.port) as (_, base_url):
                    print(f"Local demo: {base_url}")
                    config = validate_config(demo_config(base_url))
                    return _report_and_exit(asyncio.run(_scan(config, args)), args)
            serve(port=8765 if args.port is None else args.port)
            return 0
        config = load_config(args.config)
        if args.command == "validate":
            print(f"Valid configuration: {len(config['cases'])} cases; {len(config['scope'])} scope prefixes.")
            return 0
        if args.dry_run:
            print(json.dumps(_plan(config), ensure_ascii=False, indent=2))
            return 0
        return _report_and_exit(asyncio.run(_scan(config, args)), args)
    except (ConfigError, OSError, ValueError) as error:
        print(f"Error: {_safe_error(error)}", file=sys.stderr)
        return 2
    except ImportError as error:
        print(f"Dependency error: {_safe_error(error)}. Install with: python -m pip install -e '.[dev]'", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; the scan did not complete.", file=sys.stderr)
        return 3
    except Exception as error:
        print(f"Scan error: {_safe_error(error)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
