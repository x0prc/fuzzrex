"""Command-line interface for FuzzRex."""

from __future__ import annotations

import argparse
import sys

from fuzzrex import __version__
from fuzzrex.api_fuzzer import ApiFuzzer
from fuzzrex.auth import AuthHandler
from fuzzrex.config_fuzzer import ConfigFuzzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzrex",
        description="Fuzz REST APIs and configuration files.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    api_group = parser.add_argument_group("API fuzzing")
    api_group.add_argument("--api", help="Path to OpenAPI specification (JSON or YAML)")
    api_group.add_argument(
        "--base-url",
        help="Base URL of the target API (defaults to spec servers[0], else localhost:5000)",
    )
    api_group.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout")

    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--auth",
        choices=["token"],
        help="Authentication method (only 'token' is exposed on the CLI; use the API for OAuth2)",
    )
    auth_group.add_argument("--token", help="Bearer token when --auth token is set")

    config_group = parser.add_argument_group("config fuzzing")
    config_group.add_argument("--config", help="Path to configuration file (JSON or YAML)")
    config_group.add_argument(
        "--variants",
        type=int,
        default=20,
        help="Number of config variants to generate (default: 20)",
    )
    config_group.add_argument(
        "--out",
        default="findings/configs",
        help="Directory for generated config variants (default: findings/configs)",
    )
    config_group.add_argument("--seed", type=int, help="Random seed for reproducible variants")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.api and not args.config:
        parser.error("provide --api and/or --config")

    exit_code = 0

    if args.api:
        if args.auth and not args.token:
            parser.error("--auth token requires --token")
        auth = AuthHandler(auth_type=args.auth, token=args.token)
        fuzzer = ApiFuzzer(
            args.api,
            base_url=args.base_url,
            auth=auth,
            timeout=args.timeout,
        )
        findings = fuzzer.run()
        for finding in findings:
            status = finding.status_code if finding.status_code is not None else "ERR"
            print(f"[{status}] {finding.method} {finding.path}: {finding.detail}")
        print(f"API fuzzing complete: {len(findings)} finding(s)")
        if findings:
            exit_code = 1

    if args.config:
        try:
            config_fuzzer = ConfigFuzzer(args.config)
            written = config_fuzzer.run(args.out, count=args.variants, seed=args.seed)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {len(written)} config variant(s) to {args.out}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
