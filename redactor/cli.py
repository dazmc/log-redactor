"""CLI entry point for the log redactor."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import load_config, save_config
from .detectors import PATTERN_GROUPS
from .engine import Redactor
from .processors import JsonProcessor, TextProcessor, detect_format


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact",
        description="Deterministic secret redaction for log files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  redact app.log                          Redact and print to stdout
  redact app.log clean.log                Redact and write to file
  redact --salt "team-x" app.log          Use custom salt for consistent hashing
  redact --format json logs.jsonl         Force JSON mode
  redact --dry-run app.log                Preview findings without writing
  redact --config my-rules.json app.log   Use custom config
  redact --list-patterns                  Show all built-in detection patterns
""",
    )

    parser.add_argument(
        "input", nargs="?", default="-",
        help="Input log file (default: stdin)",
    )
    parser.add_argument(
        "output", nargs="?", default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "-s", "--salt",
        help="Salt for deterministic hashing (overrides config)",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config file (JSON)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["auto", "text", "json"],
        default="auto",
        help="Input format (default: auto-detect)",
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="Show findings without writing output",
    )
    parser.add_argument(
        "--list-patterns",
        action="store_true",
        help="List all built-in detection patterns and exit",
    )
    parser.add_argument(
        "--list-tlds",
        action="store_true",
        help="List TLDs matched by hostname pattern and exit",
    )
    parser.add_argument(
        "--init-config",
        metavar="FILE",
        help="Generate a default config file and exit",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress summary output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show each finding with details",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )

    # Category toggles
    cat_group = parser.add_argument_group("category toggles")
    for category in PATTERN_GROUPS:
        # Enable flag (network is disabled by default, others enabled)
        if category == "network":
            enable_flag = f"--{category.replace('_', '-')}"
            cat_group.add_argument(
                enable_flag,
                action="store_true",
                default=None,
                dest=f"cat_{category}",
                help=f"Enable {category} detection (disabled by default)",
            )
        else:
            enable_flag = f"--{category.replace('_', '-')}"
            cat_group.add_argument(
                enable_flag,
                action="store_true",
                default=None,
                dest=f"cat_{category}",
                help=f"Enable {category} detection",
            )
            disable_flag = f"--no-{category.replace('_', '-')}"
            cat_group.add_argument(
                disable_flag,
                action="store_false",
                dest=f"cat_{category}",
            )

    return parser


def cmd_list_patterns():
    """Print all built-in detection patterns."""
    print("Built-in Detection Patterns")
    print("=" * 60)
    for category, patterns in PATTERN_GROUPS.items():
        print(f"\n  [{category}]")
        for p in patterns:
            print(f"    {p.name:<25} {p.description}")
            print(f"    {'':25} Pattern: {p.regex[:80]}{'...' if len(p.regex) > 80 else ''}")
    print()


def cmd_list_tlds():
    """Print TLDs matched by the hostname pattern."""
    from .detectors import HOSTNAME
    # Extract TLDs from the regex (they're in the last alternation group)
    regex = HOSTNAME.regex
    # Find the TLD group: (?:internal|local|corp|...)
    import re
    match = re.search(r'\(\?:([\w|]+)\)\)', regex)
    if match:
        tlds = match.group(1).split("|")
        print("Supported Hostname TLDs")
        print("=" * 40)
        print(f"\n  The hostname pattern matches domains ending with:\n")
        for tld in sorted(tlds):
            print(f"    .{tld}")
        print(f"\n  Total: {len(tlds)} TLDs")
        print(f"\n  Example: server.{tlds[0]} matches")
        print(f"  Example: server.example.com does NOT match (public TLD)")
        print()


def cmd_init_config(path: str):
    """Generate a default config file."""
    save_config({
        "salt": "CHANGE-ME-TO-A-UNIQUE-SALT",
        "categories": {
            "api_keys": True,
            "tokens": True,
            "passwords": True,
            "connection_strings": True,
            "pii": True,
            "private_keys": True,
            "network": False,
            "high_entropy": True,
        },
        "high_entropy_threshold": 4.5,
        "custom_patterns": {
            "MY_INTERNAL_KEY": "MYAPP-[A-F0-9]{32}"
        },
    }, path)
    print(f"Config written to {path}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Special commands ──
    if args.list_patterns:
        cmd_list_patterns()
        return 0

    if args.list_tlds:
        cmd_list_tlds()
        return 0

    if args.init_config:
        cmd_init_config(args.init_config)
        return 0

    # ── Load config ──
    config = load_config(args.config)

    # Override salt from CLI
    if args.salt:
        config["salt"] = args.salt

    # Override categories from CLI flags
    for category in PATTERN_GROUPS:
        cli_val = getattr(args, f"cat_{category}", None)
        if cli_val is not None:
            config["categories"][category] = cli_val

    # ── Initialize engine ──
    redactor = Redactor(
        salt=config["salt"],
        categories=config["categories"],
        custom_patterns=config.get("custom_patterns"),
        high_entropy_threshold=config.get("high_entropy_threshold", 4.5),
    )

    # ── Read input ──
    if args.input == "-":
        text = sys.stdin.read()
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            return 1
        text = input_path.read_text(encoding="utf-8", errors="replace")

    if not text.strip():
        print("Warning: Empty input", file=sys.stderr)
        return 0

    # ── Detect format ──
    fmt = args.format
    if fmt == "auto":
        fmt = detect_format(text)

    # ── Process ──
    if fmt == "json":
        processor = JsonProcessor(redactor)
    else:
        processor = TextProcessor(redactor)

    redacted_text, findings = processor.process(text)

    # ── Output ──
    if args.dry_run:
        if findings:
            print(f"Found {len(findings)} secret(s):\n")
            for i, f in enumerate(findings, 1):
                line_info = f" (line {f['line']})" if "line" in f else ""
                path_info = f" (path: {f['json_path']})" if "json_path" in f else ""
                print(f"  {i}. [{f['type']}]{line_info}{path_info}")
                print(f"     Original:  {f['original'][:80]}{'...' if len(f['original']) > 80 else ''}")
                print(f"     Redacted:  {f['redacted']}")
                print()
        else:
            print("No secrets found.")
        return 0

    # Write output
    if args.output:
        Path(args.output).write_text(redacted_text, encoding="utf-8")
    else:
        sys.stdout.write(redacted_text)

    # Summary
    if not args.quiet:
        summary_parts = [f"{len(findings)} secret(s) redacted"]
        if findings:
            type_counts = {}
            for f in findings:
                type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
            breakdown = ", ".join(f"{v} {k}" for k, v in sorted(type_counts.items()))
            summary_parts.append(f"({breakdown})")

        input_label = args.input if args.input != "-" else "stdin"
        output_label = args.output if args.output else "stdout"
        print(f"  {input_label} -> {output_label}: {' '.join(summary_parts)}", file=sys.stderr)

    return 0
