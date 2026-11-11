"""Terminal interface for Cyber Operator."""

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

from cyber_operator.config import Config
from cyber_operator.core import (
    IntelligenceQuery,
    Orchestrator,
    SelectionMode,
)
from cyber_operator.utils import format_duration, safe_json_dumps

OPERATIONS = {
    "osint": ("OSINT / Cyber Intelligence", "OSINT / Cyber Intelligence"),
    "network": ("Network Intelligence", "OSINT / Cyber Intelligence"),
    "web": ("Web Security", "Web Security"),
    "threat": ("Threat Intelligence", "Blue Team / Threat Intelligence"),
    "blockchain": ("Blockchain Security", "Blockchain Security"),
    "lab": ("Cyber Lab Analysis", "Cyber Range / Lab Analysis"),
}
LOCAL_TOOLS = {
    "nmap": ("nmap", "nmap.exe"),
    "whatweb": ("whatweb",),
    "nuclei": ("nuclei", "nuclei.exe"),
    "dig": ("dig",),
    "host": ("host",),
    "nslookup": ("nslookup", "nslookup.exe"),
}


def print_banner() -> None:
    print(
        "\n"
        "============================================================\n"
        "                 CYBER OPERATOR v0.2\n"
        "        INTELLIGENCE SEARCH ENGINE - TERMINAL EDITION\n"
        "============================================================\n"
    )


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cyber Operator - terminal intelligence search engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 main.py\n"
            "  python3 main.py --target 192.168.56.102 --operation network\n"
            "  python3 main.py --target example.com --operation osint\n"
            "  python3 main.py --target example.com --sources dns_resolver,rdap_lookup\n"
            "  python3 main.py --list-sources\n"
            "  python3 main.py --history\n"
            "  python3 main.py --export <query-id> --format markdown\n"
        ),
    )
    parser.add_argument("-t", "--target", help="Domain, IP, URL, hash, or other target")
    parser.add_argument(
        "-o", "--operation",
        choices=sorted(OPERATIONS),
        help="Operation category (default: osint)",
    )
    parser.add_argument(
        "-m", "--mode",
        choices=[mode.value for mode in SelectionMode],
        default="recommended",
        help="Source-selection mode",
    )
    parser.add_argument(
        "-s", "--sources",
        help="Comma-separated source IDs; selecting these uses MANUAL mode",
    )
    parser.add_argument("--list-sources", action="store_true", help="List registered sources")
    parser.add_argument("--list-categories", action="store_true", help="List categories")
    parser.add_argument("--list-tools", action="store_true", help="Detect local tools (no execution)")
    parser.add_argument("--history", action="store_true", help="Show recent search history")
    parser.add_argument("--reports", action="store_true", help="List saved report files")
    parser.add_argument("--export", metavar="QUERY_ID", help="Export a saved query report")
    parser.add_argument(
        "--format", "--output",
        choices=("text", "json", "markdown"),
        default="text",
        help="Terminal output format, or report format with --export",
    )
    return parser


def operation_category(operation: str) -> Optional[str]:
    return OPERATIONS.get(operation, (None, None))[1]


def list_sources(orchestrator: Orchestrator) -> None:
    print("\nRegistered sources (only implemented connectors execute):")
    for source in sorted(
        orchestrator.get_available_sources(),
        key=lambda item: (item["category"], item["name"]),
    ):
        active = "active" if source["active"] else "inactive"
        availability = source["availability"].replace("_", " ")
        print(
            f"- {source['id']:<18} {source['name']:<24} "
            f"[{active}; {availability}; credentials={source['credentials_status']}; "
            f"{source['category']}]"
        )
        print(f"  {source['description']}")


def list_tools() -> None:
    print("\nLocal tool availability (detection only; tools are not executed):")
    for name, candidates in LOCAL_TOOLS.items():
        path = next(
            (shutil.which(candidate) for candidate in candidates if shutil.which(candidate)),
            None,
        )
        print(f"- {name:<10} {'available: ' + path if path else 'not installed'}")
    print("Network scanners and web scanners require separate authorization and are not run by this CLI.")


def print_history(orchestrator: Orchestrator, limit: int = 20) -> None:
    history = orchestrator.database_manager.get_query_history(limit=limit)
    if not history:
        print("\nNo saved searches.")
        return
    print("\nRecent searches:")
    for row in history:
        print(
            f"- {row.get('query_id') or row['id']} | {row['timestamp']} | "
            f"{row['target']} ({row.get('target_type') or 'unknown'}) | "
            f"{row.get('status') or ('success' if row['success'] else 'failed')} | "
            f"mode={row.get('selection_mode') or 'unknown'}"
        )


def list_reports() -> None:
    report_dir = Config.BASE_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_files = sorted(
        path for path in report_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".json", ".md"}
    )
    if not report_files:
        print("\nNo exported reports.")
        return
    print("\nSaved reports:")
    for report in report_files:
        print(f"- {report.name} ({report.stat().st_size} bytes)")


def export_report(orchestrator: Orchestrator, query_id: str, output_format: str) -> Path:
    row = orchestrator.database_manager.get_query_by_id(query_id)
    if row is None:
        raise ValueError(f"No saved search found for query ID: {query_id}")
    result = json.loads(row["result_data"])
    report_dir = Config.BASE_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    suffix = "json" if output_format == "json" else "md"
    output_path = report_dir / f"{query_id}.{suffix}"

    if output_format == "json":
        content = safe_json_dumps(result, indent=2)
    else:
        content = render_markdown_report(result)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def render_markdown_report(result: Dict) -> str:
    query = result.get("query", {})
    summary = result.get("execution_summary", {})
    findings = result.get("findings", {})
    lines = [
        "# Cyber Operator Intelligence Report",
        "",
        f"- Query ID: `{result.get('query_id', 'unknown')}`",
        f"- Target: `{query.get('target', 'unknown')}`",
        f"- Target type: `{query.get('target_type', 'unknown')}`",
        f"- Status: **{result.get('status', 'unknown')}**",
        f"- Time: {query.get('timestamp', 'unknown')}",
        "",
        "## Execution summary",
        "",
        f"- Sources queried: {summary.get('total_queries', 0)}",
        f"- Successful: {summary.get('successful', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Elapsed: {format_duration(summary.get('total_execution_time', 0))}",
        "",
        "## Sources",
        "",
    ]
    for source_id, source in findings.get("sources", {}).items():
        lines.extend([
            f"### {source.get('source_name', source_id)} (`{source_id}`)",
            "",
            f"- Availability: {source.get('availability_status', 'unknown')}",
            f"- Execution: {source.get('execution_status', 'unknown')}",
            f"- Response time: {source.get('execution_time', 0):.3f}s",
        ])
        if source.get("error"):
            lines.append(f"- Error: {source['error']}")
        if source.get("data") is not None:
            lines.extend(["", "```json", safe_json_dumps(source["data"], indent=2), "```"])
        lines.append("")
    lines.extend([
        "## Risk indicators",
        "",
        findings.get("risk_assessment", {}).get(
            "interpretation", "Indicators are not vulnerability confirmations."
        ),
        "",
    ])
    for indicator in findings.get("risk_assessment", {}).get("indicators", []):
        lines.append(f"- {indicator}")
    return "\n".join(lines) + "\n"


def print_result(result: Dict, output_format: str = "text") -> None:
    if output_format == "json":
        print(safe_json_dumps(result, indent=2))
        return

    summary = result.get("execution_summary", {})
    print(f"\nQuery: {result.get('query_id', 'unknown')}")
    print(f"Target: {result.get('query', {}).get('target', result.get('target', 'unknown'))}")
    print(f"Overall status: {result.get('status', 'failed')}")
    print(
        f"Sources: {summary.get('successful', 0)} successful, "
        f"{summary.get('failed', 0)} failed; "
        f"{format_duration(summary.get('total_execution_time', 0))}"
    )
    for source_id, source in result.get("findings", {}).get("sources", {}).items():
        print(
            f"\n[{source.get('execution_status', 'unknown').upper()}] "
            f"{source.get('source_name', source_id)} ({source_id}) "
            f"- {source.get('execution_time', 0):.3f}s"
        )
        if source.get("cached"):
            print("  Result from SQLite cache")
        if source.get("error"):
            print(f"  Error: {source['error']}")
        elif source.get("data") is not None:
            print("  Result:")
            print(
                json.dumps(source["normalized_data"], indent=2, ensure_ascii=False, default=str)
            )
    for skipped in result.get("sources", {}).get("skipped", []):
        print(
            f"\n[NOT RUN] {skipped.get('source_name', skipped.get('source_id') or 'source selection')}: "
            f"{skipped.get('availability_status', 'unavailable')}"
        )
    risk = result.get("findings", {}).get("risk_assessment", {})
    if risk:
        print(f"\nRisk heuristic: {risk.get('level', 'unknown')} (score {risk.get('score', 0)})")
        print(risk.get("interpretation", "Risk indicators do not confirm vulnerabilities."))


def choose_manual_sources(orchestrator: Orchestrator, target: str,
                          operation: str) -> List[str]:
    target_type, _ = orchestrator.classifier.classify(target)
    category = operation_category(operation)
    candidates = []
    for source in orchestrator.registry.get_active_sources():
        if category and source.category != category:
            continue
        if not orchestrator.engine.is_compatible(source, target, target_type.value):
            continue
        if orchestrator.engine.get_availability(source) != "available":
            continue
        candidates.append(source)
    if not candidates:
        print("No implemented, available sources are compatible with this target and operation.")
        return []
    print("\nCompatible sources:")
    for index, source in enumerate(candidates, 1):
        print(f"{index}. {source.name} ({source.id})")
    answer = input("Select source numbers separated by commas (or Enter to cancel): ").strip()
    if not answer:
        return []
    selected = []
    for token in answer.split(","):
        try:
            selected.append(candidates[int(token.strip()) - 1].id)
        except (ValueError, IndexError):
            print(f"Ignoring invalid selection: {token.strip()}")
    return list(dict.fromkeys(selected))


def execute_search(orchestrator: Orchestrator, target: str, operation: str,
                   mode: str, source_ids: Optional[List[str]] = None,
                   output_format: str = "text") -> int:
    operation_key = operation.lower()
    if operation_key == "network":
        target_type, _ = orchestrator.classifier.classify(target)
        if target_type.value not in {"ipv4", "ipv6", "domain"}:
            print("Network Intelligence supports domain and IP targets only.")
            return 2
    if source_ids:
        mode = "manual"
    query = IntelligenceQuery(
        target=target,
        selection_mode=SelectionMode(mode.upper()),
        categories=[operation_category(operation_key)] if operation_category(operation_key) else [],
        source_ids=source_ids,
    )
    result = orchestrator.execute_query(query)
    print_result(result, output_format)
    return 0 if result.get("success") else 1


def source_manager(orchestrator: Orchestrator) -> None:
    while True:
        list_sources(orchestrator)
        source_id = input("\nEnter source ID to toggle (Enter to return): ").strip()
        if not source_id:
            return
        source = orchestrator.registry.get_source(source_id)
        if source is None:
            print("Unknown source ID.")
            continue
        if source.active:
            orchestrator.disable_source(source_id)
            print(f"Disabled {source_id} for this session.")
        else:
            orchestrator.enable_source(source_id)
            print(f"Enabled {source_id} for this session.")


def interactive_menu(orchestrator: Orchestrator) -> int:
    operations = list(OPERATIONS.items())
    while True:
        print(
            "\nMain menu\n"
            "1. OSINT / Cyber Intelligence\n"
            "2. Network Intelligence\n"
            "3. Web Security\n"
            "4. Threat Intelligence\n"
            "5. Blockchain Security\n"
            "6. Cyber Lab Analysis\n"
            "7. Source Manager\n"
            "8. Search History\n"
            "9. Report Management\n"
            "10. Local tool availability\n"
            "0. Exit"
        )
        choice = input("Select: ").strip()
        if choice == "0":
            return 0
        if choice == "7":
            source_manager(orchestrator)
            continue
        if choice == "8":
            print_history(orchestrator)
            continue
        if choice == "9":
            list_reports()
            query_id = input("Query ID to export (Enter to return): ").strip()
            if query_id:
                report_format = input("Format [json/markdown] (default json): ").strip().lower()
                try:
                    path = export_report(
                        orchestrator, query_id,
                        "markdown" if report_format in {"md", "markdown"} else "json"
                    )
                    print(f"Report saved: {path}")
                except (ValueError, OSError, json.JSONDecodeError) as exc:
                    print(f"Report export failed: {exc}")
            continue
        if choice == "10":
            list_tools()
            continue
        try:
            operation = operations[int(choice) - 1][0]
        except (ValueError, IndexError):
            print("Invalid menu choice.")
            continue

        target = input("Target: ").strip()
        if not target:
            print("Target is required.")
            continue
        mode = input("Mode [recommended/all/manual] (default recommended): ").strip().lower()
        if not mode:
            mode = "recommended"
        if mode not in {item.value for item in SelectionMode}:
            print("Invalid selection mode.")
            continue
        source_ids = None
        if mode == "manual":
            source_ids = choose_manual_sources(orchestrator, target, operation)
            if not source_ids:
                continue
        execute_search(orchestrator, target, operation, mode, source_ids)


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    parser = get_parser()
    args = parser.parse_args(argv)
    orchestrator = Orchestrator()

    try:
        if args.list_sources:
            list_sources(orchestrator)
            return 0
        if args.list_categories:
            for category in orchestrator.get_categories():
                print(category)
            return 0
        if args.list_tools:
            list_tools()
            return 0
        if args.history:
            print_history(orchestrator)
            return 0
        if args.reports:
            list_reports()
            return 0
        if args.export:
            report_format = "json" if args.format == "text" else args.format
            path = export_report(orchestrator, args.export, report_format)
            print(f"Report saved: {path}")
            return 0
        if not args.target:
            print_banner()
            return interactive_menu(orchestrator)

        operation = args.operation or "osint"
        source_ids = (
            [source.strip() for source in args.sources.split(",") if source.strip()]
            if args.sources else None
        )
        if args.mode == "manual" and not source_ids:
            parser.error("--mode manual requires --sources for non-interactive use")
        return execute_search(
            orchestrator, args.target, operation, args.mode, source_ids,
            "json" if args.format == "json" else "text",
        )
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
