#!/usr/bin/env python3
"""Full package validation for the Multi-Agent Terminal design baseline v4.3."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
VALIDATION = ROOT / "validation"


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


checks: list[Check] = []


def record(name: str, passed: bool, detail: str) -> None:
    checks.append(Check(name, passed, detail))
    print(("PASS" if passed else "FAIL"), name, "-", detail)


def run_suite(name: str, script: str, expected_summary: str) -> None:
    proc = subprocess.run(
        [sys.executable, str(VALIDATION / script)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=120,
    )
    output = (proc.stdout + "\n" + proc.stderr).strip()
    ok = proc.returncode == 0 and expected_summary in output
    detail = expected_summary if ok else output[-1200:]
    record(name, ok, detail)


def run_regression_suites() -> None:
    specs = [
        ("suite.core_regression", "validate_v3.py", "39/39 checks passed"),
        ("suite.v32_hardening", "validate_v32_hardening.py", "68/68 v3.2 hardening checks passed"),
        ("suite.v4_cognitive", "validate_v4_memory.py", "79/79 v4 cognitive checks passed"),
        ("suite.v4_traceability", "validate_v4_traceability.py", "30/30 v4 traceability checks passed"),
        ("suite.v41_memory_utility", "validate_v41_memory_utility.py", "30/30 v4.1 memory utility checks passed"),
        ("suite.v41_traceability", "validate_v41_traceability.py", "19/19 v4.1 traceability checks passed"),
        ("suite.v411_loop_review", "validate_v411_loop_review.py", "60/60 v4.1.1 loop-review checks passed"),
        ("suite.v42_end_to_end", "validate_v42_end_to_end.py", "96/96 v4.2 end-to-end checks passed"),
        ("suite.v43_implementation_product_proof", "validate_v43_implementation_product_proof.py", "81/81 v4.3 implementation/product-proof checks passed"),
    ]

    def execute(spec: tuple[str, str, str]) -> tuple[str, bool, str]:
        name, script, expected = spec
        try:
            proc = subprocess.run(
                [sys.executable, str(VALIDATION / script)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired as exc:
            return name, False, f"timed out after {exc.timeout}s"
        output = (proc.stdout + "\n" + proc.stderr).strip()
        ok = proc.returncode == 0 and expected in output
        return name, ok, expected if ok else output[-1200:]

    resolved: dict[str, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=min(6, len(specs))) as executor:
        futures = {executor.submit(execute, spec): spec[0] for spec in specs}
        for future in as_completed(futures):
            name, ok, detail = future.result()
            resolved[name] = (ok, detail)
    for name, _, _ in specs:
        ok, detail = resolved[name]
        record(name, ok, detail)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_json_files() -> None:
    for path in sorted(ROOT.rglob("*.json")):
        try:
            load_json(path)
        except Exception as exc:
            record(f"json.parse.{path.relative_to(ROOT)}", False, str(exc))
        else:
            record(f"json.parse.{path.relative_to(ROOT)}", True, "valid JSON")


def validate_schemas() -> None:
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        try:
            Draft202012Validator.check_schema(load_json(path))
        except Exception as exc:
            record(f"schema.compile.{path.name}", False, str(exc))
        else:
            record(f"schema.compile.{path.name}", True, "Draft 2020-12 schema valid")


def validate_instance(schema_file: str, instance_file: str, definition: str | None = None) -> None:
    schema = load_json(SCHEMAS / schema_file)
    instance = load_json(SCHEMAS / instance_file)
    target = schema
    if definition is not None:
        target = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
    errors = list(Draft202012Validator(target).iter_errors(instance))
    if errors:
        record(f"example.{instance_file}", False, errors[0].message)
    else:
        record(f"example.{instance_file}", True, f"valid against {schema_file}")


def validate_root_instance(schema_file: str, instance_file: str) -> None:
    schema = load_json(SCHEMAS / schema_file)
    instance = load_json(ROOT / instance_file)
    errors = list(Draft202012Validator(schema).iter_errors(instance))
    if errors:
        record(f"example.{instance_file}", False, errors[0].message)
    else:
        record(f"example.{instance_file}", True, f"valid against {schema_file}")


def validate_examples() -> None:
    validate_instance("agent-protocol.v1.schema.json", "examples/protocol-context-query.request.json")
    validate_instance("agent-protocol.v1.schema.json", "examples/protocol-initialize.request.json")
    validate_instance("agent-protocol.v1.schema.json", "examples/protocol-run-complete.request.json")
    validate_instance("approval-digest.v1.schema.json", "examples/approval-final-commit.example.json")
    validate_instance("agent-protocol.v2.schema.json", "examples-v2/protocol-initialize.request.json", "initializeRequest")
    validate_instance("agent-protocol.v2.schema.json", "examples-v2/protocol-initialize.response.json", "initializeResponse")
    validate_instance("agent-protocol.v2.schema.json", "examples-v2/protocol-tool.response.json", "toolResponse")
    validate_instance("approval-digest.v2.schema.json", "examples-v2/approval-final-commit.example.json")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/retrieval-request.example.json", "retrievalRequest")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/memory-proposal.example.json", "memoryProposal")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/context-package.example.json", "contextPackage")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/run-evaluation.example.json", "runEvaluation")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/context-supplement-request.example.json", "contextSupplementRequest")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/working-memory-event.example.json", "workingMemoryEvent")
    validate_instance("cognitive-memory.v1.schema.json", "examples-v4/run-reflection.example.json", "runReflection")
    validate_instance("agent-quality-benchmark.v1.schema.json", "examples-v4/benchmark-suite.example.json")
    validate_instance("cognitive-memory.v2.schema.json", "examples-v41/state-record.example.json", "stateRecord")
    validate_instance("cognitive-memory.v2.schema.json", "examples-v41/memory-proposal.example.json", "memoryProposal")
    validate_instance("cognitive-memory.v2.schema.json", "examples-v41/memory-shadow-evaluation.example.json", "memoryShadowEvaluation")
    validate_instance("cognitive-memory.v2.schema.json", "examples-v41/context-budget-decision.example.json", "contextBudgetDecision")
    validate_instance("agent-quality-benchmark.v2.schema.json", "examples-v41/benchmark-suite.example.json")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/state-resolution-conflict.example.json", "stateResolutionConflict")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/state-resolution-receipt.example.json", "stateResolutionReceipt")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/memory-origin-record.example.json", "memoryOriginRecord")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/memory-shadow-evaluation.example.json", "memoryShadowEvaluation")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/memory-usage-event.example.json", "memoryUsageEvent")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/context-budget-decision.example.json", "contextBudgetDecision")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/benchmark-run-arm.example.json", "benchmarkRunArm")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/benchmark-run-memory-binding.example.json", "benchmarkRunMemoryBinding")
    validate_instance("cognitive-memory.v3.schema.json", "examples-v411/invalidation-evaluation.example.json", "invalidationEvaluation")
    validate_instance("cognitive-memory.v4.schema.json", "examples-v42/retrieval-indeterminate.example.json", "retrievalResult")
    validate_instance("cognitive-memory.v4.schema.json", "examples-v42/preference-memory-proposal.example.json", "memoryProposal")
    validate_instance("benchmark-suite.v3.schema.json", "examples-v42/benchmark-suite.example.json")
    validate_instance("benchmark-run-receipt.v1.schema.json", "examples-v42/benchmark-run-receipt.example.json")
    validate_instance("benchmark-case-result.v1.schema.json", "examples-v42/benchmark-case-result.example.json")
    validate_instance("benchmark-comparison-report.v1.schema.json", "examples-v42/benchmark-comparison-report.example.json")
    validate_instance("quality-release-decision.v1.schema.json", "examples-v42/quality-release-decision.example.json")
    validate_instance("actor-binding.v1.schema.json", "examples-v42/actor-binding.example.json")
    validate_instance("credential-challenge.v1.schema.json", "examples-v42/credential-challenge.example.json")
    validate_instance("workflow-transition-command.v1.schema.json", "examples-v43/workflow-transition-command.example.json")
    validate_instance("run-configuration.v1.schema.json", "examples-v43/run-configuration.example.json")
    validate_instance("assurance-degradation-receipt.v1.schema.json", "examples-v43/assurance-degradation-receipt.example.json")
    validate_instance("orchestration-benchmark-suite.v1.schema.json", "examples-v43/orchestration-benchmark-suite.example.json")
    validate_instance("orchestration-benchmark-run-receipt.v1.schema.json", "examples-v43/orchestration-benchmark-run-receipt.example.json")
    validate_instance("orchestration-benchmark-case-result.v1.schema.json", "examples-v43/orchestration-benchmark-case-result.example.json")
    validate_instance("orchestration-benchmark-comparison-report.v1.schema.json", "examples-v43/orchestration-benchmark-comparison-report.example.json")
    validate_instance("product-traceability.v1.schema.json", "product-traceability.v43.json")
    validate_root_instance("agent-quality-benchmark.v2.schema.json", "benchmarks/context-memory-bootstrap-v1.json")
    validate_root_instance("orchestration-benchmark-suite.v1.schema.json", "benchmarks/orchestration-product-proof-bootstrap-v1.json")


def validate_markdown_links() -> None:
    broken: list[str] = []
    pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for md in sorted(ROOT.rglob("*.md")):
        text = md.read_text(encoding="utf-8")
        for raw in pattern.findall(text):
            target = raw.strip().split()[0]
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (md.parent / target).resolve()
            if not resolved.exists():
                broken.append(f"{md.relative_to(ROOT)} -> {raw}")
    record(
        "package.markdown_links",
        not broken,
        "all relative Markdown links resolve" if not broken else "; ".join(broken[:20]),
    )


def extract_sql_enum(sql: str, column: str) -> set[str]:
    match = re.search(rf"\b{re.escape(column)}\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(\s*{re.escape(column)}\s+IN\s*\((.*?)\)\s*\)", sql, re.S)
    if not match:
        return set()
    return set(re.findall(r"'([^']+)'", match.group(1)))


def validate_transition_alignment() -> None:
    sql = (SCHEMAS / "sqlite-v7.sql").read_text(encoding="utf-8")
    workflow = load_json(SCHEMAS / "workflow-transitions.v3.json")
    workflow_table = re.search(r"CREATE TABLE task_workflow_authority\s*\((.*?)\) STRICT;", sql, re.S)
    workflow_sql = workflow_table.group(1) if workflow_table else ""
    comparisons = {
        "phases": extract_sql_enum(workflow_sql, "phase"),
        "conditions": extract_sql_enum(sql, "condition"),
        "operationStates": extract_sql_enum(sql, "operation_state"),
    }
    mismatches: list[str] = []
    for key, sql_values in comparisons.items():
        json_values = set(workflow[key])
        if sql_values != json_values:
            mismatches.append(
                f"{key}: SQL-only={sorted(sql_values-json_values)}, JSON-only={sorted(json_values-sql_values)}"
            )
    phases = set(workflow["phases"])
    transitions = list(workflow["phaseTransitions"]) + [workflow["workspaceDirtyTransition"]] + list(workflow["globalPhaseTransitions"])
    for transition in transitions:
        sources = transition.get("fromPhases", [transition.get("from")])
        if any(source not in phases for source in sources) or transition["to"] not in phases:
            mismatches.append(f"invalid phase transition {transition}")
    record(
        "package.workflow_sql_alignment",
        not mismatches,
        "v4.3 workflow enums and transition endpoints align with SQLite v7" if not mismatches else "; ".join(mismatches),
    )


def validate_text_hygiene() -> None:
    offenders: list[str] = []
    marker = r"(?:TODO|TBD|FIXME|XXX|PLACEHOLDER)"
    patterns = (
        re.compile(rf"^\s*(?:[-*]\s*)?{marker}(?:\s*[:\-]|\s*$)", re.I),
        re.compile(rf"^\s*(?:#|//|--|/\*|\*)\s*{marker}(?:\s*[:\-]|\s*$)", re.I),
        re.compile(rf"<!--\s*{marker}(?:\s*[:\-]|\s*)-->", re.I),
    )
    for path in sorted(ROOT.rglob("*")):
        if path.resolve() == Path(__file__).resolve():
            continue
        if path.is_file() and path.suffix.lower() in {".md", ".sql", ".py", ".json"}:
            text = path.read_text(encoding="utf-8")
            if any(pattern.search(line) for line in text.splitlines() for pattern in patterns):
                offenders.append(str(path.relative_to(ROOT)))
    record(
        "package.no_placeholders",
        not offenders,
        "no active placeholder markers" if not offenders else ", ".join(offenders),
    )


def write_report() -> None:
    payload = {"checks": [asdict(c) for c in checks]}
    (VALIDATION / "package-validation-results.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Package Validation Results",
        "",
        "Generated by `python validation/validate_package.py`.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for c in checks:
        detail = c.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{c.name}` | {'PASS' if c.passed else 'FAIL'} | {detail} |")
    passed = sum(c.passed for c in checks)
    lines.extend(["", f"**Package checks:** {passed}/{len(checks)} passed.", ""])
    (VALIDATION / "PACKAGE-VALIDATION-RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    run_regression_suites()
    validate_json_files()
    validate_schemas()
    validate_examples()
    validate_markdown_links()
    validate_transition_alignment()
    validate_text_hygiene()
    write_report()
    failed = [c for c in checks if not c.passed]
    passed = len(checks) - len(failed)
    print(f"\n{passed}/{len(checks)} package checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
