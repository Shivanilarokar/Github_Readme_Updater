
import ast
import re
import logging
from typing import Dict, Any

logger = logging.getLogger("CodeAnalyzer")
logging.basicConfig(level=logging.INFO)

def _extract_added_lines(patch: str) -> list[str]:
    """Return list of added lines (lines starting with '+', skip diff headers)."""
    if not patch:
        return []
    lines = []
    for l in patch.splitlines():
        if l.startswith("+") and not l.startswith("+++"):
            lines.append(l[1:])
    return lines

def _extract_removed_lines(patch: str) -> list[str]:
    if not patch:
        return []
    return [l[1:] for l in patch.splitlines() if l.startswith("-") and not l.startswith("---")]

def _is_new_file(patch: str) -> bool:
    # Git unified diff contains "new file mode" when file was added
    return "new file mode" in (patch or "") or ("+++ b/" in (patch or "") and "/dev/null" not in (patch or "") and ("--- /dev/null" in (patch or "") or "new file" in (patch or "")))

def _is_deleted_file(patch: str) -> bool:
    return "deleted file mode" in (patch or "") or ("--- a/" in (patch or "") and "/dev/null" in (patch or ""))

def _parse_python_added_defs(added: str) -> list[dict]:
    """
    Parse added python code with AST when possible to extract function and class signatures.
    If AST parse fails (partial snippet) fallback to regex heuristics.
    """
    results = []
    if not added.strip():
        return results
    try:
        tree = ast.parse(added)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                args = [a.arg for a in node.args.args]
                results.append({"type":"function", "name": node.name, "signature": f"def {node.name}({', '.join(args)})"})
            elif isinstance(node, ast.ClassDef):
                results.append({"type":"class", "name": node.name})
    except SyntaxError:
        # fallback regex; will capture many heuristic matches
        for m in re.finditer(r"def\s+(\w+)\s*\(([^)]*)\)", added):
            results.append({"type":"function", "name": m.group(1), "signature": f"def {m.group(1)}({m.group(2)})"})
        for m in re.finditer(r"class\s+(\w+)\s*(\(.*\))?:", added):
            results.append({"type":"class", "name": m.group(1)})
    return results

def _detect_cli(added: str) -> bool:
    # look for common CLI libs or constructs
    if not added:
        return False
    if re.search(r"\b(import|from)\s+(argparse|click|typer)\b", added):
        return True
    if re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", added):
        return True
    return False

def _detect_examples(added: str) -> bool:
    if not added:
        return False
    # fenced code blocks + "example" keyword, or "Usage:" lines
    if "```" in added and re.search(r"example", added, re.I):
        return True
    if re.search(r"(^|\n)\s*Usage:|\n\s*Example:", added, re.I):
        return True
    return False

def analyze_diffs(diffs: Dict[str, str]) -> Dict[str, Any]:
    """
    Main analyzer entry.

    Input:
      diffs: map filename -> unified-diff patch text (as returned by GitHub pr.get_files()[].patch)

    Returns:
      structured dict:
        - new_files: list[str]
        - deleted_files: list[str]
        - modified_signatures: list[{"file","signature"/"class"}]
        - added_examples: list[{"file","reason","snippet"}]
        - cli_changes: list[{"file","reason"}]
        - file_stats: {file: {added:int, removed:int}}
        - summary: {...}
    """
    results = {
        "new_files": [],
        "deleted_files": [],
        "modified_signatures": [],
        "added_examples": [],
        "cli_changes": [],
        "other_changes": [],
        "file_stats": {},
    }

    total_added = 0
    total_removed = 0

    for path, patch in (diffs or {}).items():
        added_lines = _extract_added_lines(patch)
        removed_lines = _extract_removed_lines(patch)
        results["file_stats"][path] = {"added": len(added_lines), "removed": len(removed_lines)}
        total_added += len(added_lines)
        total_removed += len(removed_lines)

        # file-level status
        if _is_new_file(patch):
            results["new_files"].append(path)
        if _is_deleted_file(patch):
            results["deleted_files"].append(path)

        # Prepare joined added content for string-based heuristics
        joined_added = "\n".join(added_lines)

        # Python parsing for defs/classes/signatures
        if path.endswith(".py") and joined_added.strip():
            sigs = _parse_python_added_defs(joined_added)
            for s in sigs:
                results["modified_signatures"].append({"file": path, **s})

        # CLI detection
        if _detect_cli(joined_added):
            results["cli_changes"].append({"file": path, "reason": "cli/entrypoint detected"})

        # Example detection
        if _detect_examples(joined_added):
            snippet = "\n".join(added_lines[:200])
            results["added_examples"].append({"file": path, "snippet": snippet, "reason": "fenced code/example detected"})

        # Heuristic for modified public API: new top-level defs in any language
        if re.search(r"^\s*(public |export |module |def |function |class )", joined_added, re.I | re.M):
            results["other_changes"].append({"file": path, "hint": "top-level definitions detected"})

    results["summary"] = {
        "files_changed": len(results["file_stats"]),
        "total_added": total_added,
        "total_removed": total_removed,
        "has_docworthy_changes": bool(results["modified_signatures"] or results["added_examples"] or results["cli_changes"] or results["new_files"])
    }
    logger.info("Analyzer: files=%d added=%d removed=%d docworthy=%s",
                results["summary"]["files_changed"], total_added, total_removed, results["summary"]["has_docworthy_changes"])
    return results


