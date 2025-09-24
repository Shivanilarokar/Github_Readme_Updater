# Src/agents/readme_updater.py
import logging
from typing import Dict, Any
from Src.config import OPENAI_API_KEY, OPENAI_MODEL

logger = logging.getLogger("ReadmeUpdater")
logging.basicConfig(level=logging.INFO)


def _build_prompt(owner: str, repo: str, pr_number: int, analysis: Dict[str, Any]) -> str:
    lines = [f"Repo: {owner}/{repo} PR:{pr_number}", "", "Analysis summary:"]

    summary = analysis.get("summary", {})
    lines.append(f"- files_changed: {summary.get('files_changed')}, total_added: {summary.get('total_added')}")
    lines.append("")

    # signatures (functions/classes)
    for s in analysis.get("modified_signatures", [])[:8]:
        if s.get("signature"):
            lines.append(f"- signature: {s['signature']} (file: {s['file']})")
        elif s.get("class"):
            lines.append(f"- class: {s['class']} (file: {s['file']})")

    # examples/CLI hints
    for ex in analysis.get("added_examples", [])[:3]:
        lines.append(f"- example hint: {ex.get('file')}")

    lines.append("")
    # ✅ Structured task (conservative README update)
    lines.append(
        """Task:
- Produce a short, conservative README.md patch (only markdown) that:
  * Adds an entry under "Usage" or "API" for the new functions/classes detected.
  * Shows a minimal code example demonstrating how to call the new function or CLI (if found).
  * For each item include a <!-- SOURCE: file/path.py --> comment.
- If uncertain, include a `TODO: verify` inline comment.
Return the markdown snippet ONLY.
"""
    )
    return "\n".join(lines)


def generate_readme_snippet(owner: str, repo: str, pr_number: int, analysis: Dict[str, Any]) -> str:
    """Generate a README snippet update suggestion based on analysis results."""
    if not analysis or not analysis.get("summary", {}).get("has_docworthy_changes"):
        logger.info("ReadmeUpdater: no doc-worthy changes, returning empty snippet")
        return ""

    # Fallback deterministic snippet (when no API key)
    if not OPENAI_API_KEY:
        md = ["## Auto-generated docs (preview)", f"<!-- SOURCE: {owner}/{repo} PR:{pr_number} -->", ""]
        for s in analysis.get("modified_signatures", []):
            if s.get("signature"):
                md.append(f"- `{s['signature']}` — TODO: add a brief example.")
            elif s.get("class"):
                md.append(f"- `class {s['class']}` — TODO: document usage.")
        for ex in analysis.get("added_examples", []):
            md.append(f"<!-- SOURCE: {ex['file']} -->")
            md.append("```")
            md.append(ex.get("snippet", "")[:300])
            md.append("```")
        md.append("\n> NOTE: automated suggestion; please review.")
        out = "\n".join(md)
        logger.info("ReadmeUpdater: deterministic snippet prepared")
        return out

    # ✅ Always invoke OpenAI if key available
    try:
        import openai
        openai.api_key = OPENAI_API_KEY
        prompt = _build_prompt(owner, repo, pr_number, analysis)

        resp = openai.ChatCompletion.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise technical writer. Always return valid Markdown only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=600,
            temperature=0.0,
        )

        text = resp.choices[0].message["content"].strip()
        logger.info("ReadmeUpdater: OpenAI returned snippet (len=%d)", len(text))
        return text

    except Exception as e:
        logger.exception("ReadmeUpdater: OpenAI call failed, falling back. Error: %s", e)
        return generate_readme_snippet(
            owner,
            repo,
            pr_number,
            {**analysis, "summary": {**analysis.get("summary", {})}},
        )
