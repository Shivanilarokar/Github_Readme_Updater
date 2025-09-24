#!/usr/bin/env python3
"""
CI runner for GitHub Actions — builds state from the event and invokes run_flow(state).
Place at Src/ci/gh_action_runner.py
"""

import os
import sys
import json
import argparse
import logging
from github import Github
import requests
from Src.agents.orchestrator import run_flow
from Src.config import GITHUB_TOKEN  # fallback local env if run locally

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gh_action_runner")

# Use token from env (set by workflow)
GH_TOKEN = os.environ.get("GITHUB_TOKEN", GITHUB_TOKEN)
GH_HEADERS = {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"}

def load_event(event_path):
    with open(event_path, "r", encoding="utf-8") as f:
        return json.load(f)

def fetch_pr_files_rest(owner, repo, pr_number):
    files = []
    page = 1
    per_page = 100
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?page={page}&per_page={per_page}"
        r = requests.get(url, headers=GH_HEADERS, timeout=20)
        r.raise_for_status()
        page_files = r.json()
        if not page_files:
            break
        files.extend(page_files)
        if len(page_files) < per_page:
            break
        page += 1
    return files

def fetch_compare_files(owner, repo, before, after):
    url = f"https://api.github.com/repos/{owner}/{repo}/compare/{before}...{after}"
    r = requests.get(url, headers=GH_HEADERS, timeout=30)
    r.raise_for_status()
    return r.json().get("files", [])

def build_diffs_from_rest_files(rest_files, max_lines=100):
    diffs = {}
    for f in rest_files:
        filename = f.get("filename") or f.get("path") or "<unknown>"
        status = f.get("status", "")
        if status == "added":
            patch = "[File Added]"
        elif status == "removed":
            patch = "[File Removed]"
        else:
            patch = f.get("patch") or ""
        if patch and isinstance(patch, str):
            lines = patch.splitlines()
            if len(lines) > max_lines:
                patch = "\n".join(lines[:max_lines]) + f"\n... (truncated {len(lines)-max_lines} lines)"
        diffs[filename] = patch
    return diffs

def run_for_push(event, repo_full, sha):
    owner, repo = repo_full.split("/", 1)
    before = event.get("before")
    after = event.get("after", sha)
    logger.info("Push event: %s/%s before=%s after=%s", owner, repo, before, after)
    try:
        rest_files = fetch_compare_files(owner, repo, before, after)
    except Exception as e:
        logger.warning("Compare API failed: %s; falling back to commit GET", e)
        # fallback to commit files
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{after}"
        r = requests.get(url, headers=GH_HEADERS, timeout=20)
        r.raise_for_status()
        rest_files = r.json().get("files", [])
    diffs = build_diffs_from_rest_files(rest_files)
    state = {"owner": owner, "repo": repo, "commit_sha": after, "pr_number": 0, "diffs": diffs}
    return state

def run_for_pr(event):
    pr = event.get("pull_request", {})
    owner = event["repository"]["owner"]["login"]
    repo = event["repository"]["name"]
    pr_number = pr.get("number")
    head_sha = pr.get("head", {}).get("sha")
    logger.info("PR event: %s/%s pr=%s head=%s", owner, repo, pr_number, head_sha)
    rest_files = fetch_pr_files_rest(owner, repo, pr_number)
    diffs = build_diffs_from_rest_files(rest_files)
    state = {"owner": owner, "repo": repo, "pr_number": pr_number, "commit_sha": head_sha, "diffs": diffs}
    return state

def pretty_log_state(state):
    # log filenames and patch presence (truncated)
    diffs = state.get("diffs", {})
    logger.info("Files changed: %d", len(diffs))
    for fn, patch in diffs.items():
        has = "yes" if patch and not patch.startswith("[File") else "no"
        logger.info(" - %s (patch? %s)", fn, has)
    logger.info("Diffs (truncated preview):\n%s", json.dumps({k: (v[:400] + "...") if isinstance(v,str) and len(v)>400 else v for k,v in diffs.items()}, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event_path", required=True)
    parser.add_argument("--event_name", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()

    event = load_event(args.event_path)
    state = None

    if args.event_name == "push":
        state = run_for_push(event, args.repo, args.sha)
    elif args.event_name == "pull_request":
        # only run for certain PR actions (open, synchronize, reopened, edited)
        action = event.get("action")
        if action in ("opened", "synchronize", "reopened", "edited"):
            state = run_for_pr(event)
        else:
            logger.info("PR action '%s' ignored", action)
            return 0
    else:
        logger.info("Event %s not handled", args.event_name)
        return 0

    pretty_log_state(state)

    # Safety guard: limit number of files/added lines
    max_files = int(os.getenv("MAX_FILES", "200"))
    if len(state.get("diffs", {})) == 0:
        logger.info("No diffs detected - nothing to do")
        return 0
    if len(state.get("diffs", {})) > max_files:
        logger.warning("Too many files changed (%d > %d) - skipping", len(state["diffs"]), max_files)
        return 0

    # Run the orchestrator (LangGraph pipeline)
    logger.info("Running orchestrator...")
    res = run_flow(state)
    logger.info("Orchestrator returned (truncated):\n%s", json.dumps(res, indent=2)[:4000])
    return 0

if __name__ == "__main__":
    sys.exit(main())
