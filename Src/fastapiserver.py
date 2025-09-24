from fastapi import FastAPI, Request, Header, HTTPException
import hmac, hashlib, logging, os, sys, traceback, json
from github import Github  # PyGithub
import requests  # REST API fallback
from Src.config import GITHUB_WEBHOOK_SECRET, GITHUB_TOKEN
from Src.agents.orchestrator import run_flow

# ---------------- Logging setup ----------------
logger = logging.getLogger("FastAPIWebhook")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ---------------- Globals ----------------
app = FastAPI()
gh = Github(GITHUB_TOKEN) if GITHUB_TOKEN else None

GH_API_TOKEN = GITHUB_TOKEN or os.getenv("GITHUB_TOKEN")
GH_HEADERS = {
    "Authorization": f"token {GH_API_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# ---------------- Helpers ----------------
def verify_signature(body: bytes, signature: str):
    """Verify GitHub webhook signature"""
    if not GITHUB_WEBHOOK_SECRET:
        return True
    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), msg=body, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

def fetch_pr_files_via_rest(owner: str, repo: str, pr_number: int) -> list[dict]:
    """Fetch PR file patches using REST API"""
    files, page, per_page = [], 1, 100
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?page={page}&per_page={per_page}"
        r = requests.get(url, headers=GH_HEADERS, timeout=15)
        if r.status_code != 200:
            logger.warning("REST PR fetch failed %s: %s", r.status_code, r.text)
            break
        page_files = r.json()
        if not page_files:
            break
        files.extend(page_files)
        if len(page_files) < per_page:
            break
        page += 1
    return files

def fetch_push_diffs(owner: str, repo: str, before: str, after: str) -> list[dict]:
    """Fetch push diffs via Compare API, fallback to commit if new branch"""
    if before and not before.startswith("000000"):
        # normal case: compare before..after
        url = f"https://api.github.com/repos/{owner}/{repo}/compare/{before}...{after}"
        r = requests.get(url, headers=GH_HEADERS, timeout=20)
        if r.status_code == 200:
            return r.json().get("files", [])
        logger.warning("REST compare fetch failed %s: %s", r.status_code, r.text)

    # fallback: single commit fetch
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{after}"
    r = requests.get(url, headers=GH_HEADERS, timeout=20)
    if r.status_code == 200:
        return r.json().get("files", [])
    logger.warning("REST commit fetch failed %s: %s", r.status_code, r.text)
    return []

def truncate_patch(patch: str, max_lines: int = 20) -> str:
    """Truncate patch per file to avoid massive logs"""
    if not patch:
        return patch
    lines = patch.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... (truncated {len(lines)-max_lines} lines)"
    return patch

def build_diffs_from_rest_filelist(rest_files: list) -> dict:
    """Build {filename: patch} dict with truncation"""
    diffs = {}
    for f in rest_files:
        filename = f.get("filename") or f.get("path") or "<unknown>"
        if f.get("status") == "added":
            patch = "[File Added]"
        elif f.get("status") == "removed":
            patch = "[File Removed]"
        else:
            patch = f.get("patch") or ""
        diffs[filename] = truncate_patch(patch)
    return diffs

# ---------------- Routes ----------------
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/webhook")
async def webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
):
    body = await request.body()
    verify_signature(body, x_hub_signature_256)
    payload = await request.json()

    try:
        state = None

        # ---------- Pull Request ----------
        if x_github_event == "pull_request":
            action = payload.get("action")
            if action in ("opened", "synchronize", "reopened", "edited"):
                pr = payload["pull_request"]
                owner = payload["repository"]["owner"]["login"]
                repo = payload["repository"]["name"]
                pr_number = pr["number"]

                rest_files = fetch_pr_files_via_rest(owner, repo, pr_number)
                diffs = build_diffs_from_rest_filelist(rest_files)

                logger.info("📌 Handling PR %s/%s#%s (files=%d)", owner, repo, pr_number, len(diffs))
                for fn, patch in diffs.items():
                    logger.info(" - %s (patch? %s)", fn, "yes" if patch else "no")
                logger.info("📌 Incoming diffs:\n%s", json.dumps(diffs, indent=2))

                state = {"owner": owner, "repo": repo, "pr_number": pr_number, "diffs": diffs}

        # ---------- Push ----------
        elif x_github_event == "push":
            owner = payload["repository"]["owner"]["login"]
            repo = payload["repository"]["name"]
            before = payload.get("before")
            after = payload.get("after")

            rest_files = fetch_push_diffs(owner, repo, before, after)
            diffs = build_diffs_from_rest_filelist(rest_files)

            logger.info("📌 Handling PUSH %s/%s @ %s (files=%d)", owner, repo, after, len(diffs))
            for fn, patch in diffs.items():
                logger.info(" - %s (patch? %s)", fn, "yes" if patch else "no")
            logger.info("📌 Incoming diffs:\n%s", json.dumps(diffs, indent=2))

            state = {"owner": owner, "repo": repo, "commit_sha": after, "pr_number": 0, "diffs": diffs}

        # ---------- Orchestrator ----------
        if state:
            logger.info("📌 Running orchestrator for %s/%s", state["owner"], state["repo"])
            result = run_flow(state)
            logger.info("🔥 Full LangGraph output (truncated):\n%s",
                        json.dumps(result, indent=2)[:4000])
            return {"ok": True, "event": x_github_event, "result": result}

        logger.info("⚠️ Ignored event %s", x_github_event)
        return {"ok": True, "note": "ignored event"}

    except Exception as e:
        logger.exception("Webhook handler error: %s", e)
        return {"ok": False, "error": str(e), "trace": traceback.format_exc()}
