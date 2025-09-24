from fastapi import FastAPI, Request, Header, HTTPException
import hmac, hashlib, logging, os, sys, traceback, json
from github import Github  # PyGithub
from Src.config import GITHUB_WEBHOOK_SECRET, GITHUB_TOKEN
from Src.agents.orchestrator import run_flow

logger = logging.getLogger("FastAPIWebhook")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = FastAPI()
gh = Github(GITHUB_TOKEN) if GITHUB_TOKEN else None


# -------------------
# Verify GitHub Signature
# -------------------
def verify_signature(body: bytes, signature: str):
    if not GITHUB_WEBHOOK_SECRET:
        return True
    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), msg=body, digestmod=hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


# -------------------
# Extract diffs reliably
# -------------------
def extract_diffs(files):
    diffs = {}
    for f in files:
        # Try the official PyGithub field first
        patch = getattr(f, "patch", None)

        # Fallback: sometimes patch only lives in raw_data
        if not patch:
            raw = getattr(f, "raw_data", {})
            patch = raw.get("patch")

        diffs[f.filename] = patch or "<<NO PATCH AVAILABLE>>"
    return diffs


# -------------------
# Routes
# -------------------
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

        if x_github_event == "pull_request":
            action = payload.get("action")
            if action in ("opened", "synchronize", "reopened", "edited"):
                pr = payload["pull_request"]
                owner = payload["repository"]["owner"]["login"]
                repo = payload["repository"]["name"]
                pr_number = pr["number"]

                repo_obj = gh.get_repo(f"{owner}/{repo}")
                pr_obj = repo_obj.get_pull(pr_number)
                files = list(pr_obj.get_files())
                diffs = extract_diffs(files)

                logger.info(
                    "📌 Handling PR %s/%s#%s (files=%d)",
                    owner,
                    repo,
                    pr_number,
                    len(diffs),
                )
                logger.info("📌 Incoming diffs:\n%s", json.dumps(diffs, indent=2))

                state = {"owner": owner, "repo": repo, "pr_number": pr_number, "diffs": diffs}

        elif x_github_event == "push":
            owner = payload["repository"]["owner"]["login"]
            repo = payload["repository"]["name"]
            head_sha = payload.get("after")

            repo_obj = gh.get_repo(f"{owner}/{repo}")
            commit = repo_obj.get_commit(head_sha)
            files = list(commit.files)
            diffs = extract_diffs(files)

            logger.info(
                "📌 Handling PUSH %s/%s @ %s (files=%d)",
                owner,
                repo,
                head_sha,
                len(diffs),
            )
            logger.info("📌 Incoming diffs:\n%s", json.dumps(diffs, indent=2))

            state = {
                "owner": owner,
                "repo": repo,
                "commit_sha": head_sha,
                "pr_number": 0,
                "diffs": diffs,
            }

        if state:
            result = run_flow(state)
            logger.info("🔥 Full LangGraph output:\n%s", json.dumps(result, indent=2))
            return {"ok": True, "event": x_github_event, "result": result}

        logger.info("⚠️ Ignored event %s", x_github_event)
        return {"ok": True, "note": "ignored event"}

    except Exception as e:
        logger.exception("Webhook handler error: %s", e)
        return {"ok": False, "error": str(e), "trace": traceback.format_exc()}


