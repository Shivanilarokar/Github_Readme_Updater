# src/main.py
from fastapi import FastAPI, Request, Header, HTTPException, Response
import hmac, hashlib, logging, os
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
import sys

# ----------------------------
# Config from env
# ----------------------------
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

# ----------------------------
# Logger setup
# ----------------------------
logger = logging.getLogger("ai-readme-updater")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ----------------------------
# FastAPI app
# ----------------------------
app = FastAPI()

# ----------------------------
# Metrics
# ----------------------------
WEBHOOK_COUNTER = Counter("webhook_events_total", "Total webhook events", ["event"])

# ----------------------------
# Helper functions
# ----------------------------
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

# ----------------------------
# Separate Handlers
# ----------------------------
def handle_pr_event(owner, repo, pr_number, action):
    logger.info("📌 Handling PR %s event for %s/%s#%s", action, owner, repo, pr_number)
    # TODO: enqueue job or call multi-agent system here

def handle_push_event(owner, repo, head_sha):
    logger.info("📌 Handling PUSH event for %s/%s @ %s", owner, repo, head_sha)
    # TODO: enqueue job or call multi-agent system here

# ----------------------------
# Routes
# ----------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/metrics")
async def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

@app.post("/webhook")
async def webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
):
    body = await request.body()
    verify_signature(body, x_hub_signature_256)
    payload = await request.json()

    # Count metric
    WEBHOOK_COUNTER.labels(event=x_github_event or "unknown").inc()

    # ---------------- PR Event ----------------
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action in ("opened", "synchronize", "edited", "reopened"):
            pr = payload["pull_request"]
            owner = payload["repository"]["owner"]["login"]
            repo = payload["repository"]["name"]
            pr_number = pr["number"]
            handle_pr_event(owner, repo, pr_number, action)
            return {"ok": True, "type": "pull_request", "action": action, "pr_number": pr_number}
        return {"ok": True, "note": "ignored PR action"}

    # ---------------- Push Event ----------------
    if x_github_event == "push":
        owner = payload["repository"]["owner"]["login"]
        repo = payload["repository"]["name"]
        head_sha = payload.get("after")
        handle_push_event(owner, repo, head_sha)
        return {"ok": True, "type": "push", "head_sha": head_sha}

    # ---------------- Other Events ----------------
    logger.info("⚠️ Unhandled event %s", x_github_event)
    return {"ok": True, "note": "unhandled event"}
