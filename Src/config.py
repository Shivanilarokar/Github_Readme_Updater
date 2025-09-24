from dotenv import load_dotenv
import os

# Load from .env when running locally
load_dotenv()

# --- GitHub ---
PAT_github = os.getenv("PAT_github")               # PAT with repo access
DEFAULT_BRANCH = os.getenv("DEFAULT_BRANCH", "main")
AUTO_MERGE = os.getenv("AUTO_MERGE", "false").lower() in ("1", "true")

# --- OpenAI ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# --- Limits ---
MAX_FILES = int(os.getenv("MAX_FILES", "200"))
MAX_ADDED_LINES = int(os.getenv("MAX_ADDED_LINES", "5000"))
