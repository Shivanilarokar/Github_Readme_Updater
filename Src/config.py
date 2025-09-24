# Src/config.py
from dotenv import load_dotenv
import os

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")               # PAT with repo access
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
DEFAULT_BRANCH = os.getenv("DEFAULT_BRANCH", "main")
AUTO_MERGE = os.getenv("AUTO_MERGE", "false").lower() in ("1","true")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_FILES = int(os.getenv("MAX_FILES", "200"))
MAX_ADDED_LINES = int(os.getenv("MAX_ADDED_LINES", "5000"))

