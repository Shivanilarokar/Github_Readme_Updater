from dotenv import load_dotenv
import os

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
DEFAULT_BRANCH = os.getenv("DEFAULT_BRANCH", "main")
AUTO_MERGE = os.getenv("AUTO_MERGE", "false").lower() in ("1", "true")
