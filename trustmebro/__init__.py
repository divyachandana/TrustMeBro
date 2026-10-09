"""TrustMeBro: an immune system for AI-written code."""

import os as _os
from pathlib import Path as _Path

from dotenv import load_dotenv as _load_dotenv

# Keys and CLICKHOUSE_* settings can live in a .env in the project being protected.
_load_dotenv(_Path(_os.getenv("CLAUDE_PROJECT_DIR") or _Path.cwd()) / ".env")
