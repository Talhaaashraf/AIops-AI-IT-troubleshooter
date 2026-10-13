"""Process-wide paths and settings shared by the server modules."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# SQLite file for alerts, devices, sessions, tasks and learned cases (a volume path in Docker).
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", str(PROJECT_ROOT / "alerts.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
# Folder that holds the migrated base model and the self-improving AIops model.
MODELS_DIR = Path(os.getenv("SENTINEL_MODELS_DIR", str(PROJECT_ROOT / "models")))
