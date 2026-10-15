"""
Velbrix - Configuration
Loads settings from environment variables / .env file.
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # NVIDIA NIM (primary)
    nvidia_api_key: str = os.getenv("NVIDIA_API_KEY", "")
    nvidia_base_url: str = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    nvidia_model: str = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")

    # Groq (fallback 1)
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_base_url: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

    # Gemini (fallback 2)
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

    # App
    velbrix_port: int = int(os.getenv("VELBRIX_PORT", "8000"))
    velbrix_host: str = os.getenv("VELBRIX_HOST", "0.0.0.0")
    workspace_dir: str = os.getenv("VELBRIX_WORKSPACE_DIR", "/tmp/velbrix_workspaces")
    db_path: str = os.getenv("VELBRIX_DB_PATH", "velbrix.db")
    enable_model_consensus: bool = os.getenv("ENABLE_MODEL_CONSENSUS", "false").lower() == "true"

    @property
    def workspace_path(self) -> Path:
        p = Path(self.workspace_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path_full(self) -> Path:
        return BASE_DIR / self.db_path

    @property
    def demo_project_path(self) -> Path:
        return BASE_DIR / "demo" / "vibebank"


settings = Settings()
