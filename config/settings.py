import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Ollama-first: default to Qwen (low-RAM, 1.9GB for 3b, 396MB for 0.5b) via OpenAI-compatible endpoint
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
    LLM_API_KEY = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", "ollama"))
    LLM_MODEL = os.getenv("LLM_MODEL", os.getenv("OPENAI_MODEL", "qwen2.5:3b"))
    OPENAI_API_BASE = os.getenv("OPENAI_API_BASE", "http://localhost:11434/v1")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ACTION_AUTO_THRESHOLD = float(os.getenv("ACTION_AUTO_THRESHOLD", "0.85"))
    ACTION_ANALYST_THRESHOLD = float(os.getenv("ACTION_ANALYST_THRESHOLD", "0.50"))
    GRAPH_STORE_TYPE = os.getenv("GRAPH_STORE_TYPE", "networkx")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

settings = Settings()
BASE_DIR = Path(__file__).resolve().parent.parent
