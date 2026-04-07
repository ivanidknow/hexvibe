from __future__ import annotations

import os

# Public open-source defaults for a self-hosted OpenAI-compatible local endpoint.
LOCAL_LLM_PROVIDER = os.getenv("LOCAL_LLM_PROVIDER", "local").strip().lower() or "local"
HEXVIBE_LLM_PROVIDER = os.getenv("HEXVIBE_LLM_PROVIDER", "anthropic").strip().lower() or "anthropic"

LOCAL_LLM_API_BASE = os.getenv("LOCAL_LLM_API_BASE", "http://localhost:8000/v1").strip()
LOCAL_LLM_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "").strip()
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "strong").strip() or "strong"
LOCAL_LLM_MODEL_STRONG = os.getenv("LOCAL_LLM_MODEL_STRONG", "strong").strip() or "strong"
LOCAL_LLM_MODEL_CODER = os.getenv("LOCAL_LLM_MODEL_CODER", "coder").strip() or "coder"
LOCAL_LLM_MODEL_FAST = os.getenv("LOCAL_LLM_MODEL_FAST", "fast").strip() or "fast"
