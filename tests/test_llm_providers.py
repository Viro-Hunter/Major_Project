"""API-key auto-detection, credential checks and model choice (all HTTP mocked)."""
import httpx
import pytest
from fastapi.testclient import TestClient

from llm import providers, runtime
from llm.providers import check_credentials, detect_provider, recommend, score_free_model, ModelInfo

OR_KEY = "sk-or-v1-" + "a1" * 32
MODELS = {"data": [
    {"id": "meta-llama/llama-3.3-70b-instruct:free", "name": "Llama 3.3 70B (free)", "context_length": 131072, "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "google/gemma-3-4b-it:free", "name": "Gemma 3 4B (free)", "context_length": 32768, "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "deepseek/deepseek-r1:free", "name": "R1 (free)", "context_length": 163840, "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "qwen/qwen2.5-vl-72b-instruct:free", "name": "Qwen VL (free)", "context_length": 32768, "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "anthropic/claude-3.5-sonnet", "name": "Claude 3.5 Sonnet", "context_length": 200000, "pricing": {"prompt": "0.000003", "completion": "0.000015"}},
    {"id": "anthropic/claude-sonnet-4.5", "name": "Claude Sonnet 4.5", "context_length": 200000, "pricing": {"prompt": "0.000003", "completion": "0.000015"}},
    {"id": "openai/gpt-4o-mini", "name": "GPT-4o mini", "context_length": 128000, "pricing": {"prompt": "0.00000015", "completion": "0.0000006"}},
    {"id": "openrouter/auto", "name": "Auto router", "pricing": {"prompt": "-1", "completion": "-1"}},
]}


def fake_openrouter(key_data, credits=None, status=200, models=MODELS):
    def get(url, headers):
        assert headers["Authorization"] == f"Bearer {OR_KEY}"
        req = httpx.Request("GET", url)
        if url.endswith("/key"):
            return httpx.Response(status, json={"data": key_data}, request=req)
        if url.endswith("/credits"):
            return httpx.Response(200 if credits else 403, json={"data": credits or {}}, request=req)
        if url.endswith("/models"):
            return httpx.Response(200, json=models, request=req)
        return httpx.Response(404, request=req)
    return get


@pytest.fixture(autouse=True)
def _reset():
    yield
    providers.set_http_get(None)
    runtime.clear()


@pytest.mark.parametrize("key,expected", [
    (OR_KEY, "openrouter"), ("sk-ant-api03-" + "x" * 40, "anthropic"), ("sk-proj-" + "x" * 40, "openai"),
    ("sk-" + "A" * 48, "openai"), ("gsk_" + "x" * 40, "groq"), ("AIza" + "x" * 35, "gemini"),
    ("xai-" + "x" * 40, "xai"), ("hello", None), ("", None), ("sk-or-v1 abc", None),
])
def test_detect_provider(key, expected):
    assert detect_provider(key)["provider"] == expected


def test_free_scoring_prefers_large_instruct_over_tiny_thinking_or_vision():
    m = {d["id"]: ModelInfo(d["id"], d["name"], True, d.get("context_length")) for d in MODELS["data"][:4]}
    scores = {k: score_free_model(v) for k, v in m.items()}
    assert max(scores, key=scores.get) == "meta-llama/llama-3.3-70b-instruct:free"
    assert scores["qwen/qwen2.5-vl-72b-instruct:free"] < 0  # vision model penalised


def test_openrouter_free_tier_shows_only_free_and_picks_best():
    providers.set_http_get(fake_openrouter({"is_free_tier": True, "limit": None, "limit_remaining": None, "usage": 0}))
    r = check_credentials(OR_KEY)
    assert r["valid"] and r["tier"] == "free" and not r["can_pay"]
    assert all(m["free"] for m in r["models"])
    assert r["recommended"] == "meta-llama/llama-3.3-70b-instruct:free"
    assert r["models"][0]["id"] == r["recommended"]          # recommended first in dropdown
    assert "openrouter/auto" not in {m["id"] for m in r["models"]}  # variable-price router skipped


def test_openrouter_paid_with_credit_recommends_newest_sonnet_and_lists_all():
    providers.set_http_get(fake_openrouter({"is_free_tier": False, "limit": None, "limit_remaining": None, "usage": 1.2},
                                           credits={"total_credits": 10, "total_usage": 1.2}))
    r = check_credentials(OR_KEY)
    assert r["tier"] == "paid" and r["recommended"] == "anthropic/claude-sonnet-4.5"
    assert r["credits"]["remaining_usd"] == pytest.approx(8.8)
    ids = {m["id"] for m in r["models"]}
    assert "openai/gpt-4o-mini" in ids and "meta-llama/llama-3.3-70b-instruct:free" in ids
    sonnet = next(m for m in r["models"] if m["id"] == "anthropic/claude-sonnet-4.5")
    assert sonnet["est_cost_per_verdict"] == pytest.approx(3000 * 3e-6 + 400 * 15e-6)


def test_openrouter_paid_account_out_of_credit_falls_back_to_free():
    providers.set_http_get(fake_openrouter({"is_free_tier": False, "limit": 5, "limit_remaining": 0, "usage": 5},
                                           credits={"total_credits": 5, "total_usage": 5}))
    r = check_credentials(OR_KEY)
    assert r["tier"] == "free" and r["recommended"].endswith(":free")


def test_invalid_key_and_network_failure_are_reported_not_raised():
    providers.set_http_get(fake_openrouter({}, status=401))
    r = check_credentials(OR_KEY)
    assert not r["valid"] and "rejected" in r["message"]

    def offline(url, headers):
        raise httpx.ConnectError("no route", request=httpx.Request("GET", url))
    providers.set_http_get(offline)
    r = check_credentials(OR_KEY)
    assert not r["valid"] and "Could not reach OpenRouter" in r["message"]


def test_recommend_handles_empty_catalog():
    assert recommend([], can_pay=True) is None


def test_api_connect_select_status_disconnect_and_key_never_echoed(monkeypatch):
    from api.main import app
    from llm.client import LLMClient

    providers.set_http_get(fake_openrouter({"is_free_tier": True, "limit": None, "limit_remaining": None}))
    c = TestClient(app)
    assert c.post("/llm/detect", json={"api_key": OR_KEY}).json()["provider"] == "openrouter"
    r = c.post("/llm/connect", json={"api_key": OR_KEY})
    assert r.json()["active_model"] == "meta-llama/llama-3.3-70b-instruct:free"
    assert OR_KEY not in r.text

    # free tier cannot select a paid model
    assert c.post("/llm/select", json={"model": "anthropic/claude-sonnet-4.5"}).status_code == 400
    s = c.post("/llm/select", json={"model": "google/gemma-3-4b-it:free"})
    assert s.json()["model"] == "google/gemma-3-4b-it:free" and OR_KEY not in s.text

    # the reasoning engine's client now uses the dashboard connection
    client = LLMClient()
    assert (client.provider, client.model, client.source) == ("openrouter", "google/gemma-3-4b-it:free", "dashboard")
    assert client.base_url == "https://openrouter.ai/api/v1"

    st = c.post("/llm/disconnect").json()
    assert st["source"] == "env"
    assert c.post("/llm/select", json={"model": "x"}).status_code == 409


def test_env_openrouter_auto_model(monkeypatch):
    from llm.client import LLMClient

    providers.set_http_get(fake_openrouter({"is_free_tier": True}))
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", OR_KEY)
    monkeypatch.setenv("OPENROUTER_MODEL", "auto")
    LLMClient._auto_cache.clear()
    assert LLMClient().model == "meta-llama/llama-3.3-70b-instruct:free"
