import pytest

from incident_commander.llm import OpenAICompatibleHypothesisProvider


def test_openai_compatible_provider_retries_malformed_schema_once(monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, content: str) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": self.content}}]}

    monkeypatch.setenv("LLM_API_KEY", "local-ollama")
    responses = iter(
        [
            FakeResponse('{"summary":"not the schema"}'),
            FakeResponse('{"hypotheses":[]}'),
        ]
    )
    calls: list[dict[str, object]] = []

    def fake_post(url: str, **kwargs: object) -> FakeResponse:
        assert url.endswith("/chat/completions")
        assert "json" in kwargs
        calls.append(kwargs)
        return next(responses)

    monkeypatch.setattr("incident_commander.llm.requests.post", fake_post)

    hypotheses = OpenAICompatibleHypothesisProvider().rank({}, [])

    assert hypotheses == []
    assert len(calls) == 2
    retry_body = calls[1]["json"]
    assert isinstance(retry_body, dict)
    retry_messages = retry_body["messages"]
    assert isinstance(retry_messages, list)
    assert "previous response" in retry_messages[-1]["content"]


def test_openai_compatible_provider_fails_after_invalid_retry(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": '{"summary":"not the schema"}'}}]}

    monkeypatch.setenv("LLM_API_KEY", "local-ollama")
    calls = 0

    def fake_post(url: str, **kwargs: object) -> FakeResponse:
        nonlocal calls
        calls += 1
        return FakeResponse()

    monkeypatch.setattr("incident_commander.llm.requests.post", fake_post)

    with pytest.raises(ValueError, match="after one correction attempt"):
        OpenAICompatibleHypothesisProvider().rank({}, [])

    assert calls == 2
