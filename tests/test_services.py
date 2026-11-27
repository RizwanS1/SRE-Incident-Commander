from fastapi.testclient import TestClient

from services.inventory.app import app as inventory_app
from services.orders import app as orders_module


def test_chaos_error_is_bounded_and_can_be_disabled() -> None:
    client = TestClient(inventory_app)

    enabled = client.post("/chaos", json={"mode": "error", "ttl_seconds": 30})
    failed_request = client.post("/reserve", json={"item_id": "widget", "quantity": 1})
    disabled = client.post("/chaos", json={"mode": "off"})
    recovered_request = client.post("/reserve", json={"item_id": "widget", "quantity": 1})

    assert enabled.status_code == 200
    assert failed_request.status_code == 503
    assert disabled.status_code == 200
    assert recovered_request.status_code == 200


def test_orders_calls_payments_then_inventory(monkeypatch) -> None:
    calls: list[str] = []

    class FakeResponse:
        def __init__(self, value: str) -> None:
            self.value = value

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"result": self.value}

    def fake_post(url: str, json: dict[str, object], timeout: int) -> FakeResponse:
        calls.append(url)
        return FakeResponse(url.rsplit("/", 1)[-1])

    monkeypatch.setattr(orders_module.requests, "post", fake_post)
    client = TestClient(orders_module.app)

    response = client.post("/orders", json={"item_id": "widget", "quantity": 2})

    assert response.status_code == 200
    assert calls == [
        "http://payments:8000/charge",
        "http://inventory:8000/reserve",
    ]
