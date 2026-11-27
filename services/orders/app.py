from __future__ import annotations

import os

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from services.common import instrument_service, register_chaos_route

SERVICE = "orders"
app = FastAPI(title="Orders service", version="1.0.0")
instrument_service(app, SERVICE)
register_chaos_route(app)


class OrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(min_length=1, max_length=80)
    quantity: int = Field(ge=1, le=100)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def ready() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/orders")
async def create_order(order: OrderRequest) -> dict[str, object]:
    payments_url = os.getenv("PAYMENTS_URL", "http://payments:8000")
    inventory_url = os.getenv("INVENTORY_URL", "http://inventory:8000")
    try:
        payment = requests.post(
            f"{payments_url}/charge",
            json={"amount": order.quantity * 10},
            timeout=3,
        )
        payment.raise_for_status()
        reservation = requests.post(
            f"{inventory_url}/reserve",
            json=order.model_dump(),
            timeout=3,
        )
        reservation.raise_for_status()
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail="A downstream service failed") from error
    return {
        "order_id": f"order-{order.item_id}",
        "payment": payment.json(),
        "reservation": reservation.json(),
    }
