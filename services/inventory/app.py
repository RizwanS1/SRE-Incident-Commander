from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from services.common import instrument_service, register_chaos_route

SERVICE = "inventory"
app = FastAPI(title="Inventory service", version="1.0.0")
instrument_service(app, SERVICE)
register_chaos_route(app)


class ReservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(min_length=1, max_length=80)
    quantity: int = Field(ge=1, le=100)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def ready() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/reserve")
async def reserve(request: ReservationRequest) -> dict[str, object]:
    return {
        "reservation_id": f"reservation-{request.item_id}",
        "quantity": request.quantity,
        "status": "reserved",
    }
