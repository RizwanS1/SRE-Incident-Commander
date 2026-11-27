from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from services.common import instrument_service, register_chaos_route

SERVICE = "payments"
app = FastAPI(title="Payments service", version="1.0.0")
instrument_service(app, SERVICE)
register_chaos_route(app)


class ChargeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: int = Field(gt=0, le=100_000)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def ready() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/charge")
async def charge(request: ChargeRequest) -> dict[str, object]:
    return {"payment_id": f"pay-{request.amount}", "status": "approved"}
