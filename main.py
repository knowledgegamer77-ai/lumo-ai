"""
========================================================================================
             LUMO AI | CENTRAL CLOUD PAYMENT, TELEMETRY & LICENSING ENTRYPOINT
========================================================================================
Production FastAPI ASGI entrypoint for Render.com (`uvicorn main:app`).
Delegates directly to the unified `payment_server.main` microservice with Postgres +
Safepay + PayFast + Ed25519 licensing + client telemetry + release manifest support.
========================================================================================
"""

from payment_server.main import app  # noqa: F401
