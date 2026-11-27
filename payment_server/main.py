"""
========================================================================================
            LUMO AI | AUTOMATED PAYMENT, TELEMETRY & ED25519 LICENSING SERVER
========================================================================================
Unified FastAPI cloud/local microservice executing:
- Authoritative PKR order valuation (Safepay & PayFast Pakistan)
- Hosted checkout sessions, auto-submit PayFast bridge, and return/cancel pages
- Cryptographic webhook verification (HMAC-SHA256 / PayFast validation_hash)
- Idempotent Ed25519 single-device license issuance and SMTP dispatch
- Persistent PostgreSQL (Render DATABASE_URL) + SQLite dual-backend storage
- Client telemetry heartbeats, remote kill switch, and auto-update version manifest
========================================================================================
"""

import html
import json
import logging
import os
import time
import urllib.parse
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from payment_server.config import (
    COMPANY_NAME,
    LUMO_ADMIN_API_KEY,
    PAYFAST_ENV,
    PKR_PRICES,
    PUBLIC_SERVER_URL,
    SAFEPAY_ENV,
    SUPPORT_EMAIL,
)
from payment_server.db import PaymentDBManager
from payment_server.mailer import send_license_email
from payment_server.providers import PROVIDERS, get_payment_provider
from payment_server.providers.payfast import PayFastPaymentProvider, parse_raw_payload
from payment_server.providers.safepay import SafepayPaymentProvider
from payment_server.signer import load_signing_key, sign_order_license

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("payment_server")

IS_PRODUCTION = os.getenv("ENVIRONMENT", "").lower() == "production" or bool(os.getenv("RENDER"))

app = FastAPI(
    title="Lumo AI Payment & Licensing Gateway Server",
    version="2.3.1",
    docs_url="/docs" if not IS_PRODUCTION else None,
    redoc_url=None,
)

ALLOWED_ORIGINS = [
    "http://localhost:8501",
    "http://127.0.0.1:8501",
    "https://lumo-ai-soyg.onrender.com",
    "https://lumo.pro",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Initialize database manager (uses PostgreSQL if DATABASE_URL is set, else SQLite)
db = PaymentDBManager()

# In-memory rate limiter for license polling: max 60 requests per 60 seconds per HWID/IP
_rate_limits = defaultdict(list)
RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0


def _check_rate_limit(key: str) -> bool:
    now = time.time()
    timestamps = _rate_limits[key]
    _rate_limits[key] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(_rate_limits[key]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    _rate_limits[key].append(now)
    return True


def _resolve_public_base_url(request: Request) -> str:
    env_url = os.getenv("PUBLIC_SERVER_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")

    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    fwd_proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    if fwd_host and "testserver" not in fwd_host:
        return f"{fwd_proto}://{fwd_host}".rstrip("/")

    base = str(request.base_url).rstrip("/")
    if base and "testserver" not in base:
        return base
    return PUBLIC_SERVER_URL


def _verify_admin_access(request: Request) -> None:
    required_key = os.getenv("LUMO_ADMIN_API_KEY", LUMO_ADMIN_API_KEY).strip()
    if not required_key:
        return
    provided = (
        request.headers.get("x-admin-key")
        or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    )
    if provided != required_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin API key")


class CreateOrderRequest(BaseModel):
    plan: str
    cycle: str
    hwid: str
    email: str
    provider: Optional[str] = "safepay"


@app.get("/")
@app.get("/health")
def health_check():
    try:
        load_signing_key()
        signing_ready = True
    except Exception:
        signing_ready = False

    return {
        "status": "ok",
        "online": True,
        "service": "Lumo AI Payment, Telemetry & Licensing Backend",
        "version": "2.3.1",
        "currency": "PKR",
        "db_backend": getattr(db, "backend", "sqlite"),
        "database_configured": getattr(db, "backend", "sqlite") == "postgres",
        "signing_key_configured": signing_ready,
        "safepay_configured": SafepayPaymentProvider().is_configured(),
        "payfast_configured": PayFastPaymentProvider().is_configured(),
        "providers": sorted(PROVIDERS.keys()),
        "safepay_env": os.getenv("SAFEPAY_ENV", SAFEPAY_ENV),
        "payfast_env": os.getenv("PAYFAST_ENV", PAYFAST_ENV),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.post("/orders", status_code=status.HTTP_201_CREATED)
def create_order(req: CreateOrderRequest, request: Request):
    """
    Creates an authoritative payment order.
    Expected PKR amount is strictly calculated from the server-side price matrix.
    """
    clean_plan = req.plan.lower().strip()
    clean_cycle = req.cycle.lower().strip()
    clean_hwid = req.hwid.strip()
    clean_email = req.email.strip().lower()
    clean_provider = (req.provider or "safepay").lower().strip()

    if not clean_hwid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid hardware identifier (HWID) is required.",
        )

    if (clean_plan, clean_cycle) not in PKR_PRICES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan or billing cycle. Valid combinations: {list(PKR_PRICES.keys())}",
        )

    try:
        adapter = get_payment_provider(clean_provider)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    expected_amount = PKR_PRICES[(clean_plan, clean_cycle)]
    currency = "PKR"
    order_id = f"LUMO-ORD-{uuid.uuid4().hex[:8].upper()}"

    order_record = db.create_order(
        order_id=order_id,
        plan=clean_plan,
        cycle=clean_cycle,
        expected_amount=expected_amount,
        currency=currency,
        hwid=clean_hwid,
        email=clean_email,
        status="PENDING",
        provider=clean_provider,
    )

    public_base = _resolve_public_base_url(request)
    try:
        details = adapter.create_checkout_details(
            order_id=order_id,
            amount_pkr=expected_amount,
            email=clean_email,
            plan=clean_plan,
            cycle=clean_cycle,
            public_base_url=public_base,
        )
        checkout_url = str(details["checkout_url"])
        tracker = str(details.get("tracker") or "")
    except Exception as e:
        db.update_order_status(order_id, "FAILED")
        logger.error(f"Gateway checkout creation failed for provider '{clean_provider}', order {order_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Payment gateway unavailable ({clean_provider}): {e}",
        )

    db.update_order_gateway(order_id, gateway_tracker=tracker or None, checkout_url=checkout_url)

    return {
        "order_id": order_id,
        "checkout_url": checkout_url,
        "expected_amount": expected_amount,
        "currency": currency,
        "provider": clean_provider,
        "tracker": tracker,
        "status": "PENDING",
        "created_at": order_record["created_at"],
    }


@app.get("/payfast/checkout/{order_id}", response_class=HTMLResponse)
def payfast_checkout_bridge(order_id: str, request: Request):
    """
    Renders an auto-submitting POST form targeting PayFast PostTransaction
    with the order's ACCESS_TOKEN so browsers/desktop clients open a single URL.
    """
    order = db.get_order(order_id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    if order["status"] == "COMPLETED":
        safe_id = html.escape(order_id)
        return HTMLResponse(
            f"<html><body style='font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:40px;text-align:center'>"
            f"<h2>Order {safe_id} is already paid</h2>"
            f"<p>Please return to the {html.escape(COMPANY_NAME)} desktop app.</p></body></html>"
        )

    public_base = _resolve_public_base_url(request)
    pf_provider = PayFastPaymentProvider(public_base_url=public_base)
    try:
        form_html = pf_provider.build_post_form_html(
            order=order,
            access_token=order.get("gateway_tracker"),
            public_base_url=public_base,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to initialize PayFast checkout form: {e}",
        )
    return HTMLResponse(content=form_html)


@app.get("/checkout", response_class=HTMLResponse)
def hosted_checkout_page(
    plan: str = "pro",
    cycle: str = "monthly",
    hwid: str = "",
    email: str = "",
):
    """Hosted web checkout selector for Safepay & PayFast local PKR + cards."""
    prices_json = json.dumps(
        {f"{k[0]}|{k[1]}": v for k, v in PKR_PRICES.items()}
    )
    plan_ids = list(dict.fromkeys(k[0] for k in PKR_PRICES.keys()))
    clean_req_plan = (plan or "").lower().strip()
    if clean_req_plan not in plan_ids:
        clean_req_plan = plan_ids[0] if plan_ids else "pro"
    plan_options_html = "\n      ".join(
        f'<option value="{html.escape(pid, quote=True)}" {"selected" if clean_req_plan == pid else ""}>{html.escape(pid.title())}</option>'
        for pid in plan_ids
    )
    safe_cycle = html.escape(cycle if cycle in ("monthly", "yearly") else "monthly")
    safe_hwid = html.escape(hwid, quote=True)
    safe_email = html.escape(email, quote=True)
    safe_company = html.escape(COMPANY_NAME)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{safe_company} - Subscription Checkout (PKR)</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #f8fafc; margin: 0; padding: 32px 16px; display: flex; justify-content: center; }}
    .wrap {{ width: 100%; max-width: 480px; background: #111827; border: 1px solid #1f2937; border-radius: 16px; padding: 28px; box-shadow: 0 24px 60px rgba(0,0,0,0.45); }}
    h1 {{ margin: 0 0 6px; font-size: 22px; }}
    .sub {{ color: #94a3b8; font-size: 13px; margin-bottom: 22px; }}
    label {{ display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin: 14px 0 6px; }}
    input, select {{ width: 100%; box-sizing: border-box; background: #0f172a; color: #f8fafc; border: 1px solid #334155; border-radius: 8px; padding: 10px 12px; font-size: 14px; }}
    .price-box {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 14px; margin-top: 18px; display: flex; justify-content: space-between; align-items: center; }}
    .price-val {{ font-size: 20px; font-weight: 700; color: #34d399; }}
    button {{ width: 100%; margin-top: 18px; background: #10b981; color: #052e16; font-weight: 700; border: 0; border-radius: 10px; padding: 13px; font-size: 15px; cursor: pointer; }}
    button:disabled {{ opacity: 0.6; cursor: wait; }}
    .err {{ color: #fca5a5; font-size: 13px; margin-top: 12px; display: none; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{safe_company} Upgrade</h1>
    <div class="sub">Instant single-device license activation via Safepay or PayFast (PKR)</div>
    <label for="plan">Plan</label>
    <select id="plan">
      {plan_options_html}
    </select>
    <label for="cycle">Billing Cycle</label>
    <select id="cycle">
      <option value="monthly" {"selected" if safe_cycle == "monthly" else ""}>Monthly (30 Days)</option>
      <option value="yearly" {"selected" if safe_cycle == "yearly" else ""}>Yearly (365 Days)</option>
    </select>
    <label for="provider">Payment Method</label>
    <select id="provider">
      <option value="safepay">Safepay (Visa / Mastercard / SadaPay / NayaPay / Bank)</option>
      <option value="payfast">PayFast Pakistan (Cards / Bank Account / Raast / Wallets)</option>
    </select>
    <label for="email">License Delivery Email</label>
    <input id="email" type="email" placeholder="you@company.com" value="{safe_email}" required />
    <label for="hwid">Device Hardware ID (from Lumo AI Desktop App)</label>
    <input id="hwid" type="text" placeholder="Paste your HWID from Plans & Billing" value="{safe_hwid}" required />
    <div class="price-box">
      <span>Total Payable</span>
      <span class="price-val" id="total_pkr">Rs. 0 PKR</span>
    </div>
    <button id="pay_btn" type="button">Proceed to Secure Payment</button>
    <div id="err_box" class="err"></div>
  </div>
  <script>
    const prices = {prices_json};
    const planEl = document.getElementById("plan");
    const cycleEl = document.getElementById("cycle");
    const totalEl = document.getElementById("total_pkr");
    const errEl = document.getElementById("err_box");
    const btn = document.getElementById("pay_btn");
    function refreshPrice() {{
      const p = prices[planEl.value + "|" + cycleEl.value] || 0;
      totalEl.textContent = "Rs. " + p.toLocaleString() + " PKR";
    }}
    planEl.addEventListener("change", refreshPrice);
    cycleEl.addEventListener("change", refreshPrice);
    refreshPrice();
    btn.addEventListener("click", async () => {{
      errEl.style.display = "none";
      const email = document.getElementById("email").value.trim();
      const hwid = document.getElementById("hwid").value.trim();
      if (!email || !hwid) {{
        errEl.textContent = "Please enter both your email address and Device HWID.";
        errEl.style.display = "block";
        return;
      }}
      btn.disabled = true;
      btn.textContent = "Connecting to Gateway...";
      try {{
        const res = await fetch("/orders", {{
          method: "POST",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{
            plan: planEl.value,
            cycle: cycleEl.value,
            provider: document.getElementById("provider").value,
            email,
            hwid
          }})
        }});
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Order creation failed");
        window.location.href = data.checkout_url;
      }} catch (e) {{
        errEl.textContent = e.message;
        errEl.style.display = "block";
        btn.disabled = false;
        btn.textContent = "Proceed to Secure Payment";
      }}
    }});
  </script>
</body>
</html>"""
    return HTMLResponse(content=page)


def _process_verified_event(
    adapter,
    headers: Dict[str, str],
    raw_body: bytes,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    event = adapter.parse_webhook_event(headers, payload)

    if not event.event_id:
        event.event_id = f"auto_evt_{uuid.uuid4().hex[:12]}"

    if db.is_event_processed(event.event_id):
        logger.info(f"Idempotency: Webhook event '{event.event_id}' already processed. Skipping duplicate.")
        return {"status": "already_processed", "event_id": event.event_id}

    db.record_webhook_event(event.event_id)

    order = db.get_order(event.order_id) if event.order_id else None
    if not order and getattr(event, "tracker", ""):
        order = db.get_order_by_tracker(event.tracker)

    if not order:
        logger.warning(f"Webhook received for unknown order: '{event.order_id}' (tracker='{getattr(event, 'tracker', '')}')")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    if event.is_refund:
        db.update_order_status(order["order_id"], "REFUNDED")
        db.revoke_license_by_order(order["order_id"])
        logger.info(f"Order #{order['order_id']} set to REFUNDED; license revoked.")
        return {"status": "REFUNDED", "order_id": order["order_id"]}

    if not event.is_paid:
        logger.info(f"Non-success event status '{event.status}' for order {order['order_id']}.")
        return {"status": "ignored", "reason": f"Event status is {event.status}"}

    if order["status"] != "PENDING":
        logger.info(f"Order #{order['order_id']} is already {order['status']}. No action needed.")
        return {"status": "already_settled", "order_status": order["status"]}

    if event.currency.upper() != order["currency"].upper():
        db.update_order_status(order["order_id"], "FAILED")
        logger.error(
            f"Currency mismatch for order {order['order_id']}: expected {order['currency']}, got {event.currency}."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Currency mismatch: expected {order['currency']}, got {event.currency}",
        )

    if abs(float(event.amount) - float(order["expected_amount"])) > 0.01:
        db.update_order_status(order["order_id"], "FAILED")
        logger.error(
            f"Underpaid/Wrong amount for order {order['order_id']}: expected Rs. {order['expected_amount']}, received Rs. {event.amount}."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Amount mismatch: expected {order['expected_amount']} PKR, got {event.amount} PKR",
        )

    try:
        serial_id, license_token = sign_order_license(order)
    except Exception as e:
        logger.error(f"Failed to sign Ed25519 license for order {order['order_id']}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cryptographic license issuance failure: {e}",
        )

    db.store_license(serial_id, order["order_id"], license_token)
    db.update_order_status(order["order_id"], "COMPLETED")
    logger.info(f"Order #{order['order_id']} COMPLETED. License #{serial_id} issued.")

    send_license_email(
        to_email=order["email"],
        order_id=order["order_id"],
        plan=order["plan"],
        cycle=order["cycle"],
        token=license_token,
    )

    return {
        "status": "COMPLETED",
        "order_id": order["order_id"],
        "serial_id": serial_id,
        "token": license_token,
    }


@app.post("/webhook/{provider}")
@app.post("/api/v1/webhook/{provider}")
async def handle_payment_webhook(provider: str, request: Request):
    """
    Ingests and processes gateway payment webhooks (Safepay JSON & PayFast JSON/form IPN).
    """
    clean_provider = provider.lower().strip()
    try:
        adapter = get_payment_provider(clean_provider)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    raw_body = await request.body()
    headers = dict(request.headers)

    logger.info(f"Incoming webhook for provider '{clean_provider}'. Content-Length: {len(raw_body)} bytes.")

    is_valid, error_msg = adapter.verify_webhook(headers, raw_body)
    if not is_valid:
        logger.warning(f"Signature verification rejected for {clean_provider}: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Signature verification failed: {error_msg}",
        )

    content_type = headers.get("content-type", "").lower()
    raw_text = raw_body.decode("utf-8", errors="replace").strip()
    try:
        if raw_text.startswith("{") or "application/json" in content_type:
            payload = json.loads(raw_text)
        elif clean_provider == "payfast" or "application/x-www-form-urlencoded" in content_type:
            payload = parse_raw_payload(raw_body)
        else:
            payload = json.loads(raw_text)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid JSON body: {e}")

    return _process_verified_event(adapter, headers, raw_body, payload)


@app.get("/checkout/success", response_class=HTMLResponse)
def checkout_success_page(request: Request, order_id: str = "", provider: str = ""):
    """Landing page after customer completes Safepay or PayFast checkout."""
    params = dict(request.query_params)
    resolved_order_id = (order_id or params.get("basket_id") or params.get("BASKET_ID") or "").strip()

    # If PayFast redirected via GET with a signed validation_hash, attempt idempotent verification
    if (provider.lower() == "payfast" or "validation_hash" in params) and params.get("validation_hash"):
        pf = PayFastPaymentProvider()
        raw_qs = urllib.parse.urlencode(params).encode("utf-8")
        ok, _ = pf.verify_webhook({}, raw_qs)
        if ok:
            try:
                _process_verified_event(pf, {}, raw_qs, params)
            except Exception as e:
                logger.warning(f"Checkout redirect confirmation check skipped for {resolved_order_id}: {e}")

    order = db.get_order(resolved_order_id) if resolved_order_id else None
    order_status = order["status"] if order else "PENDING"
    is_done = order_status == "COMPLETED"
    headline = "Payment Confirmed" if is_done else "Processing Payment Confirmation"
    msg = (
        f"Your {COMPANY_NAME} license is now ready. Return to the desktop app and it will activate automatically."
        if is_done
        else f"Thank you. Return to your {COMPANY_NAME} desktop app — activation completes automatically once the gateway confirms settlement."
    )

    safe_id = html.escape(resolved_order_id or "Pending")
    safe_status = html.escape(order_status)
    safe_company = html.escape(COMPANY_NAME)
    safe_support = html.escape(SUPPORT_EMAIL)

    return HTMLResponse(
        f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_company} - {html.escape(headline)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0b1120; color:#f8fafc; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:16px; }}
  .card {{ max-width:460px; background:#111827; border:1px solid #1f2937; border-radius:16px; padding:32px; text-align:center; }}
  .badge {{ display:inline-block; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; background:#064e3b; color:#34d399; margin-bottom:14px; }}
  p {{ color:#94a3b8; font-size:14px; line-height:1.6; }}
</style></head>
<body><div class="card">
  <div class="badge">Order {safe_id} &middot; {safe_status}</div>
  <h2>{html.escape(headline)}</h2>
  <p>{html.escape(msg)}</p>
  <p style="font-size:12px;margin-top:20px;">Need help? {safe_support}</p>
</div></body></html>"""
    )


@app.get("/checkout/cancel", response_class=HTMLResponse)
def checkout_cancel_page(order_id: str = "", provider: str = ""):
    safe_id = html.escape(order_id or "-")
    safe_company = html.escape(COMPANY_NAME)
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_company} - Checkout Cancelled</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0b1120; color:#f8fafc; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:16px; }}
  .card {{ max-width:460px; background:#111827; border:1px solid #1f2937; border-radius:16px; padding:32px; text-align:center; }}
  p {{ color:#94a3b8; font-size:14px; line-height:1.6; }}
</style></head>
<body><div class="card">
  <h2>Payment Cancelled</h2>
  <p>Order <b>{safe_id}</b> was not completed. No license charge was finalized.</p>
  <p>You can close this window and retry anytime from {safe_company} &rarr; Plans &amp; Billing.</p>
</div></body></html>"""
    )


@app.get("/orders/{order_id}/license")
def get_order_license(
    order_id: str,
    hwid: str = Query(..., description="Client device hardware identifier"),
    request: Request = None,
):
    """
    Returns the signed Ed25519 license token only if COMPLETED and HWID matches. Rate-limited.
    """
    rate_key = f"{hwid}:{request.client.host if request and request.client else 'client'}"
    if not _check_rate_limit(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many polling requests. Rate limit is 60 requests per minute.",
        )

    order = db.get_order(order_id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    order_status = order["status"]

    if order_status == "PENDING":
        return {
            "order_id": order_id,
            "status": "PENDING",
            "message": "Payment pending confirmation from gateway.",
        }

    if order_status == "FAILED":
        return {
            "order_id": order_id,
            "status": "FAILED",
            "message": "Payment failed or was cancelled.",
        }

    if order_status == "REFUNDED":
        return {
            "order_id": order_id,
            "status": "REFUNDED",
            "message": "Order was refunded and access has been revoked.",
        }

    if order_status != "COMPLETED":
        return {"order_id": order_id, "status": order_status}

    if order["hwid"].strip() != hwid.strip():
        logger.warning(
            f"HWID mismatch on order {order_id}: order locked to '{order['hwid']}', requested by '{hwid}'."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Hardware ID mismatch: this license is locked to another machine.",
        )

    lic = db.get_license_by_order(order_id)
    if not lic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License record not found for completed order.",
        )

    if lic.get("revoked", 0):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License has been revoked.",
        )

    return {
        "order_id": order_id,
        "status": "COMPLETED",
        "serial_id": lic["serial_id"],
        "token": lic["token"],
        "issued_at": lic["issued_at"],
    }


# ========================================================================================
#            CLIENT TELEMETRY, LICENSE REDEMPTION & 1-CLICK REMOTE KILL SWITCH
# ========================================================================================

class ClientHeartbeatRequest(BaseModel):
    hwid: Optional[str] = None
    hwid_hash: Optional[str] = ""
    license_id: Optional[str] = ""
    app_version: Optional[str] = "2.3.0"
    machine_name: str = "Desktop-Client"
    os_platform: str = "Windows"
    username: str = "Guest"
    user_email: str = ""
    plan_tier: str = "Starter"
    activation_key: str = ""
    ip_address: str = "Not Collected"
    location: str = "Not Collected"
    leads_generated: int = 0


class BlockDeviceRequest(BaseModel):
    target_id: str
    target_type: str = "HWID"
    reason: str = "Revoked by Administrator"


@app.post("/api/v1/telemetry/heartbeat")
async def record_heartbeat(payload: ClientHeartbeatRequest):
    resolved_hwid = (payload.hwid or payload.hwid_hash or "").strip()
    if not resolved_hwid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Either hwid or hwid_hash must be provided.",
        )
    res = db.record_client_heartbeat(
        hwid=resolved_hwid,
        machine_name=payload.machine_name,
        os_platform=payload.os_platform,
        username=payload.username,
        user_email=payload.user_email,
        plan_tier=payload.plan_tier,
        activation_key=payload.activation_key or payload.license_id or "",
        ip_address=payload.ip_address,
        location=payload.location,
        leads_generated=payload.leads_generated,
        app_version=payload.app_version or "",
    )
    return {"status": "ok", "telemetry": res}


class LicenseRedeemRequest(BaseModel):
    license_id: str
    hwid: str
    username: str = ""
    client_name: str = ""
    tier: str = "Pro"
    duration_days: int = 30


@app.post("/api/v1/license/redeem")
async def redeem_license_endpoint(payload: LicenseRedeemRequest):
    """Single-use cross-device activation lock registry."""
    existing = db.get_license_redemption(payload.license_id)
    if existing:
        if existing.get("hwid") and existing.get("hwid") != payload.hwid:
            return {
                "success": False,
                "message": f"Single-Use Activation Error: License '{payload.license_id}' is already bound to another machine.",
            }
        return {
            "success": True,
            "message": "License verified for this machine.",
            "data": existing,
        }

    rec = db.record_license_redemption(
        serial_id=payload.license_id,
        hwid=payload.hwid,
        username=payload.username,
        client_name=payload.client_name,
        plan_tier=payload.tier,
        duration_days=payload.duration_days,
    )
    return {
        "success": True,
        "message": "License redeemed successfully.",
        "data": rec,
    }


@app.get("/api/v1/telemetry/check")
async def check_telemetry_auth(hwid: str, email: str = ""):
    allowed, message = db.check_device_authorization(hwid=hwid, user_email=email)
    return {"allowed": allowed, "message": message}


@app.get("/api/v1/admin/devices")
async def list_admin_devices(request: Request):
    _verify_admin_access(request)
    devices = db.get_all_client_devices()
    return {"count": len(devices), "devices": devices}


@app.post("/api/v1/admin/devices/block")
async def admin_block_device_api(payload: BlockDeviceRequest, request: Request):
    _verify_admin_access(request)
    ok = db.block_device(target_id=payload.target_id, target_type=payload.target_type, reason=payload.reason)
    return {"status": "ok", "blocked": ok, "target_id": payload.target_id}


@app.post("/api/v1/admin/devices/unblock")
async def admin_unblock_device_api(payload: BlockDeviceRequest, request: Request):
    _verify_admin_access(request)
    ok = db.unblock_device(target_id=payload.target_id)
    return {"status": "ok", "unblocked": ok, "target_id": payload.target_id}


@app.get("/version")
@app.get("/api/v1/version")
async def get_latest_version_manifest():
    """Returns the latest official release manifest for client in-app auto-updating."""
    return {
        "version": os.getenv("LUMO_LATEST_VERSION", "2.3.0"),
        "name": os.getenv("LUMO_RELEASE_NAME", "Lumo AI v2.3.0 - Pro Desktop Edition"),
        "release_date": os.getenv("LUMO_RELEASE_DATE", "2026-11-26"),
        "changelog": [
            "Graphical Windows Setup Installer (Inno Setup) with standard-user installation and automatic license/database preservation on upgrades.",
            "SHA-256 verified silent in-app auto-updater with zero console windows (CREATE_NO_WINDOW).",
            "Clean UI across all screens, improved WhatsApp mobile validation, and full 200-country mapping.",
            "Automated local PKR & Card checkout supporting Safepay and PayFast Pakistan.",
        ],
        "download_url": os.getenv(
            "LUMO_DOWNLOAD_URL",
            "https://github.com/knowledgegamer77-ai/lumo-ai/releases/latest/download/Lumo_AI_Setup_2.3.0.exe",
        ),
        "sha256": os.getenv(
            "LUMO_INSTALLER_SHA256",
            "c5e2dea66b83017c5af405be37a0c6777c1f342116e4cef5e2a4b42678406e6a",
        ),
        "mandatory": False,
        "min_supported_version": "2.0.0",
    }
