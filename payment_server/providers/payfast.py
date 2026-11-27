"""
========================================================================================
            LUMO AI | PAYFAST PAYMENT GATEWAY ADAPTER (PAKISTAN)
========================================================================================
Production-ready adapter for PayFast (APPS - Pakistan's SBP-licensed gateway).
Implements GetAccessToken token exchange, auto-submit PostTransaction HTML checkout,
and constant-time validation_hash + HMAC IPN verification.
========================================================================================
"""

import hashlib
import hmac
import html
import json
import logging
import os
import urllib.parse
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests

from payment_server.config import (
    COMPANY_NAME,
    PAYFAST_CANCEL_URL,
    PAYFAST_ENV,
    PAYFAST_IPN_URL,
    PAYFAST_MERCHANT_ID,
    PAYFAST_POST_URL,
    PAYFAST_REQUEST_TIMEOUT,
    PAYFAST_RETURN_URL,
    PAYFAST_SECURED_KEY,
    PAYFAST_TOKEN_URL,
    PUBLIC_SERVER_URL,
)
from payment_server.providers.base import BasePaymentProvider, WebhookEventData

logger = logging.getLogger("payment_server.payfast")

_MOCK_MERCHANT_ID = "10001"
_MOCK_SECURED_KEY = "test_payfast_secret_key"


def parse_raw_payload(raw_body: bytes) -> Dict[str, Any]:
    """Parses either JSON or application/x-www-form-urlencoded PayFast IPN body."""
    text = raw_body.decode("utf-8", errors="replace").strip()
    if not text:
        return {}
    if text.startswith("{"):
        return json.loads(text)
    parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
    return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}


class PayFastPaymentProvider(BasePaymentProvider):
    def __init__(
        self,
        merchant_id: Optional[str] = None,
        secured_key: Optional[str] = None,
        env: Optional[str] = None,
        token_url: Optional[str] = None,
        post_url: Optional[str] = None,
        public_base_url: Optional[str] = None,
    ):
        self.env = (env or os.getenv("PAYFAST_ENV") or PAYFAST_ENV).lower().strip()
        self.merchant_id = str(merchant_id or os.getenv("PAYFAST_MERCHANT_ID") or PAYFAST_MERCHANT_ID).strip()
        self.secured_key = str(secured_key or os.getenv("PAYFAST_SECURED_KEY") or PAYFAST_SECURED_KEY).strip()

        default_token_url = (
            "https://ipg.apps.net.pk/Ecommerce/api/Transaction/GetAccessToken"
            if self.env == "production"
            else "https://ipguat.apps.net.pk/Ecommerce/api/Transaction/GetAccessToken"
        )
        default_post_url = (
            "https://ipg.apps.net.pk/Ecommerce/api/Transaction/PostTransaction"
            if self.env == "production"
            else "https://ipguat.apps.net.pk/Ecommerce/api/Transaction/PostTransaction"
        )
        self.token_url = (token_url or os.getenv("PAYFAST_TOKEN_URL") or default_token_url or PAYFAST_TOKEN_URL).strip()
        self.post_url = (post_url or os.getenv("PAYFAST_POST_URL") or default_post_url or PAYFAST_POST_URL).strip()
        self.public_base_url = (public_base_url or os.getenv("PUBLIC_SERVER_URL") or PUBLIC_SERVER_URL).rstrip("/")

    def is_configured(self) -> bool:
        return bool(
            self.merchant_id
            and self.secured_key
            and not (self.merchant_id == _MOCK_MERCHANT_ID and self.secured_key == _MOCK_SECURED_KEY)
        )

    def fetch_access_token(self, order_id: str, amount_pkr: float) -> str:
        """
        Exchanges merchant credentials and order amount with PayFast GetAccessToken API
        to obtain a short-lived transaction ACCESS_TOKEN.
        """
        is_cloud_runtime = bool(os.getenv("RENDER") or os.getenv("ENVIRONMENT", "").lower() == "production")
        if not self.merchant_id or not self.secured_key:
            raise RuntimeError(
                "PayFast credentials are not configured (set PAYFAST_MERCHANT_ID and PAYFAST_SECURED_KEY)."
            )
        if self.merchant_id == _MOCK_MERCHANT_ID and self.secured_key == _MOCK_SECURED_KEY:
            if is_cloud_runtime or self.env == "production":
                raise RuntimeError(
                    "PayFast credentials are not configured (set PAYFAST_MERCHANT_ID and PAYFAST_SECURED_KEY)."
                )
            return f"PF_MOCK_TOKEN_{order_id}"

        payload = {
            "MERCHANT_ID": self.merchant_id,
            "SECURED_KEY": self.secured_key,
            "TXNAMT": f"{float(amount_pkr):.2f}",
            "BASKET_ID": order_id,
            "CURRENCY_CODE": "PKR",
        }
        resp = requests.post(
            self.token_url,
            data=payload,
            timeout=PAYFAST_REQUEST_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"PayFast GetAccessToken failed ({resp.status_code}): {resp.text[:300]}"
            )
        data = resp.json()
        token = str(
            data.get("ACCESS_TOKEN")
            or data.get("access_token")
            or (data.get("data") or {}).get("ACCESS_TOKEN")
            or data.get("token")
            or ""
        ).strip()
        if not token:
            raise RuntimeError(f"PayFast GetAccessToken response missing ACCESS_TOKEN: {data}")
        return token

    def create_checkout_details(
        self,
        order_id: str,
        amount_pkr: int,
        email: str,
        plan: str,
        cycle: str,
        public_base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        base_pub = (public_base_url or self.public_base_url or PUBLIC_SERVER_URL).rstrip("/")
        access_token = self.fetch_access_token(order_id=order_id, amount_pkr=float(amount_pkr))
        checkout_url = f"{base_pub}/payfast/checkout/{urllib.parse.quote(order_id)}"
        logger.info(f"Created PayFast checkout session for order {order_id}: {checkout_url}")
        return {
            "checkout_url": checkout_url,
            "tracker": access_token,
        }

    def create_checkout_session(
        self,
        order_id: str,
        amount_pkr: int,
        email: str,
        plan: str,
        cycle: str,
    ) -> str:
        details = self.create_checkout_details(
            order_id=order_id,
            amount_pkr=amount_pkr,
            email=email,
            plan=plan,
            cycle=cycle,
        )
        return str(details["checkout_url"])

    def build_post_form_html(
        self,
        order: Dict[str, Any],
        access_token: Optional[str] = None,
        public_base_url: Optional[str] = None,
    ) -> str:
        """
        Generates an auto-submitting POST HTML form to redirect the customer browser to
        PayFast PostTransaction with a valid ACCESS_TOKEN.
        """
        base_pub = (public_base_url or self.public_base_url or PUBLIC_SERVER_URL).rstrip("/")
        order_id = str(order["order_id"])
        amount_val = float(order["expected_amount"])
        token = (access_token or order.get("gateway_tracker") or "").strip()
        if not token:
            token = self.fetch_access_token(order_id=order_id, amount_pkr=amount_val)

        order_date = str(order.get("created_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        signature = hashlib.sha256(
            f"{order_id}|{self.secured_key}|{self.merchant_id}|{amount_val:.2f}|PKR".encode("utf-8")
        ).hexdigest()

        return_url = os.getenv(
            "PAYFAST_RETURN_URL",
            f"{base_pub}/checkout/success?order_id={urllib.parse.quote(order_id)}&provider=payfast",
        )
        cancel_url = os.getenv(
            "PAYFAST_CANCEL_URL",
            f"{base_pub}/checkout/cancel?order_id={urllib.parse.quote(order_id)}&provider=payfast",
        )
        ipn_url = os.getenv("PAYFAST_IPN_URL", f"{base_pub}/webhook/payfast")

        fields = {
            "MERCHANT_ID": self.merchant_id,
            "MERCHANT_NAME": COMPANY_NAME,
            "TOKEN": token,
            "PROCCODE": "00",
            "TXNAMT": f"{amount_val:.2f}",
            "CUSTOMER_MOBILE_NO": "03000000000",
            "CUSTOMER_EMAIL_ADDRESS": str(order.get("email") or "customer@lumo.pro"),
            "SIGNATURE": signature,
            "VERSION": "LUMO-1.0",
            "TXNDESC": f"{COMPANY_NAME} {str(order.get('plan', 'pro')).title()} ({str(order.get('cycle', 'monthly')).title()})",
            "SUCCESS_URL": return_url,
            "FAILURE_URL": cancel_url,
            "CHECKOUT_URL": ipn_url,
            "BASKET_ID": order_id,
            "ORDER_DATE": order_date,
            "CURRENCY_CODE": str(order.get("currency") or "PKR").upper(),
        }

        hidden_inputs = "\n".join(
            f'<input type="hidden" name="{html.escape(k, quote=True)}" value="{html.escape(str(v), quote=True)}" />'
            for k, v in fields.items()
        )
        safe_post_url = html.escape(self.post_url, quote=True)
        safe_order = html.escape(order_id)
        safe_amt = f"{amount_val:,.0f}"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Redirecting to PayFast Checkout - {html.escape(COMPANY_NAME)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 32px; max-width: 440px; text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.4); }}
    h2 {{ margin: 0 0 10px; font-size: 20px; }}
    p {{ color: #94a3b8; font-size: 14px; line-height: 1.5; }}
    button {{ margin-top: 18px; background: #10b981; color: #06281e; font-weight: 700; border: 0; border-radius: 8px; padding: 12px 22px; font-size: 14px; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Redirecting to PayFast Pakistan</h2>
    <p>Order <b>{safe_order}</b> &middot; <b>Rs. {safe_amt} PKR</b></p>
    <p>Connecting you securely to PayFast (Cards, Bank Accounts &amp; Mobile Wallets)...</p>
    <form id="payfast_form" method="POST" action="{safe_post_url}">
      {hidden_inputs}
      <noscript><button type="submit">Continue to PayFast</button></noscript>
      <button type="submit">Proceed Now</button>
    </form>
  </div>
  <script>document.getElementById("payfast_form").submit();</script>
</body>
</html>"""

    def verify_webhook(
        self,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies PayFast IPN integrity via either:
        1. HMAC-SHA256 header (X-PAYFAST-SIGNATURE / SIGNATURE) over raw body, OR
        2. Standard PayFast APPS validation_hash = SHA256(basket_id|secured_key|merchant_id|err_code).
        """
        header_map = {k.upper(): v for k, v in headers.items()}
        signature = header_map.get("X-PAYFAST-SIGNATURE") or header_map.get("SIGNATURE")
        if signature:
            computed = hmac.new(
                self.secured_key.encode("utf-8"),
                msg=raw_body,
                digestmod=hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(computed, signature.strip()):
                return True, None
            return False, "Invalid PayFast HMAC signature"

        try:
            payload = parse_raw_payload(raw_body)
        except Exception:
            return False, "Invalid PayFast webhook payload"

        vhash = str(payload.get("validation_hash") or payload.get("VALIDATION_HASH") or "").strip().lower()
        if not vhash:
            return False, "Missing PayFast signature header or validation_hash"

        basket_id = str(payload.get("basket_id") or payload.get("BASKET_ID") or payload.get("order_id") or "").strip()
        err_code = str(payload.get("err_code") or payload.get("ERR_CODE") or "").strip()
        merchant_id = str(payload.get("merchant_id") or payload.get("MERCHANT_ID") or self.merchant_id).strip()

        expected_hash = hashlib.sha256(
            f"{basket_id}|{self.secured_key}|{merchant_id}|{err_code}".encode("utf-8")
        ).hexdigest().lower()

        if not hmac.compare_digest(expected_hash, vhash):
            logger.warning("PayFast validation_hash mismatch.")
            return False, "Invalid PayFast validation_hash"

        return True, None

    def parse_webhook_event(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> WebhookEventData:
        event_id = str(
            payload.get("transaction_id")
            or payload.get("PayFast_Txn_Id")
            or payload.get("event_id")
            or ""
        ).strip()
        order_id = str(
            payload.get("basket_id")
            or payload.get("BASKET_ID")
            or payload.get("order_id")
            or ""
        ).strip()
        amount = float(
            payload.get("txnamt")
            or payload.get("transaction_amount")
            or payload.get("TXNAMT")
            or payload.get("amount")
            or 0
        )
        currency = str(payload.get("currency_code") or payload.get("CURRENCY_CODE") or "PKR").upper().strip()
        res_code = str(payload.get("err_code") or payload.get("ERR_CODE") or payload.get("status") or "").strip().upper()

        is_paid = res_code in ("00", "000", "0", "PAID", "SUCCESS")
        is_refund = res_code in ("REFUND", "REFUNDED", "REVERSED")

        status = "REFUNDED" if is_refund else ("PAID" if is_paid else "FAILED")

        return WebhookEventData(
            event_id=event_id,
            order_id=order_id,
            event_type="payfast.transaction",
            status=status,
            amount=amount,
            currency=currency,
            is_paid=is_paid,
            is_refund=is_refund,
            raw_data=payload,
        )
