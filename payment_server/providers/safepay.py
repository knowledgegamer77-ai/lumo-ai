"""
========================================================================================
            LUMO AI | SAFEPAY PAYMENT GATEWAY ADAPTER (PAKISTAN)
========================================================================================
Official Safepay adapter implementing live /order/v1/init tracker creation,
SBP-regulated hosted Checkout Components URLs, and HMAC-SHA256 webhook verification.
========================================================================================
"""

import base64
import hashlib
import hmac
import logging
import os
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import requests

from payment_server.config import (
    PKR_PRICES,
    PUBLIC_SERVER_URL,
    SAFEPAY_API_KEY,
    SAFEPAY_BASE_URL,
    SAFEPAY_COMPONENTS_URL,
    SAFEPAY_ENV,
    SAFEPAY_REQUEST_TIMEOUT,
    SAFEPAY_V1_SECRET,
    SAFEPAY_WEBHOOK_SECRET,
)
from payment_server.providers.base import BasePaymentProvider, WebhookEventData

logger = logging.getLogger("payment_server.safepay")

_MOCK_SAFEPAY_API_KEY = "sec_test_mock_safepay_key"


class SafepayPaymentProvider(BasePaymentProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        components_url: Optional[str] = None,
        v1_secret: Optional[str] = None,
        env: Optional[str] = None,
    ):
        self.env = (env or os.getenv("SAFEPAY_ENV") or SAFEPAY_ENV).lower().strip()
        self.api_key = api_key or os.getenv("SAFEPAY_API_KEY") or SAFEPAY_API_KEY
        self.v1_secret = v1_secret or os.getenv("SAFEPAY_V1_SECRET") or SAFEPAY_V1_SECRET
        self.webhook_secret = webhook_secret or os.getenv("SAFEPAY_WEBHOOK_SECRET") or SAFEPAY_WEBHOOK_SECRET

        default_base = (
            "https://api.getsafepay.com"
            if self.env == "production"
            else "https://sandbox.api.getsafepay.com"
        )
        default_components = (
            "https://www.getsafepay.com/components"
            if self.env == "production"
            else "https://sandbox.api.getsafepay.com/components"
        )
        self.base_url = (base_url or os.getenv("SAFEPAY_BASE_URL") or default_base or SAFEPAY_BASE_URL).rstrip("/")
        self.components_url = (
            components_url or os.getenv("SAFEPAY_COMPONENTS_URL") or default_components or SAFEPAY_COMPONENTS_URL
        ).rstrip("/")

    def is_configured(self) -> bool:
        return bool(
            self.api_key
            and self.api_key != _MOCK_SAFEPAY_API_KEY
            and self.webhook_secret
            and self.webhook_secret != "dGVzdF9zYWZlcGF5X3dlYmhvb2tfc2VjcmV0XzEyMzQ1"
        )

    def create_checkout_details(
        self,
        order_id: str,
        amount_pkr: int,
        email: str,
        plan: str,
        cycle: str,
        public_base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Initializes a Safepay payment tracker via /order/v1/init when live/real credentials
        are present, and constructs the hosted Safepay Components checkout redirect URL.
        """
        base_pub = (public_base_url or os.getenv("PUBLIC_SERVER_URL") or PUBLIC_SERVER_URL).rstrip("/")
        env_mode = "production" if self.env == "production" else "sandbox"
        is_cloud_runtime = bool(os.getenv("RENDER") or os.getenv("ENVIRONMENT", "").lower() == "production")
        tracker_token = ""

        if not self.api_key or (self.api_key == _MOCK_SAFEPAY_API_KEY and (is_cloud_runtime or env_mode == "production")):
            raise RuntimeError(
                "Safepay API credentials are not configured (set SAFEPAY_API_KEY and SAFEPAY_WEBHOOK_SECRET)."
            )

        if self.api_key == _MOCK_SAFEPAY_API_KEY and env_mode != "production":
            tracker_token = f"track_{order_id}"
        else:
            init_url = f"{self.base_url}/order/v1/init"
            payload = {
                "client": self.api_key,
                "amount": float(amount_pkr),
                "currency": "PKR",
                "environment": env_mode,
            }
            headers = {"Content-Type": "application/json"}
            if self.v1_secret and self.v1_secret != "test_v1_secret":
                headers["X-SFPY-MERCHANT-SECRET"] = self.v1_secret

            resp = requests.post(
                init_url,
                json=payload,
                headers=headers,
                timeout=SAFEPAY_REQUEST_TIMEOUT,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"Safepay /order/v1/init failed ({resp.status_code}): {resp.text[:300]}"
                )
            data = resp.json()
            tracker_token = str(
                (data.get("data") or {}).get("token")
                or data.get("token")
                or ""
            ).strip()
            if not tracker_token:
                raise RuntimeError("Safepay /order/v1/init response missing tracker token")

        redirect_url = f"{base_pub}/checkout/success?order_id={urllib.parse.quote(order_id)}&provider=safepay"
        cancel_url = f"{base_pub}/checkout/cancel?order_id={urllib.parse.quote(order_id)}&provider=safepay"

        params = {
            "env": env_mode,
            "beacon": tracker_token,
            "source": "custom",
            "order_id": order_id,
            "redirect_url": redirect_url,
            "cancel_url": cancel_url,
            "webhooks": "true",
            "plan": plan,
            "cycle": cycle,
        }
        checkout_url = f"{self.components_url}?{urllib.parse.urlencode(params)}"
        logger.info(f"Created Safepay checkout tracker {tracker_token} for order {order_id}")
        return {
            "checkout_url": checkout_url,
            "tracker": tracker_token,
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

    def verify_webhook(
        self,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies Safepay webhook signature:
        1. Extracts X-SFPY-SIGNATURE and X-SFPY-TIMESTAMP.
        2. Constructs message: <timestamp>.<raw_body>.
        3. Decodes base64 webhook secret (or falls back to UTF-8 bytes).
        4. Computes HMAC-SHA256 and validates via constant-time compare.
        """
        header_map = {k.upper(): v for k, v in headers.items()}
        signature_header = header_map.get("X-SFPY-SIGNATURE")
        timestamp_header = header_map.get("X-SFPY-TIMESTAMP")

        if not signature_header or not timestamp_header:
            return False, "Missing X-SFPY-SIGNATURE or X-SFPY-TIMESTAMP header"

        secret = self.webhook_secret or ""
        try:
            signing_key = base64.b64decode(secret, validate=True)
        except Exception:
            signing_key = secret.encode("utf-8")

        message = timestamp_header.encode("utf-8") + b"." + raw_body
        computed_hash = hmac.new(signing_key, msg=message, digestmod=hashlib.sha256).hexdigest()

        # Also support servers where shared secret is UTF-8 or raw 64-char hex bytes
        alt_hash = hmac.new(secret.encode("utf-8"), msg=message, digestmod=hashlib.sha256).hexdigest()
        candidates = [
            f"sha256={computed_hash}",
            computed_hash,
            f"sha256={alt_hash}",
            alt_hash,
        ]
        if len(secret) == 64:
            try:
                hex_hash = hmac.new(bytes.fromhex(secret), msg=message, digestmod=hashlib.sha256).hexdigest()
                candidates.extend([f"sha256={hex_hash}", hex_hash])
            except ValueError:
                pass

        clean_sig_header = signature_header.strip()
        is_valid = any(hmac.compare_digest(candidate, clean_sig_header) for candidate in candidates)

        if not is_valid:
            logger.warning("Safepay webhook signature mismatch.")
            return False, "Invalid signature"

        return True, None

    def parse_webhook_event(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> WebhookEventData:
        """
        Normalizes Safepay webhook event payload into WebhookEventData.
        """
        header_map = {k.upper(): v for k, v in headers.items()}
        event_id = (
            header_map.get("X-SFPY-EVENT-ID")
            or str(payload.get("token", ""))
            or str(payload.get("event_id", ""))
        ).strip()

        event_type = str(payload.get("type", "")).lower().strip()
        data = payload.get("data") or {}
        metadata = data.get("metadata") or {}
        notification = data.get("notification") or {}

        tracker = str(
            data.get("tracker")
            or data.get("token")
            or payload.get("tracker")
            or ""
        ).strip()

        order_id = str(
            metadata.get("order_id")
            or metadata.get("orderId")
            or data.get("order_id")
            or data.get("orderId")
            or notification.get("reference")
            or payload.get("order_id")
            or ""
        ).strip()

        currency = str(data.get("currency", payload.get("currency", "PKR")) or "PKR").upper().strip()
        raw_amt = float(data.get("amount", payload.get("amount", 0)) or 0)

        known_prices = set(PKR_PRICES.values())
        if raw_amt > 0 and (raw_amt / 100.0) in known_prices and raw_amt not in known_prices:
            amount = raw_amt / 100.0
        else:
            amount = raw_amt

        paid_event_types = {
            "payment.succeeded",
            "authorization.succeeded",
            "tracker.completed",
            "payment.captured",
            "subscription.payment.succeeded",
        }
        refund_event_types = {
            "charge.refunded",
            "payment.refunded",
            "refund.created",
            "refund:created",
            "payment.reversed",
            "void.succeeded",
            "authorization.reversed",
        }

        state = str(data.get("state", "")).upper().strip()
        is_paid = (event_type in paid_event_types) or (
            state in ("PAID", "TRACKER_AUTHORIZED", "TRACKER_ENDED", "COMPLETED")
        )
        is_refund = (event_type in refund_event_types) or (state in ("REFUNDED", "REVERSED"))

        if is_refund:
            status = "REFUNDED"
        elif is_paid:
            status = "PAID"
        else:
            status = "FAILED"

        return WebhookEventData(
            event_id=event_id,
            order_id=order_id,
            event_type=event_type,
            status=status,
            amount=amount,
            currency=currency,
            is_paid=is_paid,
            is_refund=is_refund,
            raw_data=payload,
            tracker=tracker,
        )
