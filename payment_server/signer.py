"""
========================================================================================
            LUMO AI | ED25519 ASYMMETRIC LICENSE SIGNING ENGINE
========================================================================================
Server-side asymmetric cryptographic signing using Hashir's passphrase-protected
Ed25519 private key. Issues single-device HWID-locked license keys.
========================================================================================
"""

import base64
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from payment_server.config import (
    HASHIR_PRIVATE_KEY_PATH,
    LUMO_ADMIN_PASSPHRASE,
    PLAN_DAYS,
)


def _load_key_bytes_from_env() -> Optional[bytes]:
    """Load Ed25519 PEM bytes from environment variables when deployed without disk key files."""
    pem_str = os.getenv("LUMO_PRIVATE_KEY_PEM") or os.getenv("HASHIR_PRIVATE_KEY_PEM") or ""
    if pem_str.strip():
        normalized = pem_str.strip().replace("\\n", "\n")
        return normalized.encode("utf-8")

    b64_str = os.getenv("LUMO_PRIVATE_KEY_B64") or ""
    if b64_str.strip():
        return base64.b64decode(b64_str.strip())

    return None


def load_signing_key(
    key_path: Optional[Path] = None,
    passphrase: Optional[str] = None,
) -> ed25519.Ed25519PrivateKey:
    key_bytes: Optional[bytes] = None
    if key_path is None:
        key_bytes = _load_key_bytes_from_env()

    if key_bytes is None:
        path = Path(key_path) if key_path else HASHIR_PRIVATE_KEY_PATH
        if not path.exists():
            raise FileNotFoundError(
                f"Private signing key not found in env (LUMO_PRIVATE_KEY_PEM / LUMO_PRIVATE_KEY_B64) or at: {path}"
            )
        key_bytes = path.read_bytes()

    pwd = passphrase if passphrase is not None else os.getenv("LUMO_ADMIN_PASSPHRASE", LUMO_ADMIN_PASSPHRASE)
    pwd_bytes = pwd.encode("utf-8") if pwd else None

    try:
        return serialization.load_pem_private_key(key_bytes, password=pwd_bytes)
    except TypeError:
        if pwd_bytes is not None:
            return serialization.load_pem_private_key(key_bytes, password=None)
        raise


def sign_order_license(
    order: Dict[str, Any],
    passphrase: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Signs an Ed25519 license token bound to the customer's HWID and purchased tier/cycle.
    Returns: (serial_id, license_token)
    """
    priv_key = load_signing_key(passphrase=passphrase)
    serial_id = uuid.uuid4().hex[:8].upper()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    plan_tier = str(order.get("plan", "pro")).lower().strip()
    billing_cycle = str(order.get("cycle", "monthly")).lower().strip()
    days = PLAN_DAYS.get(billing_cycle, 30)
    customer_email = str(order.get("email", "Valued Customer")).strip()
    hwid = str(order.get("hwid", "")).strip()

    payload = {
        "serial_id": serial_id,
        "client": customer_email,
        "days": int(days),
        "tier": plan_tier,
        "cycle": billing_cycle,
        "issued_at": now_str,
        "issuer": "Hashir | Lumo Payment Gateway Server",
    }
    if hwid:
        payload["hwid"] = hwid

    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = priv_key.sign(payload_bytes)

    p_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    s_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    token = f"LUMO-LIC.{p_b64}.{s_b64}"
    return serial_id, token
