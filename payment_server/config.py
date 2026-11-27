"""
========================================================================================
            LUMO AI | CLOUD PAYMENT SERVER CONFIGURATION (PKR ONLY)
========================================================================================
Server-side configuration and authoritative pricing matrix.
All secrets (API keys, webhook secrets, database URL, Ed25519 private signing key)
MUST be supplied via environment variables in production.
========================================================================================
"""

import os
from pathlib import Path
from typing import Dict, Tuple

SERVER_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SERVER_DIR.parent

# Database Configuration (Render PostgreSQL DATABASE_URL preferred, SQLite fallback)
DATABASE_URL = (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "").strip()
PAYMENT_DB_PATH = Path(os.getenv("PAYMENT_DB_PATH", str(PROJECT_DIR / "cloud_telemetry.db")))
PUBLIC_SERVER_URL = os.getenv("PUBLIC_SERVER_URL", "https://lumo-ai-soyg.onrender.com").rstrip("/")

# Authoritative Pakistan PKR Price Matrix (Strictly in PKR)
PKR_PRICES: Dict[Tuple[str, str], int] = {
    ("pro", "monthly"): 8120,
    ("pro", "yearly"): 63840,
    ("agency", "monthly"): 16520,
    ("agency", "yearly"): 131040,
    ("unlimited", "monthly"): 27720,
    ("unlimited", "yearly"): 231840,
}

PLAN_DAYS: Dict[str, int] = {
    "monthly": 30,
    "yearly": 365,
}

# Safepay Provider Configuration (env-only in cloud deployment)
SAFEPAY_API_KEY = os.getenv("SAFEPAY_API_KEY", "")
SAFEPAY_V1_SECRET = os.getenv("SAFEPAY_V1_SECRET", "")
SAFEPAY_WEBHOOK_SECRET = os.getenv("SAFEPAY_WEBHOOK_SECRET", "")
SAFEPAY_ENV = os.getenv("SAFEPAY_ENV", "sandbox").lower().strip()
SAFEPAY_BASE_URL = os.getenv(
    "SAFEPAY_BASE_URL",
    "https://api.getsafepay.com" if SAFEPAY_ENV == "production" else "https://sandbox.api.getsafepay.com",
).rstrip("/")
SAFEPAY_COMPONENTS_URL = os.getenv(
    "SAFEPAY_COMPONENTS_URL",
    "https://www.getsafepay.com/components" if SAFEPAY_ENV == "production" else "https://sandbox.api.getsafepay.com/components",
).rstrip("/")
SAFEPAY_RETURN_URL = os.getenv("SAFEPAY_RETURN_URL", f"{PUBLIC_SERVER_URL}/checkout/success")
SAFEPAY_CANCEL_URL = os.getenv("SAFEPAY_CANCEL_URL", f"{PUBLIC_SERVER_URL}/checkout/cancel")
SAFEPAY_REQUEST_TIMEOUT = int(os.getenv("SAFEPAY_REQUEST_TIMEOUT", "15"))

# PayFast (Pakistan) Provider Configuration (env-only in cloud deployment)
PAYFAST_MERCHANT_ID = os.getenv("PAYFAST_MERCHANT_ID", "")
PAYFAST_SECURED_KEY = os.getenv("PAYFAST_SECURED_KEY", "")
PAYFAST_ENV = os.getenv("PAYFAST_ENV", "sandbox").lower().strip()
PAYFAST_TOKEN_URL = os.getenv(
    "PAYFAST_TOKEN_URL",
    "https://ipg.apps.net.pk/Ecommerce/api/Transaction/GetAccessToken"
    if PAYFAST_ENV == "production"
    else "https://ipguat.apps.net.pk/Ecommerce/api/Transaction/GetAccessToken",
)
PAYFAST_POST_URL = os.getenv(
    "PAYFAST_POST_URL",
    "https://ipg.apps.net.pk/Ecommerce/api/Transaction/PostTransaction"
    if PAYFAST_ENV == "production"
    else "https://ipguat.apps.net.pk/Ecommerce/api/Transaction/PostTransaction",
)
PAYFAST_RETURN_URL = os.getenv("PAYFAST_RETURN_URL", f"{PUBLIC_SERVER_URL}/checkout/success")
PAYFAST_CANCEL_URL = os.getenv("PAYFAST_CANCEL_URL", f"{PUBLIC_SERVER_URL}/checkout/cancel")
PAYFAST_IPN_URL = os.getenv("PAYFAST_IPN_URL", f"{PUBLIC_SERVER_URL}/webhook/payfast")
PAYFAST_REQUEST_TIMEOUT = int(os.getenv("PAYFAST_REQUEST_TIMEOUT", "15"))

# Ed25519 Signing Key & Admin Auth (Loaded exclusively from env in cloud deployment)
LUMO_PRIVATE_KEY_PEM = os.getenv("LUMO_PRIVATE_KEY_PEM") or os.getenv("HASHIR_PRIVATE_KEY_PEM") or ""
LUMO_PRIVATE_KEY_B64 = os.getenv("LUMO_PRIVATE_KEY_B64") or ""
HASHIR_PRIVATE_KEY_PATH = Path(os.getenv("HASHIR_PRIVATE_KEY_PATH", str(PROJECT_DIR / "lumo_private_key.pem")))
LUMO_ADMIN_PASSPHRASE = os.getenv("LUMO_ADMIN_PASSPHRASE", "")
LUMO_ADMIN_API_KEY = os.getenv("LUMO_ADMIN_API_KEY", "")

# SMTP & Branding Configuration
SMTP_HOST = os.getenv("LUMO_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("LUMO_SMTP_PORT", "587"))
SMTP_USER = os.getenv("LUMO_SMTP_USER", "")
SMTP_PASS = os.getenv("LUMO_SMTP_PASS", "")
SMTP_FROM = os.getenv("LUMO_SMTP_FROM", "billing@lumo.pro")
SUPPORT_EMAIL = os.getenv("LUMO_SUPPORT_EMAIL", "support@lumo.pro")
COMPANY_NAME = os.getenv("LUMO_COMPANY_NAME", "Lumo AI")
