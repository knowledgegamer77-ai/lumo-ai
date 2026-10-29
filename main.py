"""
========================================================================================
             LUMO AI | CENTRAL CLOUD TELEMETRY & ADMIN SERVER
========================================================================================
Production-ready FastAPI cloud microservice for Render.com deployment.
Provides 24/7 global telemetry, device tracking, client registrations,
1-Click remote kill switch, and automated version checking without manual IPs.
========================================================================================
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.environ.get("LUMO_DB_PATH", "cloud_telemetry.db")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS client_telemetry (
                hwid TEXT PRIMARY KEY,
                machine_name TEXT,
                os_platform TEXT,
                username TEXT,
                user_email TEXT,
                plan_tier TEXT DEFAULT 'Starter',
                activation_key TEXT,
                ip_address TEXT,
                location TEXT,
                leads_generated INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'Active',
                block_reason TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS revoked_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT UNIQUE,
                target_type TEXT,
                reason TEXT,
                revoked_at TEXT
            )
            """
        )


init_db()

app = FastAPI(
    title="Lumo AI Central Cloud Telemetry Server",
    version="2.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request Models ---
class HeartbeatPayload(BaseModel):
    hwid: str
    machine_name: str = "Client"
    os_platform: str = "Windows"
    username: str = "Guest"
    user_email: str = ""
    plan_tier: str = "Starter"
    activation_key: str = ""
    ip_address: str = "127.0.0.1"
    location: str = "Pakistan"
    leads_generated: int = 0


class BlockDeviceRequest(BaseModel):
    target_id: str
    reason: str = "Revoked by Administrator"


# --- Endpoints ---
@app.get("/")
@app.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "Lumo AI Central Cloud Telemetry & Licensing Backend",
        "version": "2.2.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/v1/version")
def get_latest_version():
    return {
        "version": "2.2.0",
        "name": "Lumo AI v2.2.0 — Pro Client Edition",
        "release_date": "2026-10-29",
        "changelog": [
            "⚡ Critical Bug Fixes & 100% Instant Smooth Performance (Zero Lag).",
            "🚀 High-Precision B2B Lead Engine & Live Deliverability Enhancements.",
            "💬 1-Click WhatsApp Direct Lead Outreach & Link Sharing.",
            "💳 Meezan Bank, JazzCash & Raast Instant QR Payment Integration.",
            "🛡️ Enhanced Security & Safe Referral Rewards Protection.",
        ],
        "download_url": "https://github.com/knowledgegamer77-ai/lumo-ai/releases/latest/download/Lumo_v2.0_Pro_Client_Release.zip",
        "mandatory": False,
        "min_supported_version": "2.0.0",
    }


@app.post("/api/v1/telemetry/heartbeat")
def record_heartbeat(payload: HeartbeatPayload):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_email = payload.user_email.strip().lower()

    with get_db() as c:
        # Check revocation
        c.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (payload.hwid,))
        rev = c.fetchone()
        if not rev and clean_email:
            c.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (clean_email,))
            rev = c.fetchone()

        is_blocked = rev is not None
        block_reason = rev["reason"] if is_blocked else None
        status_val = "Blocked" if is_blocked else "Active"

        c.execute("SELECT first_seen, leads_generated FROM client_telemetry WHERE hwid = ?", (payload.hwid,))
        row = c.fetchone()
        first_seen = row["first_seen"] if row else now_str
        max_leads = max(payload.leads_generated, row["leads_generated"] if row else 0)

        c.execute(
            """
            INSERT INTO client_telemetry (
                hwid, machine_name, os_platform, username, user_email,
                plan_tier, activation_key, ip_address, location,
                leads_generated, first_seen, last_seen, status, block_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hwid) DO UPDATE SET
                machine_name=excluded.machine_name,
                os_platform=excluded.os_platform,
                username=CASE WHEN excluded.username != 'Guest' AND excluded.username != '' THEN excluded.username ELSE client_telemetry.username END,
                user_email=CASE WHEN excluded.user_email != '' AND excluded.user_email IS NOT NULL THEN excluded.user_email ELSE client_telemetry.user_email END,
                plan_tier=CASE WHEN excluded.plan_tier != 'Starter' THEN excluded.plan_tier ELSE client_telemetry.plan_tier END,
                activation_key=CASE WHEN excluded.activation_key != '' THEN excluded.activation_key ELSE client_telemetry.activation_key END,
                ip_address=excluded.ip_address,
                location=excluded.location,
                leads_generated=MAX(excluded.leads_generated, client_telemetry.leads_generated),
                last_seen=excluded.last_seen,
                status=excluded.status,
                block_reason=excluded.block_reason
            """,
            (
                payload.hwid, payload.machine_name, payload.os_platform, payload.username, clean_email,
                payload.plan_tier, payload.activation_key, payload.ip_address, payload.location,
                max_leads, first_seen, now_str, status_val, block_reason,
            ),
        )

        return {
            "status": "ok",
            "telemetry": {
                "hwid": payload.hwid,
                "allowed": not is_blocked,
                "status": status_val,
                "block_reason": block_reason,
            },
        }


@app.get("/api/v1/telemetry/check")
def check_authorization(hwid: str, email: str = ""):
    with get_db() as c:
        if email:
            c.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (email.strip().lower(),))
            r = c.fetchone()
            if r:
                return {"allowed": False, "status": "Blocked", "reason": r["reason"] or "Revoked"}

        c.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (hwid,))
        r = c.fetchone()
        if r:
            return {"allowed": False, "status": "Blocked", "reason": r["reason"] or "Revoked"}

        c.execute("SELECT status, block_reason FROM client_telemetry WHERE hwid = ?", (hwid,))
        row = c.fetchone()
        if row and row["status"] == "Blocked":
            return {"allowed": False, "status": "Blocked", "reason": row["block_reason"] or "Revoked"}

        return {"allowed": True, "status": "Active", "reason": "Authorized"}


@app.get("/api/v1/admin/devices")
def list_devices():
    with get_db() as c:
        c.execute(
            """
            SELECT t.*, 
                   CASE WHEN r.target_id IS NOT NULL THEN 1 ELSE 0 END as is_explicitly_revoked
            FROM client_telemetry t
            LEFT JOIN revoked_devices r ON t.hwid = r.target_id OR t.user_email = r.target_id
            ORDER BY t.last_seen DESC
            """
        )
        rows = [dict(r) for r in c.fetchall()]
        return {"count": len(rows), "devices": rows}


@app.post("/api/v1/admin/devices/block")
def block_device(payload: BlockDeviceRequest):
    tid = payload.target_id.strip()
    ttype = "EMAIL" if "@" in tid else "HWID"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as c:
        c.execute(
            """
            INSERT OR REPLACE INTO revoked_devices (target_id, target_type, reason, revoked_at)
            VALUES (?, ?, ?, ?)
            """,
            (tid, ttype, payload.reason, now_str),
        )
        if ttype == "HWID":
            c.execute("UPDATE client_telemetry SET status = 'Blocked', block_reason = ? WHERE hwid = ?", (payload.reason, tid))
        else:
            c.execute("UPDATE client_telemetry SET status = 'Blocked', block_reason = ? WHERE user_email = ?", (payload.reason, tid.lower()))

        return {"status": "ok", "blocked": True, "target_id": tid}


@app.post("/api/v1/admin/devices/unblock")
def unblock_device(payload: BlockDeviceRequest):
    tid = payload.target_id.strip()
    with get_db() as c:
        c.execute("DELETE FROM revoked_devices WHERE target_id = ?", (tid,))
        c.execute("DELETE FROM revoked_devices WHERE target_id = ?", (tid.lower(),))
        c.execute("UPDATE client_telemetry SET status = 'Active', block_reason = NULL WHERE hwid = ? OR user_email = ?", (tid, tid.lower()))
        return {"status": "ok", "unblocked": True, "target_id": tid}
