"""
========================================================================================
            LUMO AI | PAYMENT & TELEMETRY DATABASE ENGINE (POSTGRESQL / SQLITE)
========================================================================================
Dual-backend persistence layer supporting Render PostgreSQL (via DATABASE_URL with
psycopg/psycopg2) in production and SQLite locally/in tests.
Stores orders, idempotent webhook events, signed licenses, device telemetry, and blocks.
========================================================================================
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from payment_server.config import DATABASE_URL as CONFIG_DATABASE_URL
from payment_server.config import PAYMENT_DB_PATH

try:
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
except ImportError:
    psycopg = None
    dict_row = None

try:
    import psycopg2  # type: ignore
    from psycopg2.extras import RealDictCursor  # type: ignore
except ImportError:
    psycopg2 = None
    RealDictCursor = None


def _resolve_backend(
    db_path: Optional[Path] = None,
    database_url: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Determines whether to use PostgreSQL or SQLite.
    Explicit db_path without an explicit database_url always uses SQLite so isolated
    local/unit tests never touch a remote database.
    """
    if database_url:
        raw_url = database_url.strip()
    elif db_path is not None:
        raw_url = ""
    else:
        raw_url = (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or CONFIG_DATABASE_URL or "").strip()

    if raw_url.startswith("postgres://") or raw_url.startswith("postgresql://"):
        if raw_url.startswith("postgres://"):
            raw_url = "postgresql://" + raw_url[len("postgres://") :]
        return "postgres", raw_url

    target_path = Path(db_path) if db_path else Path(os.getenv("PAYMENT_DB_PATH", str(PAYMENT_DB_PATH)))
    return "sqlite", str(target_path)


def _sqlite_to_pg_sql(sql: str) -> str:
    """Translates '?' DB-API placeholders to '%s' outside string literals."""
    out: List[str] = []
    in_single = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            out.append(ch)
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_single = not in_single
        elif ch == "?" and not in_single:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _is_unique_violation(exc: Exception) -> bool:
    """Checks for SQLite IntegrityError or Postgres unique constraint violation (SQLSTATE 23505)."""
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    pgcode = getattr(exc, "pgcode", None) or getattr(exc, "sqlstate", None)
    if pgcode == "23505":
        return True
    cls_name = exc.__class__.__name__.lower()
    if "uniqueviolation" in cls_name or "integrityerror" in cls_name:
        return True
    return "unique constraint" in str(exc).lower() or "duplicate key" in str(exc).lower()


class _CursorAdapter:
    """Unifies SQLite and Postgres cursor execution with dict-row outputs."""

    def __init__(self, raw_cursor: Any, backend: str):
        self._cursor = raw_cursor
        self.backend = backend

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> Any:
        query = _sqlite_to_pg_sql(sql) if self.backend == "postgres" else sql
        if params:
            return self._cursor.execute(query, params)
        return self._cursor.execute(query)

    def fetchone(self) -> Optional[Dict[str, Any]]:
        row = self._cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self) -> List[Dict[str, Any]]:
        rows = self._cursor.fetchall()
        return [dict(r) for r in rows]

    @property
    def rowcount(self) -> int:
        return int(getattr(self._cursor, "rowcount", 0) or 0)


@contextmanager
def get_db_cursor(db_path: Optional[Path] = None, database_url: Optional[str] = None):
    backend, target = _resolve_backend(db_path=db_path, database_url=database_url)
    if backend == "postgres":
        if psycopg is not None:
            conn = psycopg.connect(target, row_factory=dict_row, connect_timeout=10)
            try:
                with conn.cursor() as raw_cur:
                    yield _CursorAdapter(raw_cur, "postgres")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            return
        if psycopg2 is not None:
            conn = psycopg2.connect(target, connect_timeout=10)
            try:
                raw_cur = conn.cursor(cursor_factory=RealDictCursor)
                try:
                    yield _CursorAdapter(raw_cur, "postgres")
                finally:
                    raw_cur.close()
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            return
        raise RuntimeError(
            "PostgreSQL DATABASE_URL configured, but neither 'psycopg' nor 'psycopg2' is installed."
        )

    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        raw_cur = conn.cursor()
        yield _CursorAdapter(raw_cur, "sqlite")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _safe_add_column(cursor: _CursorAdapter, table: str, col_def: str) -> None:
    if cursor.backend == "postgres":
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col_def}")
    else:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            pass


def init_db(db_path: Optional[Path] = None, database_url: Optional[str] = None) -> None:
    """Initializes schema tables and lightweight column migrations for SQLite or PostgreSQL."""
    with get_db_cursor(db_path=db_path, database_url=database_url) as cursor:
        pk_id_col = (
            "id SERIAL PRIMARY KEY"
            if cursor.backend == "postgres"
            else "id INTEGER PRIMARY KEY AUTOINCREMENT"
        )
        amt_col = "DOUBLE PRECISION NOT NULL" if cursor.backend == "postgres" else "REAL NOT NULL"

        # 1. Orders table
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                plan TEXT NOT NULL,
                cycle TEXT NOT NULL,
                expected_amount {amt_col},
                currency TEXT NOT NULL DEFAULT 'PKR',
                hwid TEXT NOT NULL,
                email TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'COMPLETED', 'FAILED', 'REFUNDED')),
                provider TEXT NOT NULL DEFAULT 'safepay',
                gateway_tracker TEXT,
                checkout_url TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        _safe_add_column(cursor, "orders", "provider TEXT NOT NULL DEFAULT 'safepay'")
        _safe_add_column(cursor, "orders", "gateway_tracker TEXT")
        _safe_add_column(cursor, "orders", "checkout_url TEXT")

        # 2. Webhook idempotency events table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL
            )
            """
        )

        # 3. Licenses table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                serial_id TEXT PRIMARY KEY,
                order_id TEXT NOT NULL,
                token TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (order_id) REFERENCES orders(order_id)
            )
            """
        )

        # 3b. License Redemptions table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS license_redemptions (
                license_id TEXT PRIMARY KEY,
                hwid TEXT NOT NULL,
                username TEXT,
                client_name TEXT,
                tier TEXT,
                duration_days INTEGER,
                redeemed_at TEXT NOT NULL
            )
            """
        )

        # 4. Client Telemetry & Device Tracking table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS client_telemetry (
                hwid TEXT PRIMARY KEY,
                machine_name TEXT,
                os_platform TEXT,
                username TEXT,
                user_email TEXT,
                plan_tier TEXT,
                activation_key TEXT,
                ip_address TEXT,
                location TEXT,
                app_version TEXT,
                leads_generated INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'Active',
                block_reason TEXT
            )
            """
        )
        _safe_add_column(cursor, "client_telemetry", "app_version TEXT")

        # 5. Revoked Devices / Remote Kill Switch table
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS revoked_devices (
                {pk_id_col},
                target_id TEXT UNIQUE NOT NULL,
                target_type TEXT NOT NULL CHECK(target_type IN ('HWID', 'EMAIL')),
                reason TEXT,
                revoked_at TEXT NOT NULL
            )
            """
        )


class PaymentDBManager:
    def __init__(self, db_path: Optional[Path] = None, database_url: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else None
        self.database_url = database_url
        backend, target = _resolve_backend(db_path=self.db_path, database_url=self.database_url)
        self.backend = backend
        if backend == "sqlite":
            self.db_path = Path(target)
        init_db(db_path=self.db_path, database_url=self.database_url)

    def _cursor(self):
        return get_db_cursor(db_path=self.db_path, database_url=self.database_url)

    def create_order(
        self,
        order_id: str,
        plan: str,
        cycle: str,
        expected_amount: float,
        currency: str,
        hwid: str,
        email: str,
        status: str = "PENDING",
        provider: str = "safepay",
        gateway_tracker: Optional[str] = None,
        checkout_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean_provider = (provider or "safepay").lower().strip()
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO orders (
                    order_id, plan, cycle, expected_amount, currency,
                    hwid, email, status, provider, gateway_tracker, checkout_url, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order_id,
                    plan.lower().strip(),
                    cycle.lower().strip(),
                    float(expected_amount),
                    currency.upper().strip(),
                    hwid.strip(),
                    email.strip().lower(),
                    status,
                    clean_provider,
                    gateway_tracker,
                    checkout_url,
                    created_at,
                ),
            )

        return {
            "order_id": order_id,
            "plan": plan.lower().strip(),
            "cycle": cycle.lower().strip(),
            "expected_amount": float(expected_amount),
            "currency": currency.upper().strip(),
            "hwid": hwid.strip(),
            "email": email.strip().lower(),
            "status": status,
            "provider": clean_provider,
            "gateway_tracker": gateway_tracker,
            "checkout_url": checkout_url,
            "created_at": created_at,
        }

    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cursor:
            cursor.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,))
            return cursor.fetchone()

    def get_order_by_tracker(self, gateway_tracker: str) -> Optional[Dict[str, Any]]:
        if not gateway_tracker:
            return None
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM orders WHERE gateway_tracker = ? ORDER BY created_at DESC LIMIT 1",
                (gateway_tracker.strip(),),
            )
            return cursor.fetchone()

    def update_order_gateway(
        self,
        order_id: str,
        gateway_tracker: Optional[str] = None,
        checkout_url: Optional[str] = None,
    ) -> bool:
        with self._cursor() as cursor:
            cursor.execute(
                """
                UPDATE orders
                SET gateway_tracker = COALESCE(?, gateway_tracker),
                    checkout_url = COALESCE(?, checkout_url)
                WHERE order_id = ?
                """,
                (gateway_tracker, checkout_url, order_id),
            )
            return cursor.rowcount > 0

    def update_order_status(self, order_id: str, status: str) -> bool:
        with self._cursor() as cursor:
            cursor.execute(
                "UPDATE orders SET status = ? WHERE order_id = ?",
                (status, order_id),
            )
            return cursor.rowcount > 0

    def record_webhook_event(self, event_id: str) -> bool:
        """
        Idempotency check: Records event_id. Returns True if first time; False if duplicate.
        """
        received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._cursor() as cursor:
                cursor.execute(
                    "INSERT INTO webhook_events (event_id, received_at) VALUES (?, ?)",
                    (event_id, received_at),
                )
                return True
        except Exception as exc:
            if _is_unique_violation(exc):
                return False
            raise

    def is_event_processed(self, event_id: str) -> bool:
        with self._cursor() as cursor:
            cursor.execute("SELECT 1 AS found FROM webhook_events WHERE event_id = ?", (event_id,))
            return cursor.fetchone() is not None

    def store_license(self, serial_id: str, order_id: str, token: str) -> Dict[str, Any]:
        issued_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO licenses (serial_id, order_id, token, issued_at, revoked)
                VALUES (?, ?, ?, ?, 0)
                """,
                (serial_id, order_id, token, issued_at),
            )
        return {
            "serial_id": serial_id,
            "order_id": order_id,
            "token": token,
            "issued_at": issued_at,
            "revoked": 0,
        }

    def get_license_by_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        with self._cursor() as cursor:
            cursor.execute("SELECT * FROM licenses WHERE order_id = ?", (order_id,))
            return cursor.fetchone()

    def revoke_license_by_order(self, order_id: str) -> bool:
        with self._cursor() as cursor:
            cursor.execute(
                "UPDATE licenses SET revoked = 1 WHERE order_id = ?",
                (order_id,),
            )
            return cursor.rowcount > 0

    # --- Client Telemetry & Device Management Methods ---

    def record_client_heartbeat(
        self,
        hwid: str,
        machine_name: str,
        os_platform: str,
        username: str,
        user_email: str,
        plan_tier: str,
        activation_key: str,
        ip_address: str,
        location: str,
        leads_generated: int = 0,
        app_version: str = "",
    ) -> Dict[str, Any]:
        """Upserts a client telemetry record and checks authorization."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._cursor() as cursor:
            cursor.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (hwid,))
            hwid_rev = cursor.fetchone()
            if not hwid_rev and user_email:
                cursor.execute(
                    "SELECT reason FROM revoked_devices WHERE target_id = ?",
                    (user_email.lower().strip(),),
                )
                hwid_rev = cursor.fetchone()

            is_blocked = hwid_rev is not None
            block_reason = hwid_rev["reason"] if is_blocked else None
            status_val = "Blocked" if is_blocked else "Active"

            cursor.execute(
                "SELECT first_seen, leads_generated FROM client_telemetry WHERE hwid = ?",
                (hwid,),
            )
            row = cursor.fetchone()
            first_seen = row["first_seen"] if row else now_str
            max_leads = max(int(leads_generated or 0), int(row["leads_generated"] or 0) if row else 0)

            cursor.execute(
                """
                INSERT INTO client_telemetry (
                    hwid, machine_name, os_platform, username, user_email,
                    plan_tier, activation_key, ip_address, location, app_version,
                    leads_generated, first_seen, last_seen, status, block_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hwid) DO UPDATE SET
                    machine_name=EXCLUDED.machine_name,
                    os_platform=EXCLUDED.os_platform,
                    username=CASE WHEN EXCLUDED.username != 'Guest' AND EXCLUDED.username != '' THEN EXCLUDED.username ELSE client_telemetry.username END,
                    user_email=CASE WHEN EXCLUDED.user_email != '' AND EXCLUDED.user_email IS NOT NULL THEN EXCLUDED.user_email ELSE client_telemetry.user_email END,
                    plan_tier=CASE WHEN EXCLUDED.plan_tier != 'Starter' THEN EXCLUDED.plan_tier ELSE client_telemetry.plan_tier END,
                    activation_key=CASE WHEN EXCLUDED.activation_key != '' THEN EXCLUDED.activation_key ELSE client_telemetry.activation_key END,
                    ip_address=EXCLUDED.ip_address,
                    location=EXCLUDED.location,
                    app_version=CASE WHEN EXCLUDED.app_version != '' AND EXCLUDED.app_version IS NOT NULL THEN EXCLUDED.app_version ELSE client_telemetry.app_version END,
                    leads_generated=CASE
                        WHEN EXCLUDED.leads_generated > client_telemetry.leads_generated THEN EXCLUDED.leads_generated
                        ELSE client_telemetry.leads_generated
                    END,
                    last_seen=EXCLUDED.last_seen,
                    status=EXCLUDED.status,
                    block_reason=EXCLUDED.block_reason
                """,
                (
                    hwid, machine_name, os_platform, username, user_email,
                    plan_tier, activation_key, ip_address, location, app_version,
                    max_leads, first_seen, now_str, status_val, block_reason,
                ),
            )
            return {
                "hwid": hwid,
                "allowed": not is_blocked,
                "status": status_val,
                "block_reason": block_reason,
            }

    def check_device_authorization(self, hwid: str, user_email: str = "") -> Tuple[bool, str]:
        """Checks if a device or email is currently blocked."""
        with self._cursor() as cursor:
            cursor.execute("SELECT reason FROM revoked_devices WHERE target_id = ?", (hwid,))
            r = cursor.fetchone()
            if r:
                return False, f"ACCESS SUSPENDED: Device HWID '{hwid}' has been blocked by the administrator ({r['reason'] or 'Revoked'})."

            if user_email:
                cursor.execute(
                    "SELECT reason FROM revoked_devices WHERE target_id = ?",
                    (user_email.lower().strip(),),
                )
                r = cursor.fetchone()
                if r:
                    return False, f"ACCOUNT BLOCKED: Account '{user_email}' has been suspended by the administrator ({r['reason'] or 'Revoked'})."

            cursor.execute("SELECT status, block_reason FROM client_telemetry WHERE hwid = ?", (hwid,))
            row = cursor.fetchone()
            if row and row["status"] == "Blocked":
                return False, f"ACCESS SUSPENDED: Device is deactivated ({row['block_reason'] or 'Revoked'})."

            return True, "Active"

    def get_all_client_devices(self) -> List[Dict[str, Any]]:
        """Returns all tracked client devices sorted by last_seen descending."""
        with self._cursor() as cursor:
            cursor.execute(
                """
                SELECT t.*,
                       COALESCE(NULLIF(t.user_email, ''), (SELECT email FROM orders WHERE hwid = t.hwid AND email != '' ORDER BY created_at DESC LIMIT 1), '') AS resolved_email,
                       CASE WHEN r.target_id IS NOT NULL THEN 1 ELSE 0 END AS is_explicitly_revoked
                FROM client_telemetry t
                LEFT JOIN revoked_devices r ON t.hwid = r.target_id OR LOWER(t.user_email) = LOWER(r.target_id)
                ORDER BY t.last_seen DESC
                """
            )
            rows = cursor.fetchall()
            devices: List[Dict[str, Any]] = []
            seen_targets = set()
            for r in rows:
                item = dict(r)
                if not item.get("user_email") and item.get("resolved_email"):
                    item["user_email"] = item["resolved_email"]
                if item.get("is_explicitly_revoked"):
                    item["status"] = "Blocked"
                seen_targets.add(item.get("hwid"))
                if item.get("user_email"):
                    seen_targets.add(item["user_email"].lower())
                devices.append(item)

            try:
                cursor.execute(
                    "SELECT DISTINCT hwid, email, plan, created_at FROM orders WHERE hwid != '' AND hwid IS NOT NULL"
                )
                ord_rows = cursor.fetchall()
                for o_row in ord_rows:
                    o_hwid = o_row["hwid"]
                    if o_hwid not in seen_targets:
                        devices.append({
                            "hwid": o_hwid,
                            "machine_name": "Client-Workstation",
                            "os_platform": "Windows",
                            "username": (o_row["email"].split("@")[0] if o_row["email"] else "Client").capitalize(),
                            "user_email": o_row["email"] or "",
                            "plan_tier": o_row["plan"].capitalize() if o_row["plan"] else "Pro",
                            "activation_key": "",
                            "ip_address": "Direct Client",
                            "location": "Pakistan",
                            "leads_generated": 0,
                            "first_seen": o_row["created_at"],
                            "last_seen": o_row["created_at"],
                            "status": "Active",
                            "block_reason": None,
                            "is_explicitly_revoked": 0,
                        })
                        seen_targets.add(o_hwid)
            except Exception:
                pass

            cursor.execute("SELECT * FROM revoked_devices")
            rev_rows = cursor.fetchall()
            for rev in rev_rows:
                tid = rev["target_id"]
                if tid not in seen_targets and tid.lower() not in seen_targets:
                    devices.append({
                        "hwid": tid,
                        "machine_name": "Blocked Remote Host",
                        "os_platform": "Unknown",
                        "username": "Blocked User",
                        "user_email": tid if rev["target_type"] == "EMAIL" else "",
                        "plan_tier": "None",
                        "activation_key": "",
                        "ip_address": "Unknown",
                        "location": "Unknown",
                        "leads_generated": 0,
                        "first_seen": rev["revoked_at"],
                        "last_seen": rev["revoked_at"],
                        "status": "Blocked",
                        "block_reason": rev["reason"],
                    })
            return devices

    def block_device(self, target_id: str, target_type: str = "HWID", reason: str = "") -> bool:
        """Remotely blocks a target device or user email (Remote Kill Switch)."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_val = target_id.strip() if target_type == "HWID" else target_id.lower().strip()
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO revoked_devices (target_id, target_type, reason, revoked_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET reason=EXCLUDED.reason, revoked_at=EXCLUDED.revoked_at
                """,
                (target_val, target_type, reason or "Revoked by Administrator", now_str),
            )
            if target_type == "HWID":
                cursor.execute(
                    "UPDATE client_telemetry SET status = 'Blocked', block_reason = ? WHERE hwid = ?",
                    (reason or "Revoked by Administrator", target_val),
                )
            else:
                cursor.execute(
                    "UPDATE client_telemetry SET status = 'Blocked', block_reason = ? WHERE lower(user_email) = ?",
                    (reason or "Revoked by Administrator", target_val),
                )
            return True

    def unblock_device(self, target_id: str) -> bool:
        """Restores access to a previously blocked device or email."""
        target_val = target_id.strip()
        with self._cursor() as cursor:
            cursor.execute(
                "DELETE FROM revoked_devices WHERE target_id = ? OR target_id = ?",
                (target_val, target_val.lower()),
            )
            cursor.execute(
                "UPDATE client_telemetry SET status = 'Active', block_reason = NULL WHERE hwid = ? OR lower(user_email) = ?",
                (target_val, target_val.lower()),
            )
            return True

    def get_license_redemption(self, license_id: str) -> Optional[Dict[str, Any]]:
        """Checks if a license has been redeemed."""
        with self._cursor() as cursor:
            cursor.execute("SELECT * FROM license_redemptions WHERE license_id = ?", (license_id.strip(),))
            return cursor.fetchone()

    def record_license_redemption(
        self,
        serial_id: str,
        hwid: str,
        token: str = "",
        user_id: int = 0,
        username: str = "",
        client_name: str = "",
        plan_tier: str = "Pro",
        duration_days: int = 30,
        billing_cycle: str = "Monthly",
    ) -> Dict[str, Any]:
        """Records single-use license redemption."""
        now_str = datetime.now().isoformat()
        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO license_redemptions (license_id, hwid, username, client_name, tier, duration_days, redeemed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(license_id) DO UPDATE SET
                    hwid = EXCLUDED.hwid,
                    redeemed_at = EXCLUDED.redeemed_at
                """,
                (serial_id.strip(), hwid.strip(), username, client_name, plan_tier, duration_days, now_str),
            )
        return {
            "license_id": serial_id,
            "hwid": hwid,
            "username": username,
            "client_name": client_name,
            "tier": plan_tier,
            "redeemed_at": now_str,
        }
