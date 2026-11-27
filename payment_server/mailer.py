"""
========================================================================================
            LUMO AI | CUSTOMER LICENSE DISPATCH MAILER (SMTP)
========================================================================================
Sends customer purchase confirmation and cryptographically signed license keys via SMTP.
========================================================================================
"""

import html
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from payment_server.config import (
    COMPANY_NAME,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASS,
    SMTP_PORT,
    SMTP_USER,
    SUPPORT_EMAIL,
)

logger = logging.getLogger("payment_server.mailer")


def send_license_email(
    to_email: str,
    order_id: str,
    plan: str,
    cycle: str,
    token: str,
) -> bool:
    """
    Sends the customer their license key via SMTP.
    If SMTP credentials are not configured, logs a notice and returns False without failing.
    """
    if not SMTP_HOST or not to_email:
        logger.info(
            f"SMTP not configured or no recipient. Skipping email delivery for order {order_id} to {to_email}."
        )
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Your {COMPANY_NAME} {plan.upper()} License Key (Order #{order_id})"
        msg["From"] = SMTP_FROM or "billing@lumo.pro"
        msg["To"] = to_email

        text_body = (
            f"Hello,\n\n"
            f"Thank you for your purchase of {COMPANY_NAME} ({plan.capitalize()} Plan, {cycle.capitalize()})!\n\n"
            f"Your order #{order_id} has been verified and your single-device license key is ready:\n\n"
            f"{token}\n\n"
            f"To activate:\n"
            f"1. Open {COMPANY_NAME} Desktop App\n"
            f"2. Go to Plans & Billing -> Enter License Key\n"
            f"3. Paste the key above and click Activate\n\n"
            f"Need help? Contact {SUPPORT_EMAIL}\n\n"
            f"Best regards,\n"
            f"{COMPANY_NAME}"
        )

        safe_order = html.escape(order_id)
        safe_plan = html.escape(plan.capitalize())
        safe_cycle = html.escape(cycle.capitalize())
        safe_token = html.escape(token)
        safe_company = html.escape(COMPANY_NAME)
        safe_support = html.escape(SUPPORT_EMAIL)

        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: auto; padding: 24px; border: 1px solid #E2E8F0; border-radius: 12px; background: #FFFFFF;">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #0F172A; margin: 0;">Welcome to {safe_company} {safe_plan}</h2>
                <p style="color: #64748B; font-size: 14px; margin-top: 6px;">Order ID: <b>{safe_order}</b> ({safe_cycle} Billing)</p>
            </div>
            <div style="background: #F8FAFC; border: 1px solid #CBD5E1; border-radius: 8px; padding: 16px; margin: 20px 0;">
                <div style="font-size: 12px; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 8px;">Your Single-Device Activation Token:</div>
                <code style="display: block; background: #0F172A; color: #10B981; padding: 12px; border-radius: 6px; font-size: 13px; word-break: break-all;">{safe_token}</code>
            </div>
            <p style="font-size: 14px; color: #334155; line-height: 1.6;">
                <b>How to Activate:</b><br>
                1. Open the <b>{safe_company} Desktop App</b> on your licensed machine.<br>
                2. Navigate to <b>Plans &amp; Billing</b>.<br>
                3. Paste the activation token above into the license box and click <b>Activate License</b>.
            </p>
            <div style="border-top: 1px solid #E2E8F0; margin-top: 24px; padding-top: 16px; font-size: 12px; color: #94A3B8; text-align: center;">
                Need help? Contact support at <b>{safe_support}</b>.
            </div>
        </div>
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10.0) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        logger.info(f"License key email sent successfully for order {order_id} to {to_email}.")
        return True

    except Exception as e:
        logger.error(f"Failed to send license email for order {order_id} to {to_email}: {e}")
        return False
