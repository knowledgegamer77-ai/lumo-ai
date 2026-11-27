"""
========================================================================================
            LUMO AI | PAYMENT PROVIDER ABSTRACT BASE INTERFACE
========================================================================================
Pluggable gateway adapter contract for hosted checkouts, webhook signature verification,
and normalized event ingestion.
========================================================================================
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class WebhookEventData:
    event_id: str
    order_id: str
    event_type: str
    status: str  # PAID, FAILED, REFUNDED
    amount: float  # In PKR
    currency: str  # PKR
    is_paid: bool
    is_refund: bool
    raw_data: Dict[str, Any]
    tracker: str = ""


class BasePaymentProvider(ABC):
    @abstractmethod
    def create_checkout_session(
        self,
        order_id: str,
        amount_pkr: int,
        email: str,
        plan: str,
        cycle: str,
    ) -> str:
        """
        Creates a payment session / tracker with the gateway and returns the customer checkout URL.
        """
        pass

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
        Creates a payment session and returns rich metadata including checkout_url and tracker.
        """
        return {
            "checkout_url": self.create_checkout_session(order_id, amount_pkr, email, plan, cycle),
            "tracker": "",
        }

    @abstractmethod
    def verify_webhook(
        self,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verifies the gateway's cryptographic signature against the raw request body.
        Returns: (is_valid: bool, error_message: Optional[str])
        """
        pass

    @abstractmethod
    def parse_webhook_event(
        self,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> WebhookEventData:
        """
        Normalizes gateway-specific webhook payload into a standardized WebhookEventData instance.
        """
        pass
