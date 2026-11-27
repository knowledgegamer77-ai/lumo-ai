from typing import Dict, Type

from payment_server.providers.base import BasePaymentProvider, WebhookEventData
from payment_server.providers.payfast import PayFastPaymentProvider
from payment_server.providers.safepay import SafepayPaymentProvider

PROVIDERS: Dict[str, Type[BasePaymentProvider]] = {
    "safepay": SafepayPaymentProvider,
    "payfast": PayFastPaymentProvider,
}


def get_payment_provider(name: str = "safepay") -> BasePaymentProvider:
    provider_cls = PROVIDERS.get(name.lower().strip())
    if not provider_cls:
        raise ValueError(f"Unsupported payment provider: '{name}'. Supported: {list(PROVIDERS.keys())}")
    return provider_cls()
