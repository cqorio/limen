"""A ``Verifier`` for Cloudflare Turnstile — ONE bundled example of the port, not a requirement. It uses only
the standard library (``urllib``), so it needs no extra. Wire your own ``Verifier`` for hCaptcha/reCAPTCHA/an
emailed code just as easily, or wire none and handle ``CHALLENGE`` yourself.

    from limen.adapters import TurnstileVerifier
    verifier = TurnstileVerifier(secret="0x...")   # your Turnstile secret key
    verifier.verify(token_from_widget)  # -> True/False
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

_SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


class TurnstileVerifier:
    def __init__(self, secret: str, url: str = _SITEVERIFY, timeout: float = 5.0) -> None:
        self.secret = secret
        self.url = url
        self.timeout = timeout

    def verify(self, token: str) -> bool:
        """POST the token to Cloudflare's siteverify and return whether it passed. Fails CLOSED (returns
        False) on a network/parse error — an unverifiable challenge is not a passed challenge."""
        if not token:
            return False
        data = urllib.parse.urlencode({"secret": self.secret, "response": token}).encode()
        try:
            with urllib.request.urlopen(self.url, data=data, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
            return bool(payload.get("success"))
        except Exception:
            return False
