"""The Response object, shaped after requests.Response so callers who know
requests need learn nothing new."""

import json as _json
from http.cookiejar import CookieJar


class Response:
    """A completed HTTP response returned by a Session.

    Mirrors the fields the Go core sends back (see cffi_src/types.go Response):
    status, body, headers, cookies, the final URL, and the negotiated
    protocol.
    """

    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = payload.get("status", 0)
        self.text = payload.get("body", "")
        self.url = payload.get("target", "")
        # The wire protocol actually used, e.g. "HTTP/2.0" or "h3". This has no
        # requests equivalent; it is one of the more useful things to check.
        self.protocol = payload.get("usedProtocol", "")
        self.headers = payload.get("headers", {}) or {}
        self.cookies = payload.get("cookies", {}) or {}
        self.session_id = payload.get("sessionId")
        self.id = payload.get("id")

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def content(self) -> bytes:
        return self.text.encode("utf-8")

    def json(self, **kwargs):
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> "Response":
        if not self.ok:
            raise RuntimeError(f"{self.status_code} for {self.url}")
        return self

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] {self.protocol}>"


def build_response(payload: dict, cookie_jar: CookieJar = None) -> Response:
    return Response(payload)
