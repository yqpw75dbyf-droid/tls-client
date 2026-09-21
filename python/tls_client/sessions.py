"""A requests-style Session backed by the tls-client Go core.

The Session keeps a session id so the Go side reuses one client (its cookie
jar, its connections) across requests, and frees the C strings the core hands
back. Module-level get/post/... at the bottom spin up a throwaway session for
one-off calls, the way httpcloak's top-level helpers do.
"""

import ctypes
import json
import urllib.parse
import uuid
from typing import Any, Optional, Union

from . import cffi
from .headers import browser_headers, resolve_preset
from .response import Response, build_response

_METHODS_WITH_BODY = {"POST", "PUT", "PATCH", "DELETE"}


class TLSClientError(Exception):
    """Raised when the Go core reports a failure (status 0 with the error in
    the body) or when arguments are invalid."""


def _call(cfunc, payload: dict) -> dict:
    """Send a JSON payload to a C function, parse the reply, free its memory."""
    raw = cfunc(json.dumps(payload).encode("utf-8"))
    parsed = json.loads(ctypes.string_at(raw).decode("utf-8"))
    response_id = parsed.get("id")
    if response_id:
        cffi.free_memory(response_id.encode("utf-8"))
    return parsed


class Session:
    def __init__(
        self,
        client_identifier: str = "chrome_153",
        *,
        preset: Optional[str] = None,
        ja3_string: Optional[str] = None,
        h2_settings: Optional[dict] = None,
        h2_settings_order: Optional[list] = None,
        supported_signature_algorithms: Optional[list] = None,
        supported_versions: Optional[list] = None,
        key_share_curves: Optional[list] = None,
        cert_compression_algo: Optional[str] = None,
        pseudo_header_order: Optional[list] = None,
        connection_flow: Optional[int] = None,
        header_order: Optional[list] = None,
        headers: Optional[dict] = None,
        default_headers: bool = True,
        proxy: Optional[str] = None,
        proxies: Optional[Union[str, dict]] = None,
        timeout_seconds: int = 30,
        random_tls_extension_order: Optional[bool] = None,
        force_http1: bool = False,
        disable_http3: bool = False,
        disable_session_tickets: bool = False,
        protocol_racing: bool = False,
        catch_panics: bool = False,
        debug: bool = False,
    ):
        # preset is the httpcloak-flavoured alias for client_identifier. A
        # family name ("chrome", "safari"...) or "random" picks a concrete
        # version here, once per Session, like primp's impersonate="random".
        identifier = preset or client_identifier
        self.custom = ja3_string is not None
        if not self.custom:
            try:
                identifier = resolve_preset(identifier)
            except KeyError:
                raise TLSClientError(
                    f"unknown client identifier {identifier!r}. "
                    "See tls_client.CLIENT_IDENTIFIERS for the full list, "
                    "a family name or 'random', or pass ja3_string=... "
                    "to build a custom profile."
                ) from None

        # The real browser's navigation headers, in its order, so the header
        # layer tells the same story as the handshake. Caller headers override
        # by name; header_order, if given, wins outright.
        defaults = browser_headers(identifier) if default_headers and not self.custom else None
        if defaults:
            merged = dict(defaults)
            for k, v in (headers or {}).items():
                merged[k.lower()] = v
            headers = merged
            header_order = header_order or list(defaults)

        self.session_id = str(uuid.uuid4())
        self.client_identifier = identifier
        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algo = cert_compression_algo
        self.pseudo_header_order = pseudo_header_order
        self.connection_flow = connection_flow
        self.header_order = header_order
        self.headers = dict(headers) if headers else {}
        # Accept both httpcloak's `proxy=` and requests' `proxies=`.
        self.proxy = _normalize_proxy(proxy, proxies)
        self.timeout_seconds = timeout_seconds
        # Chromium shuffles its TLS extension order on every connection, so a
        # Chromium preset with a fixed order sends the same JA3 forever and is
        # flagged for it. Safari, Firefox and Tor never shuffle, so shuffling
        # them is the tell instead. Default to what the real engine does;
        # an explicit True/False always wins.
        if random_tls_extension_order is None:
            random_tls_extension_order = _shuffles_by_default(identifier) if not self.custom else False
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.disable_http3 = disable_http3
        self.disable_session_tickets = disable_session_tickets
        self.protocol_racing = protocol_racing
        self.catch_panics = catch_panics
        self.debug = debug
        self._closed = False

    # -- context manager ---------------------------------------------------
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            _call(cffi.destroy_session, {"sessionId": self.session_id})
            self._closed = True

    # -- cookies -----------------------------------------------------------
    def get_cookies(self, url: str) -> dict:
        parsed = _call(cffi.get_cookies_from_session, {"sessionId": self.session_id, "url": url})
        return {c["name"]: c["value"] for c in parsed.get("cookies") or []}

    def set_cookies(self, url: str, cookies: dict) -> dict:
        payload = {
            "sessionId": self.session_id,
            "url": url,
            "cookies": [{"name": k, "value": v} for k, v in cookies.items()],
        }
        parsed = _call(cffi.add_cookies_to_session, payload)
        return {c["name"]: c["value"] for c in parsed.get("cookies") or []}

    # -- requests ----------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[Union[str, bytes, dict]] = None,
        json: Optional[Any] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        allow_redirects: bool = True,
        insecure_skip_verify: bool = False,
        timeout_seconds: Optional[int] = None,
        proxy: Optional[str] = None,
    ) -> Response:
        if self._closed:
            raise TLSClientError("session is closed")

        method = method.upper()
        if params:
            sep = "&" if urllib.parse.urlparse(url).query else "?"
            url = f"{url}{sep}{urllib.parse.urlencode(params, doseq=True)}"

        merged_headers = {**self.headers, **(headers or {})}
        body, is_byte_request, content_type = _encode_body(method, data, json)
        if content_type and not _has_header(merged_headers, "content-type"):
            merged_headers["Content-Type"] = content_type

        payload = {
            "sessionId": self.session_id,
            "requestUrl": url,
            "requestMethod": method,
            "headers": merged_headers,
            "headerOrder": self.header_order or [],
            "requestBody": body,
            "isByteRequest": is_byte_request,
            "requestCookies": [{"name": k, "value": v} for k, v in (cookies or {}).items()],
            "followRedirects": allow_redirects,
            "insecureSkipVerify": insecure_skip_verify,
            "timeoutSeconds": timeout_seconds or self.timeout_seconds,
            "proxyUrl": proxy if proxy is not None else self.proxy,
            "withRandomTLSExtensionOrder": self.random_tls_extension_order,
            "forceHttp1": self.force_http1,
            "disableHttp3": self.disable_http3,
            "disableSessionTickets": self.disable_session_tickets,
            "withProtocolRacing": self.protocol_racing,
            "catchPanics": self.catch_panics,
            "withDebug": self.debug,
        }

        if self.custom:
            payload["customTlsClient"] = self._custom_client()
        else:
            payload["tlsClientIdentifier"] = self.client_identifier

        parsed = _call(cffi.request, payload)
        if parsed.get("status", 0) == 0:
            raise TLSClientError(parsed.get("body") or "request failed with status 0")
        return build_response(parsed)

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def _custom_client(self) -> dict:
        client = {"ja3String": self.ja3_string}
        optional = {
            "h2Settings": self.h2_settings,
            "h2SettingsOrder": self.h2_settings_order,
            "supportedSignatureAlgorithms": self.supported_signature_algorithms,
            "supportedVersions": self.supported_versions,
            "keyShareCurves": self.key_share_curves,
            "certCompressionAlgo": self.cert_compression_algo,
            "pseudoHeaderOrder": self.pseudo_header_order,
            "connectionFlow": self.connection_flow,
        }
        client.update({k: v for k, v in optional.items() if v is not None})
        return client


_CHROMIUM_PREFIXES = ("chrome_", "chromium_", "opera_", "edge_", "brave_")


def _shuffles_by_default(identifier: str) -> bool:
    """True for engines that randomize TLS extension order per connection."""
    return identifier.startswith(_CHROMIUM_PREFIXES)


def _normalize_proxy(proxy: Optional[str], proxies: Optional[Union[str, dict]]) -> str:
    if proxy:
        return proxy
    if isinstance(proxies, str):
        return proxies
    if isinstance(proxies, dict):
        return proxies.get("https") or proxies.get("http") or ""
    return ""


def _has_header(headers: dict, name: str) -> bool:
    return any(k.lower() == name for k in headers)


def _encode_body(method, data, json_body):
    """Return (body_string, is_byte_request, content_type)."""
    if json_body is not None:
        return json.dumps(json_body), False, "application/json"
    if data is None:
        return "", False, None
    if isinstance(data, dict):
        return urllib.parse.urlencode(data, doseq=True), False, "application/x-www-form-urlencoded"
    if isinstance(data, bytes):
        # The Go core base64-decodes byte requests, so send it base64 encoded.
        import base64

        return base64.b64encode(data).decode("ascii"), True, None
    return str(data), False, None


# -- module-level one-off helpers (httpcloak style) -----------------------
def request(method: str, url: str, *, preset: str = "chrome_153", **kwargs) -> Response:
    session_kwargs = {}
    for key in ("proxy", "proxies", "header_order", "headers", "default_headers",
                "force_http1", "disable_http3", "random_tls_extension_order", "timeout_seconds"):
        if key in kwargs:
            session_kwargs[key] = kwargs.pop(key)
    with Session(preset=preset, **session_kwargs) as session:
        return session.request(method, url, **kwargs)


def get(url: str, **kwargs) -> Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs) -> Response:
    return request("POST", url, **kwargs)


def put(url: str, **kwargs) -> Response:
    return request("PUT", url, **kwargs)


def patch(url: str, **kwargs) -> Response:
    return request("PATCH", url, **kwargs)


def delete(url: str, **kwargs) -> Response:
    return request("DELETE", url, **kwargs)


def head(url: str, **kwargs) -> Response:
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs) -> Response:
    return request("OPTIONS", url, **kwargs)
