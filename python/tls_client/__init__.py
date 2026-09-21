"""tls_client — Python bindings for the tls-client Go core.

    import tls_client

    r = tls_client.get("https://tls.peet.ws/api/all", preset="chrome_153")
    print(r.status_code, r.protocol)

    with tls_client.Session(preset="firefox_135") as s:
        s.get("https://example.com")

The heavy lifting is done by a compiled Go shared library; see cffi.py for how
to build and locate it.
"""

from .headers import BROWSER_FAMILIES, browser_headers, resolve_preset
from .response import Response
from .sessions import (
    Session,
    TLSClientError,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
)
from .settings import CLIENT_IDENTIFIERS

__all__ = [
    "Session",
    "Response",
    "TLSClientError",
    "CLIENT_IDENTIFIERS",
    "BROWSER_FAMILIES",
    "browser_headers",
    "resolve_preset",
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
]

__version__ = "1.27.0"
