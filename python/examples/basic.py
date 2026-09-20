"""Basic usage. Build the shared library first (see ../README.md), then run:

    python examples/basic.py
"""

import tls_client

# One-off request, httpcloak style.
r = tls_client.get("https://tls.peet.ws/api/all", preset="chrome_153")
print("one-off:", r.status_code, r.protocol)

# A session keeps cookies and connections across requests.
with tls_client.Session(preset="firefox_135") as session:
    session.headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
    }
    session.header_order = ["user-agent", "accept", "accept-language"]

    resp = session.get("https://tls.peet.ws/api/all")
    print("session:", resp.status_code, resp.protocol)
    print("ja4:", resp.json()["tls"]["ja4"])

    resp = session.post("https://httpbin.org/post", json={"hello": "world"})
    print("post echoed:", resp.json()["json"])

# Tor Browser 15 through a local Tor daemon (see tor profile notes).
with tls_client.Session(
    preset="tor_15_0",
    proxy="socks5://127.0.0.1:9150",
    disable_http3=True,
) as tor:
    print("tor:", tor.get("https://check.torproject.org/api/ip").text)
