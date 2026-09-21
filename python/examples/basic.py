"""Basic usage. Build the shared library first (see ../README.md), then run:

    python examples/basic.py
"""

import tls_client

# One-off request, httpcloak style.
r = tls_client.get("https://tls.peet.ws/api/all", preset="chrome_153")
print("one-off:", r.status_code, r.protocol)

# A session keeps cookies and connections across requests. A family name
# picks a recent version at random, and the browser's real headers (user-agent,
# sec-ch-ua, accept-*, sec-fetch-*, in its order) come with the preset.
with tls_client.Session(preset="random") as session:
    print("picked:", session.client_identifier, session.headers["user-agent"])

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
