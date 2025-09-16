# ProxyChecker

**ProxyChecker** is a high-speed tool that takes a list of proxies in the `ip:port` format and quickly identifies which ones are working.

## How It Works

ProxyChecker performs a two-stage check on each proxy:

1. **Fast preliminary check** — Establishes a TCP connection and performs a minimal protocol handshake (HTTP `HEAD` or SOCKS handshake) to quickly discard dead proxies.
2. **Full verification** — Sends an HTTP request through the proxy to known websites and marks the proxy as working only if a `200 OK` response is received.

This approach makes it possible to test **thousands of proxies in just a few seconds**.

## Why It’s Special

* **Blazing fast** — Highly parallelized and optimized for speed.
* **Reliable** — Verifies both connectivity and actual data forwarding.
* **Cross-protocol** — Supports , , and  proxies.
* **Written in ** — Delivers maximum performance and minimal overhead.

