# ProxyChecker

A blazing-fast, epoll-based, multi-threaded proxy checker written in C++20.

- Verification model:
  - HTTP proxies: validate via HTTP CONNECT to the target (default: 443)
  - SOCKS4/5: perform CONNECT to the target; if target is 80, send HTTP HEAD
- Supports HTTP, SOCKS4, SOCKS5
- Highly parallel with per-thread epoll and sharded inputs
- Aggressive timeouts and socket tuning for speed

## Build

```bash
make -C ProxyChecker -j
```

## Usage

```bash
./proxychecker --in proxies.txt --out good.txt \
  --workers 8 --concurrency 4096 \
  --test-host ifconfig.io --test-port 443 --test-path / \
  --connect-timeout 300 --handshake-timeout 500 --request-timeout 800 \
  --default-proto http --http-mode connect
```

Input file format:
- `ip:port`
- `proto://ip:port` where proto in `http`, `socks4`, `socks5`
- Or `ip:port,proto`

Output file contains one working proxy per line in `proto://ip:port` format.

Behavior when protocol is omitted:
- If a line is `ip:port` without a protocol, the checker will try all supported protocols and HTTP methods for that endpoint in parallel:
  - HTTP CONNECT
  - HTTP DIRECT (absolute-form HEAD request)
  - SOCKS5 CONNECT
  - SOCKS4 CONNECT
- In this case, the `--default-proto` flag is ignored for that line.
- If the input specifies protocol explicitly (`http://`, `socks4://`, `socks5://` or trailing `,proto`), only that protocol is attempted. For HTTP with explicit protocol, the HTTP mode is controlled by `--http-mode` (default `connect`).

Notes on correctness:
- Plain web servers on port 80/443 may respond to raw HTTP, but are not proxies.
- Using CONNECT to 443 avoids false positives by requiring proxy tunneling support.

## Notes

- Only numeric IPs are resolved currently to avoid DNS overhead. Add hostnames with caution.
- Requires high `ulimit -n`; the program attempts to raise it.
- Designed for Linux with `epoll`.

