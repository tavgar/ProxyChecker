# ProxyChecker

A blazing-fast, epoll-based, multi-threaded proxy checker written in C++20.

- Two-stage verification: fast handshake + full HTTP verification
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
  --test-host example.com --test-port 80 --test-path / \
  --connect-timeout 300 --handshake-timeout 500 --request-timeout 800 \
  --default-proto http
```

Input file format:
- `ip:port`
- `proto://ip:port` where proto in `http`, `socks4`, `socks5`
- Or `ip:port,proto`

Output file contains one working proxy per line in `proto://ip:port` format.

## Notes

- Only numeric IPs are resolved currently to avoid DNS overhead. Add hostnames with caution.
- Requires high `ulimit -n`; the program attempts to raise it.
- Designed for Linux with `epoll`.

