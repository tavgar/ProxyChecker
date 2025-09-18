# ⚠️ Disclaimer

**This tool is intended solely for educational and research purposes.**
**Do not use it to scan or access networks, systems, or devices without explicit authorization.**
Unauthorized scanning may violate laws or terms of service and could result in penalties or legal action.
**Use responsibly and only on networks you own or are permitted to test.**

---

# ProxyChecker

A blazing-fast, `epoll`-based, multi-threaded proxy checker written in C++20.

* Verification model:

  * HTTP proxies: validate via HTTP CONNECT to the target (default: 443)
  * SOCKS4/5: perform CONNECT to the target; if the target is port 80, send an HTTP HEAD request
* Supports HTTP, SOCKS4, SOCKS5
* Highly parallel with per-thread `epoll` and sharded inputs
* Aggressive timeouts and socket tuning for speed

## Build

```bash
make -C ProxyChecker -j
```

## Scan the Internet

**Theoretically**, you can scan the entire Internet searching for public proxies:

```bash
./proxychecker --range 0.0.0.0/0 --workers 12 --concurrency 500000 --timeout 20 --scan-all-ports
```

## Usage

```bash
# From a list file
./proxychecker --in proxies.txt --out good.txt \
  --workers 8 --concurrency 4096 \
  --test-host ifconfig.io --test-port 443 --test-path / \
  --timeout 2 \
  --default-proto http --http-mode connect

# Scan an IP range in CIDR on common proxy ports
./proxychecker --range 104.20.15.0/24 --out good_from_range.txt \
  --workers 8 --concurrency 4096 \
  --timeout 2

# Scan multiple CIDR ranges from a file
# range_list.txt (example):
# 104.28.234.240/30
# 104.28.234.244/32
# 104.28.246.42/31
# 109.224.208.0/21
# 109.238.144.0/20
./proxychecker --range-file range_list.txt --out good_from_ranges.txt \
  --workers 8 --concurrency 4096 \
  --timeout 2

# Scan all ports (1–65535) for each IP in a range
./proxychecker --range 10.0.0.0/30 --scan-all-ports --out good_full_scan.txt \
  --workers 12 --concurrency 50000 --timeout 5

# Example: scan ranges from a file across all ports with custom worker/concurrency
./proxychecker --range-file 212.txt --scan-all-ports --workers 12 --concurrency 50000 --timeout 5 --out good_full_scan_from_file.txt
```

## Streaming generation for range scans

When using `--range` or `--range-file`, tasks are generated on the fly and fed through a bounded queue to worker threads. This avoids preallocating every IP/port/protocol combination in memory.

* By default, the queue capacity is `workers * concurrency * 2`. You can override this with `--queue-size N`.
* Progress is shown by IPs or ports depending on whether `--scan-all-ports` is used.
* This design prevents memory exhaustion when scanning large ranges or all ports (1–65535).

---

**Input file format:**

* `ip:port`
* `proto://ip:port` where `proto` is `http`, `socks4`, or `socks5`
* Or `ip:port,proto`

**Output file format:**

* One working proxy per line in `proto://ip:port` format.

**Range scanning:**

* Use `--range CIDR` (e.g., `10.0.0.0/24`) to enumerate all IPv4 addresses in the range and test common proxy ports:
  `80, 8080, 1080, 3128, 8888, 8000, 8081, 8082, 3129, 4145, 9999`
* Use `--range-file FILE` to provide multiple CIDR ranges, one per line.
* Use `--scan-all-ports` to scan all ports (1–65535) for each IP instead of only common ports.
* `--in`, `--range`, and `--range-file` are mutually exclusive.

**Real-time feedback:**

* Successful proxies are printed immediately, e.g., `Found: http://1.2.3.4:8080`.
* A dynamic progress bar updates counts of checked, succeeded, and failed proxies.

**Behavior when protocol is omitted:**

* If a line is `ip:port` without a protocol, the checker will try all supported protocols and HTTP methods for that endpoint in parallel:

  * HTTP CONNECT
  * HTTP DIRECT (absolute-form HEAD request)
  * SOCKS5 CONNECT
  * SOCKS4 CONNECT
* In this case, the `--default-proto` flag is ignored for that line.
* If the input specifies a protocol explicitly (`http://`, `socks4://`, `socks5://` or trailing `,proto`), only that protocol is attempted. For HTTP with an explicit protocol, the HTTP mode is controlled by `--http-mode` (default `connect`).

**Notes on correctness:**

* Plain web servers on port 80/443 may respond to raw HTTP but are not proxies.
* Using CONNECT to port 443 avoids false positives by requiring proxy tunneling support.

---

## Notes

* Only numeric IPs are resolved currently to avoid DNS overhead. Add hostnames with caution.
* Requires a high `ulimit -n`; the program attempts to raise it automatically.
* Designed for Linux with `epoll`.
