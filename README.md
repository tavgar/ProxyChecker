# ⚠️ Disclaimer

**This tool is intended solely for educational and research purposes.**
**Do not use it to scan or access networks, systems, or devices without explicit authorization.**
Unauthorized scanning may violate laws or terms of service and could result in penalties or legal action.
**Use responsibly and only on networks you own or are permitted to test.**

---

# ProxyChecker

A blazing-fast, `epoll`-based, multi-threaded proxy checker written in C++20.

* Verification model:

  * HTTP proxies: validate via HTTP CONNECT to the target (default: google.com:80 - the most reliable test host). For cleartext test services on port 80, the checker performs an HTTP GET through the proxy. When using services that return client IP (like `ifconfig.io`), it requires the returned public IP differs from the client's baseline IP to avoid false positives.
  * SOCKS4/5: perform CONNECT to the target; if the target is port 80, send an HTTP HEAD request
* Supports HTTP, SOCKS4, SOCKS5 with automatic retry mechanism
* Highly parallel with per-thread `epoll` and sharded inputs
* Conservative timeouts (5s/8s/12s) and enhanced socket tuning for reliability

## Build

```bash
make -C ProxyChecker -j
```

## Scan the Internet

**Theoretically**, you can scan the entire Internet searching for public proxies:

```bash
./proxychecker --range 0.0.0.0/0 --workers 12 --concurrency 100000 --timeout 20 --scan-all-ports
```

## Usage
### Basic
#### For a range:
```
./proxychecker --range 192.168.0.1/18 --out good.txt
```
#### For a list
```
./proxychecker --in proxies_list.txt --out good.txt
```
#### For a list of ranges

```
./proxychecker --range-file proxies_list.txt --out good.txt
```

### Advanced options

```bash
# From a list file
./proxychecker --in proxies.txt --out good.txt \
  --workers 8 --concurrency 1024 \
  --test-host google.com --test-port 80 --test-path / \
  --timeout 5 \
  --default-proto http --http-mode connect

# Scan an IP range in CIDR on common proxy ports
./proxychecker --range 104.20.15.0/24 --out good_from_range.txt \
  --workers 8 --concurrency 1024 \
  --timeout 5

# Scan multiple CIDR ranges from a file
# range_list.txt (example):
# 104.28.234.240/30
# 104.28.234.244/32
# 104.28.246.42/31
# 109.224.208.0/21
# 109.238.144.0/20
./proxychecker --range-file range_list.txt --out good_from_ranges.txt \
  --workers 8 --concurrency 1024 \
  --timeout 5

# Scan all ports (1–65535) for each IP in a range
./proxychecker --range 10.0.0.0/30 --scan-all-ports --out good_full_scan.txt \
  --workers 12 --concurrency 25000 --timeout 5

# Example: scan ranges from a file across all ports with custom worker/concurrency
./proxychecker --range-file 212.txt --scan-all-ports --workers 12 --concurrency 25000 --timeout 5 --out good_full_scan_from_file.txt

# Use retry mechanism for better reliability
./proxychecker --in proxies.txt --out good.txt \
  --max-retries 2 --timeout 8

# Test all protocols even when default is specified
./proxychecker --in proxies.txt --out good.txt \
  --default-proto http --multi-protocol

# Disable strict IP masking validation (useful for Google and other hosts)
./proxychecker --in proxies.txt --out good.txt \
  --test-host google.com --disable-ip-masking
```

### HTTP proxy validation and reliability features

When verifying HTTP proxies against test services on port 80 (default: `--test-host google.com --test-port 80`), the checker includes several reliability enhancements:

#### IP Masking Validation (for IP-returning services)
For test services that return client IP (like `ifconfig.io`), the checker performs enhanced validation:
- Establishes the proxy connection (HTTP CONNECT if applicable)
- Sends an HTTP GET to the test service through the proxy
- Extracts the first IPv4 address from the response body and compares it to the client's baseline public IP
- The proxy is considered valid only if the response contains an IP that differs from the baseline IP
- Supports fallback IP services (`ifconfig.me`, `ifconfig.io`, `icanhazip.com`, `checkip.amazonaws.com`) if primary service fails

#### Google.com Compatibility (Most Reliable Default)
Google.com is the default test host because it's the most reliable and globally available service. It doesn't return client IP, so the checker:
- Accepts any successful HTTP response (2xx/3xx) as validation
- Handles bot detection redirects gracefully
- Uses `--disable-ip-masking` automatically for google.com
- Provides consistent global availability and minimal downtime

#### Retry Mechanism
- Automatic retry with increased timeouts for failed connections
- Configurable with `--max-retries N` (default: 1)
- Helps handle temporary network issues and rate limiting

Example usage with enhanced reliability:

```bash
# Standard Google validation (no IP masking needed)
./proxychecker --range-file ipranges.txt \
  --workers 4 --concurrency 10000 \
  --timeout 5 --max-retries 2 \
  --out good.txt

# IP masking validation with ifconfig.io
./proxychecker --range-file ipranges.txt \
  --workers 4 --concurrency 10000 \
  --timeout 5 --max-retries 1 \
  --test-host ifconfig.io --test-port 80 \
  --out good.txt
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

**Protocol handling and new options:**

* **Default behavior**: If a line is `ip:port` without a protocol, the checker tries all supported protocols and HTTP methods for that endpoint in parallel:
  * HTTP CONNECT
  * HTTP DIRECT (absolute-form HEAD request)
  * SOCKS5 CONNECT
  * SOCKS4 CONNECT

* **With `--default-proto`**: Only the specified protocol is tested for lines without explicit protocol

* **Explicit protocol**: Lines with explicit protocol (`http://`, `socks4://`, `socks5://` or `,proto`) use only that protocol

**New CLI options for enhanced control:**

* `--max-retries N`: Maximum retry attempts for failed connections (default: 1)
* `--disable-ip-masking`: Disable IP masking validation (useful for Google, default for google.com)
* `--strict`: Enable strict validation requiring body IP for port 80 (default: enabled)
* `--no-strict`: Accept any 2xx response as success, disable strict validation

**Notes on correctness and reliability:**

* Plain web servers on port 80/443 may respond to raw HTTP but are not proxies
* The tool now uses conservative timeouts (5s/8s/12s) instead of aggressive ones for better reliability
* Reduced default concurrency (1024 vs 2048) prevents resource exhaustion under load
* Enhanced buffer management (128KB) and TCP keepalive improve connection stability
* Automatic retry mechanism handles temporary failures and rate limiting
* Google.com testing (default) provides the most reliable connectivity validation worldwide without IP masking requirements

---

## Repository and Build

**Clean repository structure:**
* Enhanced `.gitignore` prevents build artifacts, output files, and temporary files from being tracked
* Build artifacts (`proxychecker` binary, `build/` directory) are automatically excluded
* Output files (`*.txt`, `*.log`) and IDE files are ignored
* Use `make clean` to remove all build artifacts

**Build requirements:**
* C++20 compatible compiler (GCC recommended)
* Linux with `epoll` support
* Make utility

```bash
# Clean build
make clean && make -j

# Build with custom optimization
CXXFLAGS="-O2 -g" make
```

---

## Notes

* Only numeric IPs are resolved currently to avoid DNS overhead. Add hostnames with caution
* Requires a high `ulimit -n`; the program attempts to raise it automatically
* Designed for Linux with `epoll`
* Recent improvements focus on reliability over raw speed, with conservative timeouts and retry mechanisms
