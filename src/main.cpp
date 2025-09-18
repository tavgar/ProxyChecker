#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

using std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::duration_cast;

namespace {

enum class Protocol : uint8_t {
	HTTP = 0,
	SOCKS4 = 1,
	SOCKS5 = 2,
};

enum class HttpMode : uint8_t {
	CONNECT = 0,
	DIRECT = 1,
};

static const char* protocolToString(Protocol p) {
	switch (p) {
		case Protocol::HTTP: return "http";
		case Protocol::SOCKS4: return "socks4";
		case Protocol::SOCKS5: return "socks5";
	}
	return "unknown";
}

struct ProxyTarget {
	Protocol protocol;
	std::string host; // numeric IP or hostname
	uint16_t port;
    // Optional per-target HTTP mode override (only used when protocol==HTTP)
    std::optional<HttpMode> httpModeOverride;
};

struct Settings {
	std::string inputFile;
	std::string outputFile; // final merged file
	std::string testHost = "example.com"; // remote host to HTTP HEAD via proxies
	uint16_t testPort = 443;
	std::string testPath = "/";
	int numWorkers = std::max(1, (int)std::thread::hardware_concurrency());
	int concurrencyPerWorker = 2048;
	int connectTimeoutMs = 2000; // improved for proxy reliability
	int handshakeTimeoutMs = 3000;
	int requestTimeoutMs = 5000;
	Protocol defaultProtocol = Protocol::HTTP;
	bool defaultProtocolForced = false; // true if --default-proto explicitly provided
	bool mergeOutputs = true;
	bool keepParts = false;
	bool quiet = false;
	int maxOpenFiles = 262144; // attempt to raise
	HttpMode httpMode = HttpMode::CONNECT;
    // Baseline public IP of this machine (fetched once when possible)
    std::string clientPublicIP;
    // New: CIDR range scanning (mutually exclusive with --in)
    std::string rangeCIDR;
    // New: multiple CIDR ranges from file (mutually exclusive with --in/--range)
    std::string rangeFile;
    // Progress customization for range/range-file: show per-IP totals
    bool ipProgressMode{false};
    uint64_t totalIpsForProgress{0};
    uint32_t sessionsPerIpForProgress{0};
	    // New: when enabled, scan all ports (1-65535) for each IP in range modes
	    bool scanAllPorts{false};
	    // Progress helpers for scan-all-ports mode
	    uint64_t totalPortsForProgress{0};
	    uint32_t sessionsPerPortForProgress{0};
	    // Bounded streaming queue capacity for range scans
	    int queueCapacity{0};
};

static inline uint64_t nowMs() {
	return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// Extract first IPv4 address from buffer; returns true if found
static bool extractFirstIPv4FromBuffer(const char* data, size_t len, std::string& out) {
    auto isDigit = [](char c){ return c >= '0' && c <= '9'; };
    for (size_t i = 0; i < len; ++i) {
        size_t p = i;
        int octets[4];
        bool ok = true;
        for (int oct = 0; oct < 4; ++oct) {
            if (p >= len || !isDigit(data[p])) { ok = false; break; }
            int val = 0; size_t digits = 0;
            while (p < len && isDigit(data[p]) && digits < 3) { val = val * 10 + (data[p] - '0'); ++p; ++digits; }
            if (val > 255) { ok = false; break; }
            if (digits == 0) { ok = false; break; }
            octets[oct] = val;
            if (oct < 3) {
                if (p >= len || data[p] != '.') { ok = false; break; }
                ++p;
            }
        }
        if (ok) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
            out.assign(buf);
            return true;
        }
    }
    return false;
}

static int setNonBlocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
	return 0;
}

static void tuneSocket(int fd) {
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	int buf = 1 << 16; // 64KB
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
}

static void logf(bool quiet, const char* fmt, ...) {
	if (quiet) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static bool parseUint16(const std::string& s, uint16_t& out) {
	char* end = nullptr;
	long v = strtol(s.c_str(), &end, 10);
	if (!end || *end != '\0') return false;
	if (v < 0 || v > 65535) return false;
	out = (uint16_t)v;
	return true;
}

static bool isWhitespace(char c) {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static std::string trim(const std::string& s) {
	size_t i = 0, j = s.size();
	while (i < j && isWhitespace(s[i])) ++i;
	while (j > i && isWhitespace(s[j - 1])) --j;
	return s.substr(i, j - i);
}

struct ParsedProxyLine {
	std::string host;
	uint16_t port{0};
	Protocol proto{Protocol::HTTP};
	bool explicitProto{false};
};

static std::optional<ParsedProxyLine> parseProxyLineDetailed(const std::string& line, Protocol defaultProto) {
	std::string s = trim(line);
	if (s.empty()) return std::nullopt;
	if (s[0] == '#') return std::nullopt;

	Protocol proto = defaultProto;
	bool explicitProto = false;
	std::string hostport;
	// Allow protocol://host:port
	if (s.rfind("socks5://", 0) == 0) {
		proto = Protocol::SOCKS5;
		explicitProto = true;
		hostport = s.substr(9);
	} else if (s.rfind("socks4://", 0) == 0) {
		proto = Protocol::SOCKS4;
		explicitProto = true;
		hostport = s.substr(9);
	} else if (s.rfind("http://", 0) == 0) {
		proto = Protocol::HTTP;
		explicitProto = true;
		hostport = s.substr(7);
	} else {
		hostport = s;
	}

	// Also support trailing ",proto"
	{
		size_t comma = hostport.find(',');
		if (comma != std::string::npos) {
			std::string p = trim(hostport.substr(comma + 1));
			hostport = trim(hostport.substr(0, comma));
			if (p == "socks5") { proto = Protocol::SOCKS5; explicitProto = true; }
			else if (p == "socks4") { proto = Protocol::SOCKS4; explicitProto = true; }
			else if (p == "http") { proto = Protocol::HTTP; explicitProto = true; }
		}
	}

	{
		std::istringstream iss(hostport);
		std::string host, portStr;
		if (hostport.size() && hostport[0] == '[') {
			// IPv6 [addr]:port
			size_t rb = hostport.find(']');
			if (rb == std::string::npos) return std::nullopt;
			host = hostport.substr(1, rb - 1);
			if (rb + 1 >= hostport.size() || hostport[rb + 1] != ':') return std::nullopt;
			portStr = hostport.substr(rb + 2);
		} else {
			size_t colon = hostport.rfind(':');
			if (colon == std::string::npos) return std::nullopt;
			host = hostport.substr(0, colon);
			portStr = hostport.substr(colon + 1);
		}
		host = trim(host);
		portStr = trim(portStr);
		if (host.empty() || portStr.empty()) return std::nullopt;
		uint16_t port = 0;
		if (!parseUint16(portStr, port)) return std::nullopt;
		return ParsedProxyLine{host, port, proto, explicitProto};
	}
}

struct Counters {
	std::atomic<uint64_t> total{0};
	std::atomic<uint64_t> started{0};
	std::atomic<uint64_t> succeeded{0};
	std::atomic<uint64_t> failed{0};
};

enum class SessionState : uint8_t {
	CONNECTING = 0,
	HTTP_CONNECT_SEND,
	HTTP_CONNECT_RECV,
	HTTP_SEND,
	HTTP_RECV,
	HTTP_TUNNEL_HTTP_SEND,
	HTTP_TUNNEL_HTTP_RECV,
	S5_METHOD_SEND,
	S5_METHOD_RECV,
	S5_CONNECT_SEND,
	S5_CONNECT_RECV,
	S4_CONNECT_SEND,
	S4_CONNECT_RECV,
	SOCKS_HTTP_SEND,
	SOCKS_HTTP_RECV,
	DONE,
	FAILED
};

struct Session {
	int fd{-1};
	Protocol proto{Protocol::HTTP};
	SessionState state{SessionState::CONNECTING};
	uint64_t deadlineMs{0};
	uint32_t deadlineVersion{0};
	std::string proxyHost;
	uint16_t proxyPort{0};
    std::optional<HttpMode> httpModeOverride; // honored when proto==HTTP
	bool requireIpMasking{false}; // for HTTP proxies when validating via testHost on port 80
	// Buffers
	std::string writeBuf;
	std::string readBuf;
	size_t writeOffset{0};
	// For parsing HTTP
	bool statusParsed{false};
	int statusCode{0};
	// Track header/body split when parsing HTTP for IP masking
	bool headersComplete{false};
	// Track whether the last HTTP request was GET (vs HEAD)
	bool lastWasGet{false};
	// For worker context
	class Worker* worker{nullptr};
};

static std::mutex g_printMutex;

// Simple bounded thread-safe queue for streaming tasks
class TaskQueue {
public:
    explicit TaskQueue(size_t capacity)
        : capacity_(capacity), closed_(false) {}

    bool push(ProxyTarget&& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_cv_.wait(lock, [&]{ return closed_ || queue_.size() < capacity_; });
        if (closed_) return false;
        queue_.push_back(std::move(item));
        not_empty_cv_.notify_one();
        return true;
    }

    bool try_pop(ProxyTarget& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        not_full_cv_.notify_one();
        return true;
    }

    bool wait_pop(ProxyTarget& out) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_cv_.wait(lock, [&]{ return closed_ || !queue_.empty(); });
        if (queue_.empty()) return false; // closed and empty
        out = std::move(queue_.front());
        queue_.pop_front();
        not_full_cv_.notify_one();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        not_empty_cv_.notify_all();
        not_full_cv_.notify_all();
    }

    bool isClosedAndEmpty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_ && queue_.empty();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable not_empty_cv_;
    std::condition_variable not_full_cv_;
    std::deque<ProxyTarget> queue_;
    size_t capacity_;
    bool closed_;
};

class Worker {
public:
    Worker(int id,
        const Settings& s,
        std::vector<ProxyTarget> proxies,
        Counters& counters)
        : id_(id), settings_(s), proxies_(std::move(proxies)), counters_(counters) {}

    Worker(int id,
        const Settings& s,
        std::shared_ptr<TaskQueue> queue,
        Counters& counters)
        : id_(id), settings_(s), counters_(counters), taskQueue_(std::move(queue)) {}

	void start() {
		thread_ = std::thread([this]() { this->run(); });
	}

	void join() {
		if (thread_.joinable()) thread_.join();
	}

private:
	int id_;
	Settings settings_;
	std::vector<ProxyTarget> proxies_;
    std::shared_ptr<TaskQueue> taskQueue_;
	Counters& counters_;
	std::thread thread_;
	int epfd_{-1};
	std::ofstream out_;
    uint64_t nextIndex_{0};
	uint32_t nextDeadlineVersion_{1};
	int active_{0};

	static constexpr int kMaxEvents = 4096;

	// Extract first IPv4 address from a text buffer; returns true and sets out if found
	static bool extractFirstIPv4(const char* data, size_t len, std::string& out) {
		auto isDigit = [](char c){ return c >= '0' && c <= '9'; };
		for (size_t i = 0; i < len; ++i) {
			// Try parse a.b.c.d starting at i
			size_t p = i;
			int octets[4];
			bool ok = true;
			for (int oct = 0; oct < 4; ++oct) {
				if (p >= len || !isDigit(data[p])) { ok = false; break; }
				int val = 0; size_t start = p; size_t digits = 0;
				while (p < len && isDigit(data[p]) && digits < 3) { val = val * 10 + (data[p] - '0'); ++p; ++digits; }
				if (val > 255) { ok = false; break; }
				if (digits == 0) { ok = false; break; }
				octets[oct] = val;
				if (oct < 3) {
					if (p >= len || data[p] != '.') { ok = false; break; }
					++p;
				}
			}
			if (ok) {
				char buf[16];
				snprintf(buf, sizeof(buf), "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
				out.assign(buf);
				return true;
			}
		}
		return false;
	}

    void run() {
		std::string outPath = settings_.outputFile.empty()
			? std::string()
			: (settings_.outputFile + "." + std::to_string(id_));
		if (!outPath.empty()) {
			out_.open(outPath, std::ios::out | std::ios::trunc);
		}

		epfd_ = epoll_create1(EPOLL_CLOEXEC);
		if (epfd_ < 0) {
			perror("epoll_create1");
			return;
		}

		// total is set upfront in main

        // Prime initial sessions
        refill();

		epoll_event events[kMaxEvents];
        while (active_ > 0 || (taskQueue_ && !taskQueue_->isClosedAndEmpty())) {
			int timeout = 10; // ms
			int n = epoll_wait(epfd_, events, kMaxEvents, timeout);
			if (n < 0) {
				if (errno == EINTR) continue;
				perror("epoll_wait");
				break;
			}
			for (int i = 0; i < n; ++i) {
				auto* sess = static_cast<Session*>(events[i].data.ptr);
				if (!sess) continue;
				if (events[i].events & (EPOLLERR | EPOLLHUP)) {
					failSession(sess);
					continue;
				}
				if (events[i].events & EPOLLOUT) {
					handleWritable(sess);
				}
				if (sess->state == SessionState::FAILED || sess->state == SessionState::DONE) continue;
				if (events[i].events & EPOLLIN) {
					handleReadable(sess);
				}
			}
			checkTimeouts();
            refill();
		}

		if (out_.is_open()) { out_.flush(); out_.close(); }
		if (epfd_ >= 0) close(epfd_);
	}

    void refill() {
        if (taskQueue_) {
            // Streaming mode
            while (active_ < settings_.concurrencyPerWorker) {
                ProxyTarget tgt;
                bool ok = false;
                if (active_ == 0) {
                    ok = taskQueue_->wait_pop(tgt);
                } else {
                    ok = taskQueue_->try_pop(tgt);
                }
                if (!ok) break;
                launch(tgt);
            }
        } else {
            // Preloaded vector mode
            while (active_ < settings_.concurrencyPerWorker && nextIndex_ < proxies_.size()) {
                launch(proxies_[nextIndex_++]);
            }
        }
    }

	void setEpoll(int fd, Session* sess, uint32_t events, bool add) {
		epoll_event ev{};
		ev.events = events;
		ev.data.ptr = sess;
		int op = add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
		if (epoll_ctl(epfd_, op, fd, &ev) < 0) {
			// Could be already closed
		}
	}

	void arm(Session* sess, bool wantRead, bool wantWrite) {
		uint32_t ev = 0;
		if (wantRead) ev |= EPOLLIN;
		if (wantWrite) ev |= EPOLLOUT;
		setEpoll(sess->fd, sess, ev, false);
	}

	void setDeadline(Session* sess, uint64_t msFromNow) {
		sess->deadlineMs = nowMs() + msFromNow;
		sess->deadlineVersion = nextDeadlineVersion_++;
	}

	void checkTimeouts() {
		uint64_t now = nowMs();
		// Iterate epoll set is not trivial; Keep a simple list? For speed, we forgo elaborate heap and use readBuf capacity as presence marker. Here we do a coarse approach: rely on event loop to progress and use per-operation timeouts by checking on writable/readable and on each iteration closing expired by scanning active sessions would be costly.
		// To avoid O(n^2), we piggy-back timeouts on IO: we set connect, handshake and request timeouts when arming; if EPOLL times out (no events) we opportunistically scan a bounded number.
		static thread_local size_t scanStart = 0;
		const size_t scanBatch = 1024;
		if (activeList_.empty()) return;
		size_t n = activeList_.size();
		size_t scanned = 0;
		for (; scanned < scanBatch && scanned < n; ++scanned) {
			size_t idx = (scanStart + scanned) % n;
			Session* sess = activeList_[idx];
			if (!sess) continue;
			if (sess->deadlineMs && now >= sess->deadlineMs) {
				failSession(sess);
			}
		}
		scanStart = (scanStart + scanned) % std::max<size_t>(1, n);
	}

	void removeFromActive(Session* sess) {
		// swap-erase from activeList_
		if (sess->fd >= 0) {
			epoll_ctl(epfd_, EPOLL_CTL_DEL, sess->fd, nullptr);
			close(sess->fd);
			sess->fd = -1;
		}
		for (size_t i = 0; i < activeList_.size(); ++i) {
			if (activeList_[i] == sess) {
				activeList_[i] = activeList_.back();
				activeList_.pop_back();
				break;
			}
		}
		delete sess;
		--active_;
	}

	void succeedSession(Session* sess) {
		counters_.succeeded.fetch_add(1, std::memory_order_relaxed);
		if (out_.is_open()) {
			out_ << protocolToString(sess->proto) << "://" << sess->proxyHost << ":" << sess->proxyPort << "\n";
		}
		{
			std::lock_guard<std::mutex> lock(g_printMutex);
			std::cout << "Found: " << protocolToString(sess->proto) << "://" << sess->proxyHost << ":" << sess->proxyPort << std::endl;
		}
		sess->state = SessionState::DONE;
		removeFromActive(sess);
	}

	void failSession(Session* sess) {
		counters_.failed.fetch_add(1, std::memory_order_relaxed);
		sess->state = SessionState::FAILED;
		removeFromActive(sess);
	}

	void launch(const ProxyTarget& tgt) {
		// Resolve numeric only (avoid DNS locally)
		addrinfo hints{};
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
		addrinfo* res = nullptr;
		char portStr[16];
		snprintf(portStr, sizeof(portStr), "%u", (unsigned)tgt.port);
		int gai = getaddrinfo(tgt.host.c_str(), portStr, &hints, &res);
		if (gai != 0) {
			// Skip non-numeric hosts; could add DNS resolve pool later
			counters_.failed.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		int fd = -1;
		for (addrinfo* ai = res; ai; ai = ai->ai_next) {
			fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
			if (fd < 0) continue;
			if (setNonBlocking(fd) != 0) { close(fd); fd = -1; continue; }
			tuneSocket(fd);
			int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
			if (rc == 0 || (rc < 0 && errno == EINPROGRESS)) {
				break;
			}
			close(fd);
			fd = -1;
		}
		freeaddrinfo(res);
		if (fd < 0) {
			counters_.failed.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		Session* sess = new Session();
		sess->fd = fd;
		sess->proto = tgt.protocol;
		sess->proxyHost = tgt.host;
		sess->proxyPort = tgt.port;
		sess->httpModeOverride = tgt.httpModeOverride;
		// For HTTP protocol, require masking when testing via HTTP on port 80
		sess->requireIpMasking = (tgt.protocol == Protocol::HTTP) && (settings_.testPort == 80);
		sess->worker = this;
		sess->state = SessionState::CONNECTING;
		sess->writeBuf.clear();
		sess->readBuf.clear();
		sess->writeOffset = 0;
		sess->statusParsed = false;
		sess->statusCode = 0;
		sess->headersComplete = false;
		sess->lastWasGet = false;

		epoll_event ev{};
		ev.events = EPOLLOUT; // wait connect complete
		ev.data.ptr = sess;
		if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
			close(fd);
			delete sess;
			counters_.failed.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		setDeadline(sess, settings_.connectTimeoutMs);
		activeList_.push_back(sess);
		++active_;
		counters_.started.fetch_add(1, std::memory_order_relaxed);
	}

	void handleWritable(Session* sess) {
		if (sess->state == SessionState::CONNECTING) {
			int err = 0; socklen_t len = sizeof(err);
			if (getsockopt(sess->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
				failSession(sess);
				return;
			}
			// Connected
				switch (sess->proto) {
				case Protocol::HTTP: {
					HttpMode mode = sess->httpModeOverride.has_value() ? *sess->httpModeOverride : settings_.httpMode;
						bool useConnect = (mode == HttpMode::CONNECT) || (settings_.testPort != 80);
					if (useConnect) {
						prepareHttpConnect(sess, settings_.testHost, settings_.testPort);
						sess->state = SessionState::HTTP_CONNECT_SEND;
						setDeadline(sess, settings_.handshakeTimeoutMs);
					} else {
							prepareHttpGet(sess, settings_.testHost, settings_.testPort, settings_.testPath);
							sess->state = SessionState::HTTP_SEND;
						setDeadline(sess, settings_.handshakeTimeoutMs);
					}
					break;
				}
				case Protocol::SOCKS5: prepareSocks5Method(sess); sess->state = SessionState::S5_METHOD_SEND; setDeadline(sess, settings_.handshakeTimeoutMs); break;
				case Protocol::SOCKS4: prepareSocks4Connect(sess, settings_.testHost, settings_.testPort); sess->state = SessionState::S4_CONNECT_SEND; setDeadline(sess, settings_.handshakeTimeoutMs); break;
			}
			arm(sess, /*read*/false, /*write*/true);
			return;
		}
		// Write pending buffer
		if (sess->writeOffset < sess->writeBuf.size()) {
			ssize_t n = ::send(sess->fd, sess->writeBuf.data() + sess->writeOffset, (size_t)std::min<size_t>(sess->writeBuf.size() - sess->writeOffset, 65536), MSG_NOSIGNAL);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					arm(sess, /*read*/false, /*write*/true);
					return;
				}
				failSession(sess);
				return;
			}
			sess->writeOffset += (size_t)n;
		}
		if (sess->writeOffset >= sess->writeBuf.size()) {
			// Move to expected read stage
		switch (sess->state) {
				case SessionState::HTTP_CONNECT_SEND: sess->state = SessionState::HTTP_CONNECT_RECV; setDeadline(sess, settings_.requestTimeoutMs); arm(sess, true, false); break;
				case SessionState::HTTP_SEND: sess->state = SessionState::HTTP_RECV; setDeadline(sess, settings_.requestTimeoutMs); arm(sess, true, false); break;
				case SessionState::HTTP_TUNNEL_HTTP_SEND: sess->state = SessionState::HTTP_TUNNEL_HTTP_RECV; setDeadline(sess, settings_.requestTimeoutMs); arm(sess, true, false); break;
				case SessionState::S5_METHOD_SEND: sess->state = SessionState::S5_METHOD_RECV; arm(sess, true, false); break;
				case SessionState::S5_CONNECT_SEND: sess->state = SessionState::S5_CONNECT_RECV; arm(sess, true, false); break;
				case SessionState::S4_CONNECT_SEND: sess->state = SessionState::S4_CONNECT_RECV; arm(sess, true, false); break;
				case SessionState::SOCKS_HTTP_SEND: sess->state = SessionState::SOCKS_HTTP_RECV; setDeadline(sess, settings_.requestTimeoutMs); arm(sess, true, false); break;
				default: break;
			}
		}
	}

	void handleReadable(Session* sess) {
		char buf[8192];
		ssize_t n = ::recv(sess->fd, buf, sizeof(buf), 0);
		if (n == 0) { failSession(sess); return; }
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			failSession(sess);
			return;
		}
		sess->readBuf.append(buf, (size_t)n);
		// Parse based on state
		switch (sess->state) {
			case SessionState::HTTP_CONNECT_RECV: parseHttpStatus(sess);
				break;
			case SessionState::HTTP_RECV: parseHttpStatus(sess);
				break;
			case SessionState::HTTP_TUNNEL_HTTP_RECV: parseHttpStatus(sess);
				break;
			case SessionState::S5_METHOD_RECV: parseSocks5Method(sess);
				break;
			case SessionState::S5_CONNECT_RECV: parseSocks5Connect(sess);
				break;
			case SessionState::S4_CONNECT_RECV: parseSocks4Connect(sess);
				break;
			case SessionState::SOCKS_HTTP_RECV: parseHttpStatus(sess);
				break;
			default:
				break;
		}
	}

	// Protocol helpers
	static void buildHttpConnect(std::string& out, const std::string& host, uint16_t port) {
		out.clear();
		std::string hostHeader = host + ":" + std::to_string(port);
		out += "CONNECT ";
		out += hostHeader;
		out += " HTTP/1.1\r\n";
		out += "Host: ";
		out += hostHeader;
		out += "\r\n";
		out += "Proxy-Connection: keep-alive\r\n";
		out += "Connection: keep-alive\r\n\r\n";
	}
	static void buildHttpHead(std::string& out, const std::string& host, uint16_t port, const std::string& path, bool absoluteForm) {
		out.clear();
		std::string hostHeader = host;
		if (!(port == 80 || port == 443)) hostHeader += ":" + std::to_string(port);
		if (absoluteForm) {
			out += "HEAD http://";
			out += hostHeader;
			out += path;
			out += " HTTP/1.1\r\n";
		} else {
			out += "HEAD ";
			out += path;
			out += " HTTP/1.1\r\n";
		}
		out += "Host: ";
		out += hostHeader;
		out += "\r\n";
		out += "User-Agent: ProxyChecker/0.1\r\n";
		out += "Connection: close\r\n\r\n";
	}
	static void buildHttpGet(std::string& out, const std::string& host, uint16_t port, const std::string& path, bool absoluteForm) {
		out.clear();
		std::string hostHeader = host;
		if (!(port == 80 || port == 443)) hostHeader += ":" + std::to_string(port);
		if (absoluteForm) {
			out += "GET http://";
			out += hostHeader;
			out += path;
			out += " HTTP/1.1\r\n";
		} else {
			out += "GET ";
			out += path;
			out += " HTTP/1.1\r\n";
		}
		out += "Host: ";
		out += hostHeader;
		out += "\r\n";
		out += "User-Agent: ProxyChecker/0.1\r\n";
		out += "Accept: text/plain, text/*;q=0.9, */*;q=0.1\r\n";
		out += "Connection: close\r\n\r\n";
	}

	void prepareHttpHead(Session* sess, const std::string& host, uint16_t port, const std::string& path) {
		buildHttpHead(sess->writeBuf, host, port, path, /*absoluteForm*/true);
		sess->writeOffset = 0;
		sess->readBuf.clear();
		sess->lastWasGet = false;
	}

	void prepareHttpConnect(Session* sess, const std::string& host, uint16_t port) {
		buildHttpConnect(sess->writeBuf, host, port);
		sess->writeOffset = 0;
		sess->readBuf.clear();
	}

	void prepareSocks5Method(Session* sess) {
		sess->writeBuf.resize(3);
		sess->writeBuf[0] = (char)0x05;
		sess->writeBuf[1] = (char)0x01;
		sess->writeBuf[2] = (char)0x00; // no auth
		sess->writeOffset = 0;
		sess->readBuf.clear();
	}

	void prepareSocks5Connect(Session* sess, const std::string& host, uint16_t port) {
		std::string& b = sess->writeBuf;
		b.clear();
		b.push_back((char)0x05); // ver
		b.push_back((char)0x01); // cmd connect
		b.push_back((char)0x00); // rsv
		b.push_back((char)0x03); // atyp domain
		if (host.size() > 255) {
			// truncate to be safe
			b.push_back((char)255);
			b.append(host.data(), 255);
		} else {
			b.push_back((char)host.size());
			b.append(host);
		}
		uint16_t be = htons(port);
		b.push_back((char)((be >> 8) & 0xFF));
		b.push_back((char)(be & 0xFF));
		sess->writeOffset = 0;
		sess->readBuf.clear();
	}

	void prepareSocks4Connect(Session* sess, const std::string& host, uint16_t port) {
		std::string& b = sess->writeBuf;
		b.clear();
		b.push_back((char)0x04); // VN
		b.push_back((char)0x01); // CONNECT
		uint16_t be = htons(port);
		b.push_back((char)((be >> 8) & 0xFF));
		b.push_back((char)(be & 0xFF));
		// SOCKS4a: 0.0.0.1
		b.push_back((char)0x00);
		b.push_back((char)0x00);
		b.push_back((char)0x00);
		b.push_back((char)0x01);
		b.push_back((char)0x00); // userid terminator
		b.append(host);
		b.push_back((char)0x00);
		sess->writeOffset = 0;
		sess->readBuf.clear();
	}

	void prepareSocksHttpHead(Session* sess, const std::string& host, uint16_t port, const std::string& path) {
		buildHttpHead(sess->writeBuf, host, port, path, /*absoluteForm*/false);
		sess->writeOffset = 0;
		sess->readBuf.clear();
	}

	void prepareHttpGet(Session* sess, const std::string& host, uint16_t port, const std::string& path) {
		buildHttpGet(sess->writeBuf, host, port, path, /*absoluteForm*/true);
		sess->writeOffset = 0;
		sess->readBuf.clear();
		sess->lastWasGet = true;
	}

	void prepareTunneledHttpGet(Session* sess, const std::string& host, uint16_t port, const std::string& path) {
		buildHttpGet(sess->writeBuf, host, port, path, /*absoluteForm*/false);
		sess->writeOffset = 0;
		sess->readBuf.clear();
		sess->lastWasGet = true;
	}

	void parseHttpStatus(Session* sess) {
		// Ensure we have at least a status line
		size_t lineEnd = sess->readBuf.find("\r\n");
		if (lineEnd == std::string::npos) {
			if (sess->readBuf.size() > 16384) { failSession(sess); }
			return;
		}
		// Parse status once
		if (!sess->statusParsed) {
			int code = 0;
			const char* data = sess->readBuf.data();
			size_t len = lineEnd;
			size_t sp = sess->readBuf.find(' ');
			if (sp != std::string::npos && sp + 4 <= len) {
				if (std::isdigit((unsigned char)data[sp + 1]) && std::isdigit((unsigned char)data[sp + 2]) && std::isdigit((unsigned char)data[sp + 3])) {
					code = (data[sp + 1] - '0') * 100 + (data[sp + 2] - '0') * 10 + (data[sp + 3] - '0');
				}
			}
			sess->statusParsed = true;
			sess->statusCode = code;
		}

		// Handle based on state
		switch (sess->state) {
			case SessionState::HTTP_CONNECT_RECV: {
				if (sess->statusCode >= 200 && sess->statusCode < 300) {
					// If IP masking required and port 80, send GET within tunnel (origin-form)
					if (sess->requireIpMasking && sess->worker->settings_.testPort == 80) {
						sess->readBuf.clear();
						sess->statusParsed = false;
						sess->headersComplete = false;
						sess->worker->prepareTunneledHttpGet(sess, sess->worker->settings_.testHost, sess->worker->settings_.testPort, sess->worker->settings_.testPath);
						sess->state = SessionState::HTTP_TUNNEL_HTTP_SEND;
						sess->worker->setDeadline(sess, sess->worker->settings_.requestTimeoutMs);
						sess->worker->arm(sess, false, true);
						return;
					}
					succeedSession(sess);
					return;
				}
				failSession(sess);
				return;
			}
			case SessionState::HTTP_RECV:
			case SessionState::HTTP_TUNNEL_HTTP_RECV:
			case SessionState::SOCKS_HTTP_RECV: {
				if (!(sess->statusCode >= 200 && sess->statusCode < 300)) { failSession(sess); return; }
				// For SOCKS HTTP verification, we do not require IP masking; treat 2xx as success
				if (sess->state == SessionState::SOCKS_HTTP_RECV) { succeedSession(sess); return; }
				// For HTTP direct or tunneled GET, if masking not required, success
				if (!sess->requireIpMasking || sess->worker->settings_.clientPublicIP.empty()) { succeedSession(sess); return; }
				// Need headers end to parse body
				size_t hdrEnd = sess->readBuf.find("\r\n\r\n");
				if (hdrEnd == std::string::npos) {
					if (sess->readBuf.size() > (1u << 20)) { failSession(sess); }
					return;
				}
				sess->headersComplete = true;
				size_t bodyPos = hdrEnd + 4;
				if (bodyPos >= sess->readBuf.size()) return; // wait for body
				std::string ip;
				if (extractFirstIPv4(sess->readBuf.data() + bodyPos, sess->readBuf.size() - bodyPos, ip)) {
					if (!ip.empty() && ip != sess->worker->settings_.clientPublicIP) {
						succeedSession(sess);
						return;
					}
					// Found but equals our own IP => not a proxy masking -> fail
					failSession(sess);
					return;
				}
				// Keep reading until close or threshold
				if (sess->readBuf.size() > 65536) { failSession(sess); }
				return;
			}
			default:
				break;
		}
	}

	void parseSocks5Method(Session* sess) {
		if (sess->readBuf.size() < 2) return;
		unsigned char ver = (unsigned char)sess->readBuf[0];
		unsigned char method = (unsigned char)sess->readBuf[1];
		if (ver != 5 || method != 0x00) { failSession(sess); return; }
		// Proceed to CONNECT
		prepareSocks5Connect(sess, settings_.testHost, settings_.testPort);
		sess->state = SessionState::S5_CONNECT_SEND;
		setDeadline(sess, settings_.handshakeTimeoutMs);
		arm(sess, false, true);
	}

	void parseSocks5Connect(Session* sess) {
		if (sess->readBuf.size() < 2) return;
		unsigned char ver = (unsigned char)sess->readBuf[0];
		unsigned char rep = (unsigned char)sess->readBuf[1];
		if (ver != 5 || rep != 0x00) { failSession(sess); return; }
		// If testing port 80, we can do an HTTP HEAD over the tunnel for content check.
		// For non-80 (e.g., 443), avoid sending plaintext HTTP; consider CONNECT success as pass.
		if (settings_.testPort == 80) {
			prepareSocksHttpHead(sess, settings_.testHost, settings_.testPort, settings_.testPath);
			sess->state = SessionState::SOCKS_HTTP_SEND;
			arm(sess, false, true);
		} else {
			succeedSession(sess);
		}
	}

	void parseSocks4Connect(Session* sess) {
		if (sess->readBuf.size() < 2) return;
		unsigned char vn = (unsigned char)sess->readBuf[0];
		unsigned char cd = (unsigned char)sess->readBuf[1];
		if (vn != 0x00 || cd != 0x5A) { failSession(sess); return; }
		if (settings_.testPort == 80) {
			prepareSocksHttpHead(sess, settings_.testHost, settings_.testPort, settings_.testPath);
			sess->state = SessionState::SOCKS_HTTP_SEND;
			arm(sess, false, true);
		} else {
			succeedSession(sess);
		}
	}

	std::vector<Session*> activeList_;
};

static void raiseNoFileLimit(int target, bool quiet) {
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return;
	rl.rlim_cur = std::max<rlim_t>(rl.rlim_cur, target);
	rl.rlim_max = std::max<rlim_t>(rl.rlim_max, target);
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		logf(quiet, "Warning: failed to raise RLIMIT_NOFILE to %d", target);
	}
}

static void usage(const char* argv0) {
	std::cerr << "Usage: " << argv0 << " (--in proxies.txt | --range CIDR | --range-file FILE) --out good.txt [options]\n";
	std::cerr << "Options:\n";
	std::cerr << "  --in FILE             Input file of proxies (ip:port or proto://ip:port)\n";
    std::cerr << "  --range CIDR          Scan IP range in CIDR (e.g., 104.20.15.0/24) on common proxy ports (or all ports with --scan-all-ports)\n";
	std::cerr << "  --range-file FILE     Scan multiple CIDR ranges listed in FILE (one per line)\n";
	std::cerr << "  --out FILE            Output file for working proxies\n";
	std::cerr << "  --workers N           Number of worker threads (default: hw cores)\n";
	std::cerr << "  --concurrency N       Connections per worker (default: 2048)\n";
	std::cerr << "  --test-host HOST      Target host for verification (default: example.com)\n";
	std::cerr << "  --test-port PORT      Target port for verification (default: 443)\n";
	std::cerr << "  --test-path PATH      HTTP path for verification (default: /)\n";
    std::cerr << "  --timeout S           Base timeout in seconds; scales internal timeouts proportionally\n";
	std::cerr << "  --default-proto [http|socks4|socks5] (default: http)\n";
	std::cerr << "  --http-mode [connect|direct] HTTP proxy verification mode (default: connect)\n";
	std::cerr << "  --no-merge            Do not merge per-thread outputs\n";
	std::cerr << "  --quiet               Reduce logging\n";
	std::cerr << "  --scan-all-ports      Scan all ports (1-65535) for each IP in range modes\n";
	std::cerr << "  --queue-size N        Bounded queue capacity for range scanning (default: workers*concurrency*2)\n";
	    std::cerr << "\n";
	    std::cerr << "Notes:\n";
	    std::cerr << "  - If a line omits protocol (e.g., ip:port) and --default-proto is NOT provided,\n";
	    std::cerr << "    the checker tries all supported protocols/modes: HTTP CONNECT, HTTP DIRECT, SOCKS4, SOCKS5.\n";
	    std::cerr << "  - If --default-proto is provided, unspecified lines are tested ONLY with that protocol\n";
	    std::cerr << "    (HTTP uses --http-mode). Lines that explicitly specify a protocol are honored as-is.\n";
	    std::cerr << "  - --in, --range, and --range-file are mutually exclusive.\n";
	std::cerr << std::flush;
}

static bool parseArgs(int argc, char** argv, Settings& s) {
	for (int i = 1; i < argc; ++i) {
		std::string a = argv[i];
		auto need = [&](const char* name) -> const char* {
			if (i + 1 >= argc) {
				std::cerr << "Missing value for " << name << "\n";
				return nullptr;
			}
			return argv[++i];
		};
		if (a == "--in") { const char* v = need("--in"); if (!v) return false; s.inputFile = v; }
		else if (a == "--range") { const char* v = need("--range"); if (!v) return false; s.rangeCIDR = v; }
		else if (a == "--range-file") { const char* v = need("--range-file"); if (!v) return false; s.rangeFile = v; }
		else if (a == "--out") { const char* v = need("--out"); if (!v) return false; s.outputFile = v; }
		else if (a == "--workers") { const char* v = need("--workers"); if (!v) return false; s.numWorkers = std::max(1, atoi(v)); }
		else if (a == "--concurrency") { const char* v = need("--concurrency"); if (!v) return false; s.concurrencyPerWorker = std::max(1, atoi(v)); }
		else if (a == "--test-host") { const char* v = need("--test-host"); if (!v) return false; s.testHost = v; }
		else if (a == "--test-port") { const char* v = need("--test-port"); if (!v) return false; s.testPort = (uint16_t)atoi(v); }
		else if (a == "--test-path") { const char* v = need("--test-path"); if (!v) return false; s.testPath = v; }
    else if (a == "--timeout") {
            const char* v = need("--timeout");
            if (!v) return false;
            // value is in seconds; compute proportional timeouts in milliseconds
            int seconds = std::max(1, atoi(v));
            int baseMs = seconds * 1000;
            // Proportional scaling: connect=1.0x, handshake=1.5x, request=2.5x
            s.connectTimeoutMs = baseMs;
            s.handshakeTimeoutMs = (int)(baseMs * 1.5);
            s.requestTimeoutMs = (int)(baseMs * 2.5);
        }
		else if (a == "--default-proto") { const char* v = need("--default-proto"); if (!v) return false; std::string pv = v; if (pv == "http") s.defaultProtocol = Protocol::HTTP; else if (pv == "socks4") s.defaultProtocol = Protocol::SOCKS4; else if (pv == "socks5") s.defaultProtocol = Protocol::SOCKS5; else { std::cerr << "Unknown proto: " << pv << "\n"; return false; } s.defaultProtocolForced = true; }
		else if (a == "--http-mode") { const char* v = need("--http-mode"); if (!v) return false; std::string hv = v; if (hv == "connect") s.httpMode = HttpMode::CONNECT; else if (hv == "direct") s.httpMode = HttpMode::DIRECT; else { std::cerr << "Unknown http mode: " << hv << "\n"; return false; } }
		else if (a == "--no-merge") { s.mergeOutputs = false; }
		else if (a == "--keep-parts") { s.keepParts = true; }
		else if (a == "--quiet") { s.quiet = true; }
		else if (a == "--scan-all-ports") { s.scanAllPorts = true; }
		else if (a == "--queue-size") { const char* v = need("--queue-size"); if (!v) return false; s.queueCapacity = std::max(1, atoi(v)); }
		else if (a == "-h" || a == "--help") { usage(argv[0]); return false; }
		else { std::cerr << "Unknown arg: " << a << "\n"; usage(argv[0]); return false; }
	}
	// Validate exclusivity and presence
	int provided = 0;
	if (!s.inputFile.empty()) ++provided;
	if (!s.rangeCIDR.empty()) ++provided;
	if (!s.rangeFile.empty()) ++provided;
	if (provided > 1) {
		std::cerr << "--in, --range, and --range-file are mutually exclusive\n";
		return false;
	}
	if (provided == 0) {
		std::cerr << "One of --in, --range, or --range-file must be provided\n";
		return false;
	}
	return true;
}


// Fetch the public IP of this machine by making a direct HTTP GET to testHost:testPort testPath
// Only supports HTTP on port 80 (no TLS). Returns true on success and populates settings.clientPublicIP
static bool fetchBaselinePublicIP(Settings& settings) {
    if (settings.testPort != 80) return false;
    const std::string& host = settings.testHost;
    const std::string& path = settings.testPath.empty() ? std::string("/") : settings.testPath;
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC; hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    char portStr[16]; snprintf(portStr, sizeof(portStr), "%u", (unsigned)settings.testPort);
    int gai = getaddrinfo(host.c_str(), portStr, &hints, &res);
    if (gai != 0 || !res) {
        return false;
    }
    int fd = -1; addrinfo* aiSel = nullptr;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        // Set short timeouts
        struct timeval tv; tv.tv_sec = settings.connectTimeoutMs / 1000; tv.tv_usec = (settings.connectTimeoutMs % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) { aiSel = ai; break; }
        close(fd); fd = -1;
    }
    if (fd < 0) { freeaddrinfo(res); return false; }
    // Build simple origin-form GET
    std::string req;
    req.reserve(256);
    req += "GET "; req += path.empty() ? "/" : path; req += " HTTP/1.1\r\n";
    req += "Host: "; req += host; req += "\r\n";
    req += "User-Agent: ProxyChecker/0.1\r\n";
    req += "Accept: text/plain, text/*;q=0.9, */*;q=0.1\r\n";
    req += "Connection: close\r\n\r\n";
    ssize_t wn = ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
    if (wn < 0) { close(fd); freeaddrinfo(res); return false; }
    // Read response
    std::string buf; buf.reserve(4096);
    char tmp[2048];
    while (true) {
        ssize_t rn = ::recv(fd, tmp, sizeof(tmp), 0);
        if (rn <= 0) break;
        buf.append(tmp, (size_t)rn);
        if (buf.size() > (1u << 20)) break; // 1MB cap
    }
    close(fd); freeaddrinfo(res);
    // Find body
    size_t hdrEnd = buf.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return false;
    size_t bodyPos = hdrEnd + 4;
    if (bodyPos >= buf.size()) return false;
    std::string ip;
    if (extractFirstIPv4FromBuffer(buf.data() + bodyPos, buf.size() - bodyPos, ip)) {
        settings.clientPublicIP = ip;
        return true;
    }
    return false;
}


static bool readProxies(const std::string& path, const Settings& s, std::vector<ProxyTarget>& out) {
	std::ifstream in(path);
	if (!in.is_open()) return false;
	std::string line;
	while (std::getline(in, line)) {
		auto v = parseProxyLineDetailed(line, s.defaultProtocol);
        if (!v) continue;
        const ParsedProxyLine& pl = *v;
		if (pl.explicitProto) {
			// Honor explicit protocol lines as-is
			out.push_back(ProxyTarget{pl.proto, pl.host, pl.port, std::nullopt});
		} else {
			// Protocol omitted in input
			if (s.defaultProtocolForced) {
				// Enforce the specified default protocol only
				switch (s.defaultProtocol) {
					case Protocol::HTTP:
						out.push_back(ProxyTarget{Protocol::HTTP, pl.host, pl.port, s.httpMode});
						break;
					case Protocol::SOCKS5:
						out.push_back(ProxyTarget{Protocol::SOCKS5, pl.host, pl.port, std::nullopt});
						break;
					case Protocol::SOCKS4:
						out.push_back(ProxyTarget{Protocol::SOCKS4, pl.host, pl.port, std::nullopt});
						break;
				}
			} else {
				// Try all protocols and HTTP modes by default
				out.push_back(ProxyTarget{Protocol::HTTP, pl.host, pl.port, HttpMode::CONNECT});
				out.push_back(ProxyTarget{Protocol::HTTP, pl.host, pl.port, HttpMode::DIRECT});
				out.push_back(ProxyTarget{Protocol::SOCKS5, pl.host, pl.port, std::nullopt});
				out.push_back(ProxyTarget{Protocol::SOCKS4, pl.host, pl.port, std::nullopt});
			}
		}
	}
	return true;
}

// Common proxy ports for range scanning
static const uint16_t kCommonProxyPorts[] = {
    80, 8080, 1080, 3128, 8888, 8000, 8081, 8082, 3129, 4145, 9999
};

static bool parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& maskBits) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    std::string ipStr = cidr.substr(0, slash);
    std::string maskStr = cidr.substr(slash + 1);
    if (maskStr.empty()) return false;
    char* end = nullptr;
    long m = strtol(maskStr.c_str(), &end, 10);
    if (!end || *end != '\0' || m < 0 || m > 32) return false;
    maskBits = (uint32_t)m;
    in_addr addr{};
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) return false;
    network = ntohl(addr.s_addr);
    // Ensure network is aligned to mask
    uint32_t mask = maskBits == 0 ? 0 : (0xFFFFFFFFu << (32 - maskBits));
    network &= mask;
    return true;
}

static void enumerateIPsInCIDR(uint32_t network, uint32_t maskBits, std::vector<std::string>& outIPs) {
    uint32_t mask = maskBits == 0 ? 0 : (0xFFFFFFFFu << (32 - maskBits));
    uint32_t start = network; // already masked
    uint32_t end = start | (~mask);
    outIPs.reserve(outIPs.size() + (size_t)(end - start + 1));
    char buf[INET_ADDRSTRLEN];
    for (uint32_t ip = start; ip <= end; ++ip) {
        in_addr a{};
        a.s_addr = htonl(ip);
        if (inet_ntop(AF_INET, &a, buf, sizeof(buf))) {
            outIPs.emplace_back(buf);
        }
        if (ip == 0xFFFFFFFFu) break; // guard overflow when maskBits==0
    }
}

static bool generateProxiesFromRange(const Settings& s, std::vector<ProxyTarget>& out) {
    uint32_t network = 0, maskBits = 0;
    if (!parseCIDR(s.rangeCIDR, network, maskBits)) {
        std::cerr << "Invalid CIDR: " << s.rangeCIDR << "\n";
        return false;
    }
    std::vector<std::string> ips;
    enumerateIPsInCIDR(network, maskBits, ips);
    if (ips.empty()) return true;
    auto pushForPort = [&](const std::string& ip, uint16_t port){
        if (s.defaultProtocolForced) {
            switch (s.defaultProtocol) {
                case Protocol::HTTP:
                    out.push_back(ProxyTarget{Protocol::HTTP, ip, port, s.httpMode});
                    break;
                case Protocol::SOCKS5:
                    out.push_back(ProxyTarget{Protocol::SOCKS5, ip, port, std::nullopt});
                    break;
                case Protocol::SOCKS4:
                    out.push_back(ProxyTarget{Protocol::SOCKS4, ip, port, std::nullopt});
                    break;
            }
        } else {
            out.push_back(ProxyTarget{Protocol::HTTP, ip, port, HttpMode::CONNECT});
            out.push_back(ProxyTarget{Protocol::HTTP, ip, port, HttpMode::DIRECT});
            out.push_back(ProxyTarget{Protocol::SOCKS5, ip, port, std::nullopt});
            out.push_back(ProxyTarget{Protocol::SOCKS4, ip, port, std::nullopt});
        }
    };
    for (const std::string& ip : ips) {
        if (s.scanAllPorts) {
            for (uint32_t p = 1; p <= 65535u; ++p) {
                pushForPort(ip, (uint16_t)p);
            }
        } else {
            for (uint16_t port : kCommonProxyPorts) {
                pushForPort(ip, port);
            }
        }
    }
    return true;
}

static inline uint64_t countIPsInCIDR(uint32_t maskBits) {
    if (maskBits > 32) return 0ULL;
    uint32_t hostBits = 32 - maskBits;
    return (hostBits >= 32) ? (1ULL << 32) : (1ULL << hostBits);
}

static void generateProxiesFromCIDR(uint32_t network, uint32_t maskBits, const Settings& s, std::vector<ProxyTarget>& out) {
    uint32_t mask = maskBits == 0 ? 0 : (0xFFFFFFFFu << (32 - maskBits));
    uint32_t start = network & mask;
    uint32_t end = start | (~mask);
    char buf[INET_ADDRSTRLEN];
    for (uint32_t ip = start; ip <= end; ++ip) {
        in_addr a{};
        a.s_addr = htonl(ip);
        if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) {
            if (ip == 0xFFFFFFFFu) break; // guard overflow
            continue;
        }
        const std::string ipStr(buf);
        auto pushForPort = [&](uint16_t port){
            if (s.defaultProtocolForced) {
                switch (s.defaultProtocol) {
                    case Protocol::HTTP:
                        out.push_back(ProxyTarget{Protocol::HTTP, ipStr, port, s.httpMode});
                        break;
                    case Protocol::SOCKS5:
                        out.push_back(ProxyTarget{Protocol::SOCKS5, ipStr, port, std::nullopt});
                        break;
                    case Protocol::SOCKS4:
                        out.push_back(ProxyTarget{Protocol::SOCKS4, ipStr, port, std::nullopt});
                        break;
                }
            } else {
                out.push_back(ProxyTarget{Protocol::HTTP, ipStr, port, HttpMode::CONNECT});
                out.push_back(ProxyTarget{Protocol::HTTP, ipStr, port, HttpMode::DIRECT});
                out.push_back(ProxyTarget{Protocol::SOCKS5, ipStr, port, std::nullopt});
                out.push_back(ProxyTarget{Protocol::SOCKS4, ipStr, port, std::nullopt});
            }
        };
        if (s.scanAllPorts) {
            for (uint32_t p = 1; p <= 65535u; ++p) pushForPort((uint16_t)p);
        } else {
            for (uint16_t port : kCommonProxyPorts) pushForPort(port);
        }
        if (ip == 0xFFFFFFFFu) break; // guard overflow when maskBits==0
    }
}

static bool generateProxiesFromRangeFile(const Settings& s, std::vector<ProxyTarget>& out, uint64_t& totalIpsOut) {
    std::ifstream in(s.rangeFile);
    if (!in.is_open()) {
        std::cerr << "Failed to open range file: " << s.rangeFile << "\n";
        return false;
    }
    totalIpsOut = 0ULL;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        std::string sline = trim(line);
        if (sline.empty()) continue;
        if (sline[0] == '#') continue;
        uint32_t network = 0, maskBits = 0;
        if (!parseCIDR(sline, network, maskBits)) {
            std::cerr << "Invalid CIDR at " << s.rangeFile << ":" << lineNo << ": " << sline << "\n";
            return false;
        }
        totalIpsOut += countIPsInCIDR(maskBits);
        generateProxiesFromCIDR(network, maskBits, s, out);
    }
    return true;
}

static void buildProgressBar(uint64_t current, uint64_t total, int width, std::string& out) {
    out.clear();
    double ratio = (total == 0) ? 0.0 : (double)current / (double)total;
    if (ratio < 0.0) ratio = 0.0; if (ratio > 1.0) ratio = 1.0;
    int filled = (int)(ratio * width + 0.5);
    out.push_back('[');
    for (int i = 0; i < width; ++i) {
        out += (i < filled) ? "\xE2\x96\x88" /*█*/ : "\xE2\x96\x91" /*░*/;
    }
    out.push_back(']');
}

static void progressLoop(const Settings& s, const Counters& counters, std::atomic<bool>& stopFlag) {
    if (s.quiet) return;
    std::string bar;
    while (!stopFlag.load(std::memory_order_relaxed)) {
        uint64_t total = counters.total.load(std::memory_order_relaxed);
        uint64_t started = counters.started.load(std::memory_order_relaxed);
        uint64_t ok = counters.succeeded.load(std::memory_order_relaxed);
        uint64_t bad = counters.failed.load(std::memory_order_relaxed);
        uint64_t checked = ok + bad; // sessions that completed
        if (s.scanAllPorts && s.totalPortsForProgress > 0 && s.sessionsPerPortForProgress > 0) {
            uint64_t portUnitsDone = checked / (uint64_t)s.sessionsPerPortForProgress;
            if (portUnitsDone > s.totalPortsForProgress) portUnitsDone = s.totalPortsForProgress;
            buildProgressBar(portUnitsDone, s.totalPortsForProgress, 28, bar);
            double pct = (s.totalPortsForProgress == 0) ? 0.0 : (double)portUnitsDone * 100.0 / (double)s.totalPortsForProgress;
            fprintf(stderr, "\r%s %5.1f%% | Ports: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64,
                    bar.c_str(), pct, portUnitsDone, s.totalPortsForProgress, ok, bad);
        } else if (s.ipProgressMode && s.sessionsPerIpForProgress > 0) {
            uint64_t ipUnitsDone = checked / (uint64_t)s.sessionsPerIpForProgress;
            if (ipUnitsDone > s.totalIpsForProgress) ipUnitsDone = s.totalIpsForProgress;
            buildProgressBar(ipUnitsDone, s.totalIpsForProgress, 28, bar);
            double pct = (s.totalIpsForProgress == 0) ? 0.0 : (double)ipUnitsDone * 100.0 / (double)s.totalIpsForProgress;
            fprintf(stderr, "\r%s %5.1f%% | IPs: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64,
                    bar.c_str(), pct, ipUnitsDone, s.totalIpsForProgress, ok, bad);
        } else {
            uint64_t current = (started < total) ? started : total;
            buildProgressBar(current, total, 28, bar);
            double pct = (total == 0) ? 0.0 : (double)current * 100.0 / (double)total;
            fprintf(stderr, "\r%s %5.1f%% | Checked: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64,
                    bar.c_str(), pct, checked, total, ok, bad);
        }
        fflush(stderr);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    // Final line
    uint64_t total = counters.total.load(std::memory_order_relaxed);
    uint64_t started = counters.started.load(std::memory_order_relaxed);
    uint64_t ok = counters.succeeded.load(std::memory_order_relaxed);
    uint64_t bad = counters.failed.load(std::memory_order_relaxed);
    uint64_t checked = ok + bad;
    if (s.scanAllPorts && s.totalPortsForProgress > 0 && s.sessionsPerPortForProgress > 0) {
        buildProgressBar(s.totalPortsForProgress, s.totalPortsForProgress, 28, bar);
        fprintf(stderr, "\r%s %5.1f%% | Ports: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64 "\n",
                bar.c_str(), 100.0, s.totalPortsForProgress, s.totalPortsForProgress, ok, bad);
    } else if (s.ipProgressMode && s.sessionsPerIpForProgress > 0) {
        buildProgressBar(s.totalIpsForProgress, s.totalIpsForProgress, 28, bar);
        fprintf(stderr, "\r%s %5.1f%% | IPs: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64 "\n",
                bar.c_str(), 100.0, s.totalIpsForProgress, s.totalIpsForProgress, ok, bad);
    } else {
        buildProgressBar(total, total, 28, bar);
        fprintf(stderr, "\r%s %5.1f%% | Checked: %" PRIu64 "/%" PRIu64 " | Succeeded: %" PRIu64 ", Failed: %" PRIu64 "\n",
                bar.c_str(), 100.0, checked, total, ok, bad);
    }
    fflush(stderr);
}

} // end anonymous namespace

int main(int argc, char** argv) {
	// Ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	Settings settings;
	if (!parseArgs(argc, argv, settings)) {
		return 1;
	}

	raiseNoFileLimit(settings.maxOpenFiles, settings.quiet);

	std::vector<ProxyTarget> all;
	bool streamingMode = false;

	// Determine mode and compute progress totals without preallocation for range modes
	if (!settings.rangeFile.empty() || !settings.rangeCIDR.empty()) {
		streamingMode = true;
		settings.ipProgressMode = true;
		uint64_t totalIps = 0;
		if (!settings.rangeFile.empty()) {
			// Sum IPs across all CIDRs in file
			std::ifstream in(settings.rangeFile);
			if (!in.is_open()) {
				std::cerr << "Failed to open range file: " << settings.rangeFile << "\n";
				return 1;
			}
			std::string line; int lineNo = 0;
			while (std::getline(in, line)) {
				++lineNo;
				std::string sline = trim(line);
				if (sline.empty() || sline[0] == '#') continue;
				uint32_t network=0, bits=0;
				if (!parseCIDR(sline, network, bits)) {
					std::cerr << "Invalid CIDR at " << settings.rangeFile << ":" << lineNo << ": " << sline << "\n";
					return 1;
				}
				totalIps += countIPsInCIDR(bits);
			}
		} else {
			uint32_t network=0, bits=0;
			if (!parseCIDR(settings.rangeCIDR, network, bits)) {
				std::cerr << "Invalid CIDR: " << settings.rangeCIDR << "\n";
				return 1;
			}
			totalIps = countIPsInCIDR(bits);
		}
		settings.totalIpsForProgress = totalIps;
		uint64_t protocolsPerTarget = settings.defaultProtocolForced ? 1ULL : 4ULL;
		if (settings.scanAllPorts) {
			settings.totalPortsForProgress = totalIps * 65535ULL;
			settings.sessionsPerPortForProgress = (uint32_t)protocolsPerTarget;
		} else {
			const uint64_t commonPortCount = (uint64_t)(sizeof(kCommonProxyPorts) / sizeof(kCommonProxyPorts[0]));
			settings.sessionsPerIpForProgress = (uint32_t)(protocolsPerTarget * commonPortCount);
		}
	} else {
		// Input file mode: preload
		if (!readProxies(settings.inputFile, settings, all)) {
			std::cerr << "Failed to read proxies from " << settings.inputFile << "\n";
			return 1;
		}
		if (all.empty()) {
			std::cerr << "No proxies generated from input file\n";
			return 1;
		}
	}

	// If HTTP on port 80, prefetch our public IP baseline once to enable IP-masking verification
	if (settings.testPort == 80) {
		(void)fetchBaselinePublicIP(settings);
	}

	// Number of workers
	int workers = std::max(1, settings.numWorkers);

	// Prepare streaming queue if needed
	std::shared_ptr<TaskQueue> taskQueue;
	std::thread producerThread;
	if (streamingMode) {
		int capacity = settings.queueCapacity;
		if (capacity <= 0) {
			capacity = std::max(1, workers * settings.concurrencyPerWorker * 2);
		}
		taskQueue = std::make_shared<TaskQueue>((size_t)capacity);
		// Producer lambda for pushing tasks on-the-fly
		auto pushForIpPort = [&](const std::string& ipStr, uint16_t port){
			if (settings.defaultProtocolForced) {
				switch (settings.defaultProtocol) {
					case Protocol::HTTP:
						(void)taskQueue->push(ProxyTarget{Protocol::HTTP, ipStr, port, settings.httpMode});
						break;
					case Protocol::SOCKS5:
						(void)taskQueue->push(ProxyTarget{Protocol::SOCKS5, ipStr, port, std::nullopt});
						break;
					case Protocol::SOCKS4:
						(void)taskQueue->push(ProxyTarget{Protocol::SOCKS4, ipStr, port, std::nullopt});
						break;
				}
			} else {
				(void)taskQueue->push(ProxyTarget{Protocol::HTTP, ipStr, port, HttpMode::CONNECT});
				(void)taskQueue->push(ProxyTarget{Protocol::HTTP, ipStr, port, HttpMode::DIRECT});
				(void)taskQueue->push(ProxyTarget{Protocol::SOCKS5, ipStr, port, std::nullopt});
				(void)taskQueue->push(ProxyTarget{Protocol::SOCKS4, ipStr, port, std::nullopt});
			}
		};
		producerThread = std::thread([&, pushForIpPort]() {
			char ipbuf[INET_ADDRSTRLEN];
			auto produceCIDR = [&](uint32_t network, uint32_t maskBits){
				uint32_t mask = maskBits == 0 ? 0 : (0xFFFFFFFFu << (32 - maskBits));
				uint32_t start = network & mask;
				uint32_t end = start | (~mask);
				for (uint32_t ip = start; ip <= end; ++ip) {
					in_addr a{}; a.s_addr = htonl(ip);
					if (!inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf))) {
						if (ip == 0xFFFFFFFFu) break;
						continue;
					}
					std::string ipStr(ipbuf);
					if (settings.scanAllPorts) {
						for (uint32_t p = 1; p <= 65535u; ++p) pushForIpPort(ipStr, (uint16_t)p);
					} else {
						for (uint16_t port : kCommonProxyPorts) pushForIpPort(ipStr, port);
					}
					if (ip == 0xFFFFFFFFu) break; // guard overflow
				}
			};
			if (!settings.rangeFile.empty()) {
				std::ifstream in(settings.rangeFile);
				std::string line; int lineNo = 0;
				while (std::getline(in, line)) {
					++lineNo;
					std::string sline = trim(line);
					if (sline.empty() || sline[0] == '#') continue;
					uint32_t network=0, bits=0;
					if (!parseCIDR(sline, network, bits)) {
						continue; // skip invalid here; already validated earlier
					}
					produceCIDR(network, bits);
				}
			} else if (!settings.rangeCIDR.empty()) {
				uint32_t network=0, bits=0;
				if (parseCIDR(settings.rangeCIDR, network, bits)) {
					produceCIDR(network, bits);
				}
			}
			taskQueue->close();
		});
	}

	// Shard proxies across workers (input file mode only)
	std::vector<std::vector<ProxyTarget>> shards;
	if (!streamingMode) {
		shards.assign((size_t)workers, {});
		for (size_t i = 0; i < all.size(); ++i) {
			shards[i % shards.size()].push_back(std::move(all[i]));
		}
	}

	Counters counters;
	if (streamingMode) {
		if (settings.scanAllPorts && settings.totalPortsForProgress > 0 && settings.sessionsPerPortForProgress > 0) {
			counters.total.store((uint64_t)settings.totalPortsForProgress * (uint64_t)settings.sessionsPerPortForProgress, std::memory_order_relaxed);
		} else if (settings.totalIpsForProgress > 0 && settings.sessionsPerIpForProgress > 0) {
			counters.total.store((uint64_t)settings.totalIpsForProgress * (uint64_t)settings.sessionsPerIpForProgress, std::memory_order_relaxed);
		} else {
			counters.total.store(0, std::memory_order_relaxed);
		}
	} else {
		counters.total.store((uint64_t)all.size(), std::memory_order_relaxed);
	}
	std::atomic<bool> progressStop{false};
	std::thread progressThread;
	if (!settings.quiet) {
		progressThread = std::thread(progressLoop, settings, std::cref(counters), std::ref(progressStop));
	}
	std::vector<std::unique_ptr<Worker>> workerObjs;
	workerObjs.reserve((size_t)workers);
	if (streamingMode) {
		for (int i = 0; i < workers; ++i) {
			workerObjs.emplace_back(std::make_unique<Worker>(i, settings, taskQueue, counters));
		}
		uint64_t expected = counters.total.load(std::memory_order_relaxed);
		logf(settings.quiet, "Starting %d workers (streaming), expected sessions: %" PRIu64, workers, expected);
	} else {
		for (int i = 0; i < workers; ++i) {
			workerObjs.emplace_back(std::make_unique<Worker>(i, settings, std::move(shards[(size_t)i]), counters));
		}
		uint64_t totalWork = (uint64_t)all.size();
		logf(settings.quiet, "Starting %d workers, total proxies: %" PRIu64, workers, totalWork);
	}
	for (auto& w : workerObjs) w->start();
	for (auto& w : workerObjs) w->join();
	if (producerThread.joinable()) producerThread.join();
	progressStop.store(true, std::memory_order_relaxed);
	if (progressThread.joinable()) progressThread.join();

	logf(settings.quiet, "Done. Succeeded=%" PRIu64 ", Failed=%" PRIu64, counters.succeeded.load(), counters.failed.load());

	// Merge outputs
	if (settings.mergeOutputs && !settings.outputFile.empty()) {
		std::ofstream merged(settings.outputFile, std::ios::out | std::ios::trunc);
		if (!merged.is_open()) {
			logf(settings.quiet, "Warning: failed to open merged output %s", settings.outputFile.c_str());
		} else {
			for (int i = 0; i < workers; ++i) {
				std::string part = settings.outputFile + "." + std::to_string(i);
				std::ifstream in(part, std::ios::in | std::ios::binary);
				if (!in.is_open()) {
					continue;
				}
				char buffer[1 << 16];
				while (in) {
					in.read(buffer, sizeof(buffer));
					std::streamsize n = in.gcount();
					if (n > 0) {
						merged.write(buffer, n);
					}
				}
				merged.flush();
				in.close();
				if (!settings.keepParts) unlink(part.c_str());
			}
			merged.flush();
			merged.close();
		}
	}

	return 0;
}

