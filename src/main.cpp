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
	bool mergeOutputs = true;
	bool keepParts = false;
	bool quiet = false;
	int maxOpenFiles = 262144; // attempt to raise
	HttpMode httpMode = HttpMode::CONNECT;
};

static inline uint64_t nowMs() {
	return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
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
	// Buffers
	std::string writeBuf;
	std::string readBuf;
	size_t writeOffset{0};
	// For parsing HTTP
	bool statusParsed{false};
	int statusCode{0};
	// For worker context
	class Worker* worker{nullptr};
};

class Worker {
public:
	Worker(int id,
		const Settings& s,
		std::vector<ProxyTarget> proxies,
		Counters& counters)
		: id_(id), settings_(s), proxies_(std::move(proxies)), counters_(counters) {}

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
	Counters& counters_;
	std::thread thread_;
	int epfd_{-1};
	std::ofstream out_;
	uint64_t nextIndex_{0};
	uint32_t nextDeadlineVersion_{1};
	int active_{0};

	static constexpr int kMaxEvents = 4096;

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

		counters_.total.fetch_add(proxies_.size(), std::memory_order_relaxed);

		// Prime initial sessions
		refill();

		epoll_event events[kMaxEvents];
		while (active_ > 0) {
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
		while (active_ < settings_.concurrencyPerWorker && nextIndex_ < proxies_.size()) {
			launch(proxies_[nextIndex_++]);
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
		sess->worker = this;
		sess->state = SessionState::CONNECTING;
		sess->writeBuf.clear();
		sess->readBuf.clear();
		sess->writeOffset = 0;
		sess->statusParsed = false;
		sess->statusCode = 0;

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
						prepareHttpHead(sess, settings_.testHost, settings_.testPort, settings_.testPath);
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

	void prepareHttpHead(Session* sess, const std::string& host, uint16_t port, const std::string& path) {
		buildHttpHead(sess->writeBuf, host, port, path, /*absoluteForm*/true);
		sess->writeOffset = 0;
		sess->readBuf.clear();
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

	void parseHttpStatus(Session* sess) {
		// Look for first CRLF
		size_t pos = sess->readBuf.find("\r\n");
		if (pos == std::string::npos) {
			if (sess->readBuf.size() > 16384) { failSession(sess); }
			return;
		}
		// Parse status code
		// Expect: HTTP/1.1 200 OK
		int code = 0;
		const char* data = sess->readBuf.data();
		size_t len = pos;
		// Find first space then parse number after
		size_t sp = sess->readBuf.find(' ');
		if (sp != std::string::npos && sp + 4 <= len) {
			if (std::isdigit((unsigned char)data[sp + 1]) && std::isdigit((unsigned char)data[sp + 2]) && std::isdigit((unsigned char)data[sp + 3])) {
				code = (data[sp + 1] - '0') * 100 + (data[sp + 2] - '0') * 10 + (data[sp + 3] - '0');
			}
		}
		// Success criteria:
		// - For CONNECT mode (HTTP proxy) expect 200 Connection established (some send 200 or 2xx/OK variants)
		// - For direct HTTP HEAD expect 200
		if (code >= 200 && code < 300) {
			succeedSession(sess);
			return;
		}
		failSession(sess);
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
	std::cerr << "Usage: " << argv0 << " --in proxies.txt --out good.txt [options]\n";
	std::cerr << "Options:\n";
	std::cerr << "  --in FILE             Input file of proxies (ip:port or proto://ip:port)\n";
	std::cerr << "  --out FILE            Output file for working proxies\n";
	std::cerr << "  --workers N           Number of worker threads (default: hw cores)\n";
	std::cerr << "  --concurrency N       Connections per worker (default: 2048)\n";
	std::cerr << "  --test-host HOST      Target host for verification (default: example.com)\n";
	std::cerr << "  --test-port PORT      Target port for verification (default: 443)\n";
	std::cerr << "  --test-path PATH      HTTP path for verification (default: /)\n";
	std::cerr << "  --connect-timeout MS  TCP connect timeout (default: 2000)\n";
	std::cerr << "  --handshake-timeout MS Handshake timeout (default: 3000)\n";
	std::cerr << "  --request-timeout MS  HTTP request timeout (default: 5000)\n";
	std::cerr << "  --default-proto [http|socks4|socks5] (default: http)\n";
	std::cerr << "  --http-mode [connect|direct] HTTP proxy verification mode (default: connect)\n";
	std::cerr << "  --no-merge            Do not merge per-thread outputs\n";
	std::cerr << "  --quiet               Reduce logging\n";
    std::cerr << "\n";
    std::cerr << "Notes:\n";
    std::cerr << "  - If a line omits protocol (e.g., ip:port), the checker tries http (CONNECT and DIRECT), socks4, and socks5.\n";
    std::cerr << "  - In that case, --default-proto is ignored.\n";
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
		else if (a == "--out") { const char* v = need("--out"); if (!v) return false; s.outputFile = v; }
		else if (a == "--workers") { const char* v = need("--workers"); if (!v) return false; s.numWorkers = std::max(1, atoi(v)); }
		else if (a == "--concurrency") { const char* v = need("--concurrency"); if (!v) return false; s.concurrencyPerWorker = std::max(1, atoi(v)); }
		else if (a == "--test-host") { const char* v = need("--test-host"); if (!v) return false; s.testHost = v; }
		else if (a == "--test-port") { const char* v = need("--test-port"); if (!v) return false; s.testPort = (uint16_t)atoi(v); }
		else if (a == "--test-path") { const char* v = need("--test-path"); if (!v) return false; s.testPath = v; }
		else if (a == "--connect-timeout") { const char* v = need("--connect-timeout"); if (!v) return false; s.connectTimeoutMs = std::max(1, atoi(v)); }
		else if (a == "--handshake-timeout") { const char* v = need("--handshake-timeout"); if (!v) return false; s.handshakeTimeoutMs = std::max(1, atoi(v)); }
		else if (a == "--request-timeout") { const char* v = need("--request-timeout"); if (!v) return false; s.requestTimeoutMs = std::max(1, atoi(v)); }
		else if (a == "--default-proto") { const char* v = need("--default-proto"); if (!v) return false; std::string pv = v; if (pv == "http") s.defaultProtocol = Protocol::HTTP; else if (pv == "socks4") s.defaultProtocol = Protocol::SOCKS4; else if (pv == "socks5") s.defaultProtocol = Protocol::SOCKS5; else { std::cerr << "Unknown proto: " << pv << "\n"; return false; } }
		else if (a == "--http-mode") { const char* v = need("--http-mode"); if (!v) return false; std::string hv = v; if (hv == "connect") s.httpMode = HttpMode::CONNECT; else if (hv == "direct") s.httpMode = HttpMode::DIRECT; else { std::cerr << "Unknown http mode: " << hv << "\n"; return false; } }
		else if (a == "--no-merge") { s.mergeOutputs = false; }
		else if (a == "--keep-parts") { s.keepParts = true; }
		else if (a == "--quiet") { s.quiet = true; }
		else if (a == "-h" || a == "--help") { usage(argv[0]); return false; }
		else { std::cerr << "Unknown arg: " << a << "\n"; usage(argv[0]); return false; }
	}
	if (s.inputFile.empty()) { std::cerr << "--in is required\n"; return false; }
	return true;
}

static bool readProxies(const std::string& path, Protocol defaultProto, std::vector<ProxyTarget>& out) {
	std::ifstream in(path);
	if (!in.is_open()) return false;
	std::string line;
	while (std::getline(in, line)) {
        auto v = parseProxyLineDetailed(line, defaultProto);
        if (!v) continue;
        const ParsedProxyLine& pl = *v;
        if (pl.explicitProto) {
            out.push_back(ProxyTarget{pl.proto, pl.host, pl.port, std::nullopt});
        } else {
            // Expand unspecified protocol to try all protocols and HTTP modes
            out.push_back(ProxyTarget{Protocol::HTTP, pl.host, pl.port, HttpMode::CONNECT});
            out.push_back(ProxyTarget{Protocol::HTTP, pl.host, pl.port, HttpMode::DIRECT});
            out.push_back(ProxyTarget{Protocol::SOCKS5, pl.host, pl.port, std::nullopt});
            out.push_back(ProxyTarget{Protocol::SOCKS4, pl.host, pl.port, std::nullopt});
        }
	}
	return true;
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
	if (!readProxies(settings.inputFile, settings.defaultProtocol, all)) {
		std::cerr << "Failed to read proxies from " << settings.inputFile << "\n";
		return 1;
	}
	if (all.empty()) {
		std::cerr << "No proxies found in input\n";
		return 1;
	}

	// Shard proxies across workers
	int workers = std::max(1, settings.numWorkers);
	std::vector<std::vector<ProxyTarget>> shards((size_t)workers);
	for (size_t i = 0; i < all.size(); ++i) {
		shards[i % shards.size()].push_back(std::move(all[i]));
	}

	Counters counters;
	std::vector<std::unique_ptr<Worker>> workerObjs;
	workerObjs.reserve((size_t)workers);
	for (int i = 0; i < workers; ++i) {
		workerObjs.emplace_back(std::make_unique<Worker>(i, settings, std::move(shards[(size_t)i]), counters));
	}
	uint64_t totalWork = (uint64_t)all.size();
	logf(settings.quiet, "Starting %d workers, total proxies: %" PRIu64, workers, totalWork);
	for (auto& w : workerObjs) w->start();
	for (auto& w : workerObjs) w->join();

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

