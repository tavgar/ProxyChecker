#!/usr/bin/env python3
import socket
import socketserver
import threading
import select
import struct
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Simple origin HTTP server that returns the client IP in body (for port 80 tests)
class OriginHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-Type", "text/plain")
		self.end_headers()
		# Return the connected peer IP (proxy's outbound IP)
		peer_ip = self.client_address[0]
		self.wfile.write(peer_ip.encode("ascii"))
	def log_message(self, format, *args):
		pass

# HTTP Direct proxy (acts like an HTTP server that forwards absolute-form requests)
class HttpDirectProxyHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		# Expect absolute-form URL like GET http://host[:port]/path
		# Parse Host header to connect
		host = self.headers.get("Host")
		if not host:
			self.send_error(400)
			return
		if ":" in host:
			domain, port_str = host.rsplit(":", 1)
			try:
				port = int(port_str)
			except ValueError:
				self.send_error(400)
				return
		else:
			domain, port = host, 80
		# Open upstream TCP
		try:
			up = socket.create_connection((domain, port), timeout=5.0)
		except OSError:
			self.send_error(502)
			return
		# Build origin-form request for upstream
		path = self.path
		# Convert absolute-form to origin-form for upstream
		if path.startswith("http://"):
			# Strip scheme://host[:port]
			rest = path.split("//", 1)[1]
			rest = rest.split("/", 1)
			path = "/" + (rest[1] if len(rest) > 1 else "")
		req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
		try:
			up.sendall(req.encode("ascii"))
			# Relay response
			self.send_response_only(200)
			# We'll just raw-forward the entire response from upstream to client
			# But BaseHTTPRequestHandler manages headers; so instead stream manually
			self.close_connection = True
			# hijack underlying socket
			self.connection.setblocking(False)
			up.setblocking(False)
			# Write our own simple response header; then copy body from upstream
			# Read upstream headers fully first
			buf = b""
			while True:
				ready, _, _ = select.select([up], [], [], 5.0)
				if not ready:
					break
				chunk = up.recv(65536)
				if not chunk:
					break
				buf += chunk
				if b"\r\n\r\n" in buf:
					break
			head_end = buf.find(b"\r\n\r\n")
			up_body = b""
			if head_end != -1:
				up_body = buf[head_end+4:]
			# Send minimal 200 OK header to client
			cli = self.connection
			cli.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n")
			# If upstream body started, forward it and the rest
			if up_body:
				cli.sendall(up_body)
			# Stream the rest of upstream
			while True:
				ready, _, _ = select.select([up], [], [], 5.0)
				if not ready:
					break
				chunk = up.recv(65536)
				if not chunk:
					break
				cli.sendall(chunk)
		except Exception:
			pass
		finally:
			try:
				up.close()
			except Exception:
				pass
	def log_message(self, format, *args):
		pass

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
	allow_reuse_address = True

daemon_threads = True

# HTTP CONNECT proxy
class ConnectHandler(BaseHTTPRequestHandler):
	def do_CONNECT(self):
		# Path like host:port
		try:
			host, port_str = self.path.rsplit(":", 1)
			port = int(port_str)
		except Exception:
			self.send_error(400)
			return
		try:
			up = socket.create_connection((host, port), timeout=5.0)
		except OSError:
			self.send_error(502)
			return
		# Send 200 and tunnel bytes
		self.send_response(200, "Connection Established")
		self.end_headers()
		self.connection.setblocking(False)
		up.setblocking(False)
		# Relay until either closes
		while True:
			r, _, _ = select.select([self.connection, up], [], [], 5.0)
			if not r:
				break
			if self.connection in r:
				data = None
				try:
					data = self.connection.recv(65536)
				except Exception:
					data = b""
				if not data:
					break
				up.sendall(data)
			if up in r:
				data = None
				try:
					data = up.recv(65536)
				except Exception:
					data = b""
				if not data:
					break
				self.connection.sendall(data)
		try:
			up.close()
		except Exception:
			pass
	def log_message(self, format, *args):
		pass

# Minimal SOCKS5 server (no auth, CONNECT only, domain or IPv4)
class Socks5Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True

class Socks5Handler(socketserver.BaseRequestHandler):
	def handle(self):
		self.request.settimeout(5.0)
		try:
			with open("/tmp/mock_socks5.log","a") as lg:
				lg.write("S5: connection from %s\n"% (self.client_address,))
		except Exception:
			pass
		# Greeting
		data = self._recvn(2)
		if not data or data[0] != 0x05:
			return
		nmeth = data[1]
		methods = self._recvn(nmeth)
		# Respond no-auth
		self.request.sendall(b"\x05\x00")
		# Request
		hdr = self._recvn(4)
		if not hdr or hdr[0] != 0x05 or hdr[1] != 0x01:
			return
		atyp = hdr[3]
		if atyp == 0x01:
			addr = self._recvn(4)
			host = socket.inet_ntoa(addr)
		elif atyp == 0x03:
			dlen = self._recvn(1)[0]
			host = self._recvn(dlen).decode("ascii")
		elif atyp == 0x04:
			addr = self._recvn(16)
			host = socket.inet_ntop(socket.AF_INET6, addr)
		else:
			return
		port = struct.unpack("!H", self._recvn(2))[0]
		try:
			with open("/tmp/mock_socks5.log","a") as lg:
				lg.write(f"S5: CONNECT {host}:{port}\n")
		except Exception:
			pass
		# Connect upstream
		try:
			up = socket.create_connection((host, port), timeout=5.0)
		except OSError:
			self.request.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
			return
		# Success reply with IPv4 0.0.0.0:0
		self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
		self._relay(self.request, up)
		try:
			up.close()
		except Exception:
			pass
	def _recvn(self, n):
		buf = b""
		while len(buf) < n:
			chunk = self.request.recv(n - len(buf))
			if not chunk:
				return b""
			buf += chunk
		return buf
	def _relay(self, a, b):
		a.setblocking(False)
		b.setblocking(False)
		while True:
			r, _, _ = select.select([a, b], [], [], 5.0)
			if not r:
				break
			if a in r:
				data = a.recv(65536)
				if not data:
					break
				b.sendall(data)
			if b in r:
				data = b.recv(65536)
				if not data:
					break
				a.sendall(data)

# Minimal SOCKS4a server (CONNECT only)
class Socks4Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True

class Socks4Handler(socketserver.BaseRequestHandler):
	def handle(self):
		self.request.settimeout(5.0)
		try:
			with open("/tmp/mock_socks4.log","a") as lg:
				lg.write("S4: connection from %s\n"% (self.client_address,))
		except Exception:
			pass
		data = self._recvn(8)
		if not data or data[0] != 0x04 or data[1] != 0x01:
			return
		port = struct.unpack("!H", data[2:4])[0]
		ip = data[4:8]
		# Read userid until 0x00
		while True:
			b = self._recvn(1)
			if not b or b == b"\x00":
				break
		# SOCKS4a: if IP is 0.0.0.x then next is domain string
		if ip[:3] == b"\x00\x00\x00" and ip[3] != 0x00:
			host = self._read_cstr()
		else:
			host = socket.inet_ntoa(ip)
		try:
			with open("/tmp/mock_socks4.log","a") as lg:
				lg.write(f"S4: CONNECT {host}:{port}\n")
		except Exception:
			pass
		try:
			up = socket.create_connection((host, port), timeout=5.0)
		except OSError:
			self.request.sendall(b"\x00\x5B" + b"\x00\x00\x00\x00\x00\x00")
			return
		# Grant
		self.request.sendall(b"\x00\x5A" + b"\x00\x00\x00\x00\x00\x00")
		self._relay(self.request, up)
		try:
			up.close()
		except Exception:
			pass
	def _read_cstr(self):
		buf = b""
		while True:
			b = self._recvn(1)
			if not b or b == b"\x00":
				break
			buf += b
		return buf.decode("ascii")
	def _recvn(self, n):
		buf = b""
		while len(buf) < n:
			chunk = self.request.recv(n - len(buf))
			if not chunk:
				return b""
			buf += chunk
		return buf
	def _relay(self, a, b):
		a.setblocking(False)
		b.setblocking(False)
		while True:
			r, _, _ = select.select([a, b], [], [], 5.0)
			if not r:
				break
			if a in r:
				data = a.recv(65536)
				if not data:
					break
				b.sendall(data)
			if b in r:
				data = b.recv(65536)
				if not data:
					break
				a.sendall(data)


def start_servers():
	# Origin HTTP server on port 18080
	origin = ThreadingHTTPServer(("127.0.0.1", 18080), OriginHandler)
	th_origin = threading.Thread(target=origin.serve_forever, daemon=True)
	th_origin.start()
	# HTTP direct proxy on port 18081
	http_direct = ThreadingHTTPServer(("127.0.0.1", 18081), HttpDirectProxyHandler)
	th_hd = threading.Thread(target=http_direct.serve_forever, daemon=True)
	th_hd.start()
	# HTTP CONNECT proxy on port 18082
	connect_proxy = ThreadingHTTPServer(("127.0.0.1", 18082), ConnectHandler)
	th_cp = threading.Thread(target=connect_proxy.serve_forever, daemon=True)
	th_cp.start()
	# SOCKS5 on port 18083
	s5 = Socks5Server(("127.0.0.1", 18083), Socks5Handler)
	th_s5 = threading.Thread(target=s5.serve_forever, daemon=True)
	th_s5.start()
	# SOCKS4 on port 18084
	s4 = Socks4Server(("127.0.0.1", 18084), Socks4Handler)
	th_s4 = threading.Thread(target=s4.serve_forever, daemon=True)
	th_s4.start()
	# Dummy TCP listener on 443 for HTTPS CONNECT upstream success (optional)
	class _Dummy(socketserver.BaseRequestHandler):
		def handle(self):
			try:
				# read and discard
				self.request.settimeout(2.0)
				self.request.recv(1)
			except Exception:
				pass
			try:
				self.request.close()
			except Exception:
				pass
	try:
		dummy443 = socketserver.TCPServer(("127.0.0.1", 443), _Dummy)
		dummy443.allow_reuse_address = True
		th_d443 = threading.Thread(target=dummy443.serve_forever, daemon=True)
		th_d443.start()
	except Exception:
		dummy443 = None
	return {
		"origin": origin,
		"http_direct": http_direct,
		"http_connect": connect_proxy,
		"socks5": s5,
		"socks4": s4,
		"dummy443": dummy443,
	}


def stop_servers(servers):
	for srv in servers.values():
		try:
			srv.shutdown()
			srv.server_close()
		except Exception:
			pass

if __name__ == "__main__":
	# For manual debugging
	servers = start_servers()
	print("servers started on 127.0.0.1: origin=18080, http_direct=18081, http_connect=18082, socks5=18083, socks4=18084")
	try:
		threading.Event().wait()
	except KeyboardInterrupt:
		pass
	finally:
		stop_servers(servers)
