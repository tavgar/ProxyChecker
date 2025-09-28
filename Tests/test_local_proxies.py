#!/usr/bin/env python3
import os
import subprocess
import tempfile
import time
import signal
from pathlib import Path

from mock_proxies import start_servers, stop_servers

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "proxychecker"

def wait_for_port(host, port, timeout=3.0):
	import socket
	t0 = time.time()
	while time.time() - t0 < timeout:
		try:
			s = socket.create_connection((host, port), timeout=0.5)
			s.close()
			return True
		except OSError:
			time.sleep(0.05)
	return False


def run():
	servers = start_servers()
	try:
		# Ensure services are listening
		for p in [18080, 18081, 18082, 18083, 18084]:
			assert wait_for_port("127.0.0.1", p), f"port {p} not ready"
		# Prepare input list
		inp = tempfile.NamedTemporaryFile(delete=False, mode="w", prefix="proxies_", suffix=".txt")
		inp_path = inp.name
		# Use both scheme prefixes and trailing ,proto variants
		# http direct proxy listens 18081 and will forward to test host; we test both direct and connect modes
		lines = [
			"http://127.0.0.1:18082",
			"https://127.0.0.1:18082",
			"127.0.0.1:18082",
			"socks5://127.0.0.1:18083",
			"127.0.0.1:18084,socks4",
		]
		inp.write("\n".join(lines))
		inp.flush(); inp.close()
		out_file = tempfile.NamedTemporaryFile(delete=False, mode="w", prefix="good_", suffix=".txt").name
		# Run proxychecker; use test-host origin at port 18080 so HTTP CONNECT goes to a reachable upstream
		cmd = [
			str(BIN), "--in", inp_path, "--out", out_file,
			"--workers", "1", "--concurrency", "10",
			"--test-host", "127.0.0.1", "--test-port", "18080", "--test-path", "/",
			"--http-mode", "connect",
			"--timeout", "3", "--no-strict", "--disable-ip-masking",
		]
		# Launch
		env = os.environ.copy()
		p = subprocess.run(cmd, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
		if p.returncode != 0:
			print(p.stdout)
			print(p.stderr)
			raise SystemExit(f"proxychecker failed: {p.returncode}")
		# Read outputs
		with open(out_file, "r") as f:
			out_lines = {line.strip() for line in f if line.strip()}
		expected = {
			"http://127.0.0.1:18082",
			"socks5://127.0.0.1:18083",
			"socks4://127.0.0.1:18084",
		}
		missing = expected - out_lines
		if missing:
			print("STDOUT:\n", p.stdout)
			print("STDERR:\n", p.stderr)
			raise AssertionError(f"Missing expected proxies: {missing}. Got: {out_lines}")
		print("OK: all proxies detected")
	finally:
		stop_servers(servers)

if __name__ == "__main__":
	run()
