#!/usr/bin/env python3
"""Isolated CLI/subscription/DNS/observed-group smoke; no system changes."""
from pathlib import Path
import http.server
import json
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parent.parent
mode = {"bad": False, "updated": False}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(204)
            self.end_headers()
            return
        extra = ",{name: extra, type: direct}" if mode["updated"] else ""
        body = ("proxy-providers:\n pool:\n  type: inline\n  payload: [{name: node, type: direct}%s]\n"
                "  health-check: {enable: true, url: 'http://127.0.0.1:%d/health', lazy: false}\n"
                "proxy-groups:\n - {name: Auto, type: url-test, use: [pool], url: 'http://127.0.0.1:%d/health', lazy: false}\n"
                " - {name: Choice, type: select, proxies: [Auto, DIRECT]}\n"
                "dns: {enable: true, nameserver: [192.0.2.53], enhanced-mode: fake-ip, fake-ip-ttl: 60%s}\n"
                "rules: ['MATCH,Choice']\n" % (extra, self.server.server_port, self.server.server_port,
                                               ", unsupported-option: true" if mode["bad"] else "")).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    root = Path(tempfile.mkdtemp(prefix="reka-cli-smoke-"))
    log = open(root / "daemon.log", "w")
    process = None

    def cli(*args, ok=True, as_json=True):
        command = [str(REPO / "bin/rekactl"), "-state-root", str(root)]
        if as_json:
            command.append("-json")
        result = subprocess.run(command + list(args), capture_output=True, text=True, timeout=20)
        if (result.returncode == 0) != ok:
            raise RuntimeError(f"CLI failed: {args}: {result.stderr} {result.stdout}")
        return json.loads(result.stdout) if as_json and result.stdout.strip() else result.stdout

    def start(initial=False):
        nonlocal process
        args = [str(REPO / "bin/reka"), "-state-root", str(root), "-edit-dir", "-"]
        if initial:
            args += ["-profile", str(root / "initial.yaml")]
        process = subprocess.Popen(args, stdout=log, stderr=log)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("daemon exited")
            try:
                cli("status")
                return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("daemon not ready")

    def stop():
        nonlocal process
        if process is not None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            process = None

    try:
        (root / "initial.yaml").write_text("schema-version: 1\nrules: [{match: {all: true}, outbound: direct}]\n")
        start(True)
        endpoint = f"http://127.0.0.1:{server.server_port}/root"
        cli("subscription", "set", "airport", endpoint)
        assert cli("subscription", "refresh", "airport")["state"] == "current"
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dns_port = probe.getsockname()[1]
        probe.close()
        (root / "profile.yaml").write_text(
            "schema-version: 1\nimports: [{source: airport, outbounds: true, groups: true}]\n"
            f"dns: {{from: airport, listen: '127.0.0.1:{dns_port}'}}\nrules: [{{source: airport}}]\n")
        plan = cli("plan", str(root / "profile.yaml"))
        assert plan["valid"] and plan["plan"]["dns_changed"]
        cli("commit", str(root / "profile.yaml"), "-yes")
        cfg = cli("get", "effective")
        choice = next(key for key, item in cfg["effective"]["group_metadata"].items() if item["name"] == "Choice")
        cli("select", choice, "direct")
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            states = cli("group-status")
            if states and all(s["results"] and all(r["alive"] for r in s["results"]) for s in states):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("health observations missing")
        assert cli("group-status", as_json=False).strip()
        revision = cli("status")["revision"]
        time.sleep(0.1)
        assert cli("status")["revision"] == revision
        assert cli("explain", "example.test:443")["outbound"] == "direct"
        origin = cli("origin", "/dns/nameserver/#0")
        assert origin["layer"] == "source"

        def fake_address():
            name = b"\x09accept-ok\x04test\x00"
            wire = struct.pack("!6H", 1234, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(2)
                udp.sendto(wire, ("127.0.0.1", dns_port))
                reply = udp.recv(4096)
            header = struct.unpack("!6H", reply[:12])
            assert header[0] == 1234 and header[1] & 15 == 0 and header[3] == 1
            return socket.inet_ntoa(reply[-4:])

        address = fake_address()
        assert address.startswith("198.18."), address
        mode["updated"] = True
        assert cli("subscription", "refresh", "airport")["state"] == "current"
        assert cli("explain", "example.test:443")["outbound"] == "direct"
        revision = cli("status")["revision"]
        mode["bad"] = True
        assert cli("subscription", "refresh", "airport", ok=False)["stale"]
        assert cli("status")["revision"] == revision
        stop()
        server.shutdown()
        server.server_close()
        start()
        assert fake_address() == address
        assert cli("explain", "example.test:443")["outbound"] == "direct"
        print(json.dumps({key: "passed" for key in ["CLI", "subscription+provider+DNS", "group-status",
              "health-keeps-revision", "refresh-keeps-manual-selection", "invalid-refresh-keeps-revision",
              "DNS-provenance", "Fake-IP-offline-restart"]}, indent=2))
    finally:
        stop()
        server.shutdown()
        server.server_close()
        log.close()
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
