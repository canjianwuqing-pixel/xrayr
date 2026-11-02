#!/usr/bin/env python3
"""Run a built server against a loopback-only NewV2board fixture and TCP echo."""
import argparse
import http.server
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
import zipfile

from build import PLATFORMS, check_elf, digest


def exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise RuntimeError("Connection closed before echo completed")
        data += part
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--package", type=Path)
    source.add_argument("--binary", type=Path)
    parser.add_argument("--arch", choices=PLATFORMS, required=True)
    parser.add_argument("--mode", choices=["native", "emulated", "compat32", "development"], required=True)
    parser.add_argument("--emulator")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.mode == "native":
        expected = {"amd64": "x86_64", "arm64": "aarch64"}
        if platform.system() != "Linux" or platform.machine() != expected.get(args.arch) or args.emulator:
            raise SystemExit("Native acceptance requires the actual matching Linux runner")
    if args.mode == "compat32" and (args.arch != "386" or platform.system() != "Linux" or args.emulator):
        raise SystemExit("compat32 requires Linux x86 execution without QEMU")
    if args.mode == "emulated" and not args.emulator:
        raise SystemExit("Emulated acceptance must identify its emulator")

    identity = uuid.uuid4()
    token = uuid.uuid4().hex
    traffic = threading.Event()
    counts = {"echo_connections": 0, "upload": 0, "download": 0}
    lock = threading.Lock()
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    inbound_port = reservation.getsockname()[1]
    reservation.close()

    class Panel(http.server.BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def respond(self, body, etag=None):
            if etag and self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.end_headers()
                return
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if etag:
                self.send_header("ETag", etag)
            try:
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The server may close an in-flight report during shutdown.

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if urllib.parse.parse_qs(url.query).get("token") != [token]:
                self.send_error(403)
                return
            if url.path.endswith("/config"):
                self.respond({"server_port": inbound_port, "network": "tcp", "tls": 0, "flow": "",
                              "tls_settings": {"server_port": "443"}, "routes": [],
                              "base_config": {"push_interval": 1, "pull_interval": 1}}, '"node"')
            elif url.path.endswith("/user"):
                self.respond({"users": [{"id": 1, "uuid": str(identity), "speed_limit": 0, "device_limit": 0}]}, '"users"')
            elif url.path.endswith("/alivelist"):
                self.respond({"alive": {"1": 0}})
            else:
                self.send_error(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            if urllib.parse.urlsplit(self.path).path.endswith("/push"):
                with lock:
                    amount = body.get("1", [0, 0])
                    counts["upload"] += amount[0]
                    counts["download"] += amount[1]
                    if counts["upload"] > 0 and counts["download"] > 0:
                        traffic.set()
            self.respond({})

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with lock:
                counts["echo_connections"] += 1
            self.request.settimeout(10)
            try:
                while data := self.request.recv(16384):
                    self.request.sendall(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    panel = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Panel)
    panel.daemon_threads = True
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (panel, echo)]
    for thread in threads:
        thread.start()
    result = None
    output = ""
    try:
        with tempfile.TemporaryDirectory(prefix="kuaiyun-runtime-") as tmp:
            root = Path(tmp)
            if args.package:
                with zipfile.ZipFile(args.package) as z:
                    metadata = json.loads(z.read("BUILD-INFO.json"))
                    if metadata["platform"] != args.arch:
                        raise RuntimeError("Package platform mismatch")
                    for name, expected in metadata["file_sha256"].items():
                        if digest(z.read(name)) != expected:
                            raise RuntimeError("Package digest mismatch: " + name)
                    data = z.read("XrayR")
                    check_elf(data, args.arch)
                    binary = root / "XrayR"
                    binary.write_bytes(data)
                    binary.chmod(0o755)
            else:
                if args.mode != "development":
                    raise RuntimeError("Release acceptance must use the packaged binary")
                binary = args.binary.resolve()
                metadata = {}
            prefix = [args.emulator] if args.emulator else []
            version = subprocess.check_output(prefix + [str(binary), "version"], text=True, timeout=30)
            if "XrayR 0.9.4" not in version:
                raise RuntimeError("Unexpected runtime program version")
            # The target core blocks private destinations by default. Permit only this
            # temporary echo endpoint through an existing custom-outbound config.
            (root / "custom_outbound.json").write_text(json.dumps([{"tag": "runtime-loopback", "protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"],
                                              "network": "tcp", "port": str(echo.server_address[1])}]}}]), encoding="utf-8")
            (root / "route.json").write_text(json.dumps({"rules": [{"type": "field", "ip": ["127.0.0.1/32"],
                "port": str(echo.server_address[1]), "outboundTag": "runtime-loopback"}]}), encoding="utf-8")
            config = {"Log": {"Level": "warning"}, "OutboundConfigPath": "custom_outbound.json", "RouteConfigPath": "route.json",
                      "Nodes": [{"PanelType": "NewV2board",
                      "ApiConfig": {"ApiHost": "http://127.0.0.1:" + str(panel.server_port), "ApiKey": token,
                                    "NodeID": 1, "NodeType": "Vless", "EnableVless": True},
                      "ControllerConfig": {"ListenIP": "127.0.0.1", "SendIP": "127.0.0.1", "UpdatePeriodic": 1,
                                           "DisableSniffing": True, "GlobalDeviceLimitConfig": {"Enable": False}}}]}
            (root / "config.yml").write_text(json.dumps(config), encoding="utf-8")
            with (root / "server.log").open("w", encoding="utf-8") as log:
                process = subprocess.Popen(prefix + [str(binary), "-c", "config.yml"], cwd=root, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 45
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("Server exited during startup")
                        # A listening socket precedes dynamic user/limiter setup.
                        # Wait for the controller to finish before authenticating.
                        startup = (root / "server.log").read_text(encoding="utf-8", errors="replace")
                        if "Start user monitor periodic task" not in startup:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Controller did not finish user initialization")
                            time.sleep(0.1)
                            continue
                        try:
                            ready = socket.create_connection(("127.0.0.1", inbound_port), timeout=1)
                            ready.close()
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Server did not listen")
                            time.sleep(0.1)
                    payload = b"kuaiyun-native-echo\x00" * 2048
                    # Actual VLESS TCP authentication/address framing, with an IPv4 loopback destination.
                    header = b"\x00" + identity.bytes + b"\x00\x01" + echo.server_address[1].to_bytes(2, "big") + b"\x01\x7f\x00\x00\x01"
                    with socket.create_connection(("127.0.0.1", inbound_port), timeout=10) as client:
                        client.settimeout(15)
                        client.sendall(header + payload)
                        response = exact(client, 2)
                        if response[0] != 0:
                            raise RuntimeError("Invalid VLESS response version")
                        exact(client, response[1])
                        if exact(client, len(payload)) != payload:
                            raise RuntimeError("TCP echo data changed")
                    if not traffic.wait(30):
                        raise RuntimeError("Local panel did not receive both traffic counters")
                    before = counts["echo_connections"]
                    with socket.create_connection(("127.0.0.1", inbound_port), timeout=5) as rejected:
                        rejected.settimeout(5)
                        rejected.sendall(b"\x00" + uuid.uuid4().bytes + header[17:] + payload[:32])
                        try:
                            if rejected.recv(1):
                                raise RuntimeError("Unknown user received a VLESS response")
                        except ConnectionResetError:
                            pass
                    if counts["echo_connections"] != before:
                        raise RuntimeError("Unknown user reached the destination")
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    output = (root / "server.log").read_text(encoding="utf-8", errors="replace")
                    sanitized = re.sub(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "[ephemeral-user]", output).replace(token, "[ephemeral-token]")
                    (args.output / "runtime.log").write_text(sanitized, encoding="utf-8")
            clean_sigterm = process.returncode == 0
            if not clean_sigterm and args.mode != "development":
                raise RuntimeError("Server did not shut down cleanly")
            if "Xray Core Version: 26.7.28" not in output:
                raise RuntimeError("Runtime core version missing")
            result = {"status": "PASS", "platform": args.arch, "mode": args.mode, "host_system": platform.system(),
                      "host_machine": platform.machine(), "emulator": args.emulator, "source_commit": metadata.get("source_commit"),
                      "program_version": "0.9.4", "runtime_core_version": "26.7.28", "echo_bytes": len(payload),
                      "upload_counter": counts["upload"], "download_counter": counts["download"],
                      "unknown_user_rejected": True, "clean_sigterm": clean_sigterm,
                      "scope": "loopback NewV2board fixture and actual VLESS TCP forwarding; no real panel/VPS/client handshake"}
    finally:
        for server in (panel, echo):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
    (args.output / "runtime-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
