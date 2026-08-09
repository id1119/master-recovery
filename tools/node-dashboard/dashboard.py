#!/usr/bin/env python3
"""Node uptime dashboard backend for the guardian protocol docker network."""

import json
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "compose.network.yml"


def parse_created(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parts = value.split()
        naive = datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")
        return naive
    except (ValueError, IndexError):
        return None


def fetch_status():
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip() or f"exit {result.returncode}"}
        try:
            return parse_ps_output(result.stdout)
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as error:
            return {"error": f"invalid docker compose status output: {error}"}
    except FileNotFoundError:
        return {"error": "docker not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"error": "docker compose timed out"}


def parse_ps_output(stdout):
    entries = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("["):
            try:
                entries = json.loads(line)
            except json.JSONDecodeError:
                continue
            break
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    ids = [entry.get("ID", "") for entry in entries if entry.get("ID")]
    inspect = fetch_inspect(ids)
    stats = fetch_stats(ids)
    nodes = []
    for entry in entries:
        container_id = entry.get("ID", "")
        lookup_id = container_id[:12]
        started = parse_time(inspect.get(lookup_id, {}).get("started_at"))
        created = parse_created(entry.get("CreatedAt"))
        started = started if started is not None else created
        uptime = None
        if started is not None:
            uptime = max(0, int(time.time() - started.timestamp()))
        nodes.append({
            "name": entry.get("Name"),
            "service": entry.get("Service"),
            "state": entry.get("State"),
            "health": entry.get("Health"),
            "status": entry.get("Status"),
            "uptime_secs": uptime,
            "ports": entry.get("Ports") or "",
            "container_id": container_id,
            "image": entry.get("Image") or "",
            "exit_code": entry.get("ExitCode"),
            "restart_count": inspect.get(lookup_id, {}).get("restart_count"),
            "memory": stats.get(lookup_id, {}).get("memory"),
        })
    nodes.sort(key=lambda node: _sort_key(node["service"]))
    return {"nodes": nodes, "fetched_at": time.time()}


def fetch_inspect(container_ids):
    result = {}
    if not container_ids:
        return result
    try:
        output = subprocess.run(
            ["docker", "inspect", "--format", "{{json .}}"] + container_ids,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            cwd=REPO_ROOT,
        )
        if output.returncode != 0:
            return result
        for line in output.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                info = json.loads(line)
            except json.JSONDecodeError:
                continue
            result[info.get("Id", "")[:12]] = {
                "started_at": info.get("State", {}).get("StartedAt"),
                "restart_count": info.get("RestartCount"),
            }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def fetch_stats(container_ids):
    result = {}
    if not container_ids:
        return result
    try:
        output = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"] + container_ids,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            cwd=REPO_ROOT,
        )
        if output.returncode == 0:
            for line in output.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    stats = json.loads(line)
                except json.JSONDecodeError:
                    continue
                result[stats.get("ID", "")[:12]] = {"memory": stats.get("MemUsage")}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _sort_key(service):
    base_order = [
        "relay",
        "relay-2",
        "relay-3",
        "config-store",
        "config-store-2",
        "config-store-3",
        "signer-1",
        "signer-2",
        "signer-3",
        "guardian-1",
        "guardian-2",
        "guardian-3",
        "guardian-4",
        "guardian-5",
        "guardian-6",
        "guardian-7",
        "guardian-8",
    ]
    if service in base_order:
        return base_order.index(service)
    return len(base_order)


HTML_PATH = Path(__file__).parent / "dashboard.html"


class Handler(BaseHTTPRequestHandler):
    server_version = "GuardianDashboard"
    sys_version = ""

    def do_GET(self):
        if self.path == "/api/status":
            self._json(fetch_status())
        elif self.path in ("/", "/index.html"):
            body = HTML_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def _json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))


def main():
    port = 8788
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Guardian node dashboard on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
