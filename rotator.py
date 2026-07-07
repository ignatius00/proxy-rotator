#!/usr/bin/env python3
"""
proxy-rotator — Timer-based SOCKS5 proxy rotator.

Runs a local SOCKS5 proxy on 127.0.0.1:18800 that chains through
a rotating pool of upstream SOCKS5 proxies. Switches which upstream
proxy it uses every N minutes, transparently.

Usage:
    python3 rotator.py                    # auto-detect proxies.txt
    python3 rotator.py --interval 300     # rotate every 5 minutes
    python3 rotator.py --port 18800
    python3 rotator.py --proxies my-proxies.txt

No dependencies outside Python stdlib.
"""

import argparse
import asyncio
import logging
import os
import signal
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("rotator")

# ── SOCKS5 constants ──────────────────────────────────────────
SOCKS5_VER = 0x05
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REPLY_SUCCESS = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_CONN_NOT_ALLOWED = 0x02
REPLY_NET_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONN_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_CMD_NOT_SUPPORTED = 0x07
REPLY_ATYPE_NOT_SUPPORTED = 0x08
AUTH_NO_AUTH = 0x00
AUTH_USERPASS = 0x02


@dataclass
class UpstreamProxy:
    """A single upstream SOCKS5 proxy."""
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @classmethod
    def from_string(cls, s: str) -> "UpstreamProxy":
        parts = s.strip().split(":")
        if len(parts) == 4:
            return cls(parts[0], int(parts[1]), parts[2], parts[3])
        elif len(parts) == 2:
            return cls(parts[0], int(parts[1]))
        raise ValueError(f"Invalid proxy format (expect ip:port or ip:port:user:pass): {s!r}")

    @property
    def display(self) -> str:
        return f"{self.host}:{self.port}"


class ProxyPool:
    """Round-robin proxy pool with timer-based rotation."""

    def __init__(self, proxies: list[UpstreamProxy], interval_sec: int = 300):
        if not proxies:
            raise ValueError("Proxy list is empty")
        self.proxies = proxies
        self.interval = interval_sec
        self._index = 0
        self._last_rotate = 0.0
        self._rotations = 0

    @property
    def current(self) -> UpstreamProxy:
        return self.proxies[self._index]

    @property
    def uptime(self) -> float:
        """Seconds since last rotation."""
        return time.monotonic() - self._last_rotate if self._last_rotate else 0

    def rotate(self) -> UpstreamProxy:
        self._index = (self._index + 1) % len(self.proxies)
        self._last_rotate = time.monotonic()
        self._rotations += 1
        return self.current

    def start(self):
        """Mark the start time (called when server begins)."""
        if not self._last_rotate:
            self._last_rotate = time.monotonic()

    def tick(self) -> bool:
        """Check if rotation is due; if so, rotate and return True."""
        if time.monotonic() - self._last_rotate >= self.interval:
            old = self.proxies[self._index].display
            new = self.rotate().display
            log.info("🔄 Rotated %s → %s  (rotation #%d, pool size: %d)",
                       old, new, self._rotations, len(self.proxies))
            return True
        return False

    def rotate_healthy(self, health_check_fn) -> bool:
        """Rotate, skipping dead proxies until a healthy one is found.
        Returns True if a healthy proxy was found, False if all are dead.
        """
        attempts = 0
        while attempts < len(self.proxies):
            next_idx = (self._index + 1) % len(self.proxies)
            candidate = self.proxies[next_idx]
            healthy = health_check_fn(candidate)
            if healthy:
                old = self.current.display
                self._index = next_idx
                self._last_rotate = time.monotonic()
                self._rotations += 1
                log.info("🔄 Rotated %s → %s  (rotation #%d, pool size: %d)",
                           old, candidate.display, self._rotations, len(self.proxies))
                return True
            else:
                log.warning("⏭ Skipping dead proxy %s — trying next", candidate.display)
                self._index = next_idx
                self._rotations += 1
            attempts += 1
        log.error("✗ All %d proxies are dead!", len(self.proxies))
        return False

    def set_working_index(self, health_check_fn) -> bool:
        """Find the first healthy proxy starting from current index."""
        attempts = 0
        start = self._index
        while attempts < len(self.proxies):
            candidate = self.proxies[start]
            if health_check_fn(candidate):
                if start != self._index:
                    log.info("✅ Found working proxy %s (was at index %d)", candidate.display, self._index)
                    self._index = start
                    self._last_rotate = time.monotonic()
                return True
            else:
                log.warning("⏭ Proxy %s is dead — testing next", candidate.display)
            start = (start + 1) % len(self.proxies)
            attempts += 1
        log.error("✗ All %d proxies are dead on startup!", len(self.proxies))
        return False

    def status(self) -> dict:
        return {
            "current": self.current.display,
            "index": self._index,
            "total": len(self.proxies),
            "rotations": self._rotations,
            "uptime_sec": int(self.uptime),
            "next_rotation_sec": max(0, self.interval - int(self.uptime)),
            "health_check": True,
        }


# ── SOCKS5 protocol helpers ──────────────────────────────────

async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly n bytes, raising on EOF."""
    data = await reader.readexactly(n)
    return data


async def socks5_connect_upstream(
    proxy: UpstreamProxy,
    dst_host: str,
    dst_port: int,
    *,
    connect_timeout: float = 10,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connect through an upstream SOCKS5 proxy to dst_host:dst_port.
    Returns (reader, writer) for the proxied connection.
    """

    # Open TCP connection to the upstream proxy
    up_reader, up_writer = await asyncio.wait_for(
        asyncio.open_connection(proxy.host, proxy.port),
        timeout=connect_timeout,
    )

    try:
        # ── Step 1: Greet ──
        if proxy.username:
            methods = bytes([SOCKS5_VER, 2, AUTH_NO_AUTH, AUTH_USERPASS])
        else:
            methods = bytes([SOCKS5_VER, 1, AUTH_NO_AUTH])

        up_writer.write(methods)
        await up_writer.drain()

        ver, chosen = await _read_exact(up_reader, 2)
        if ver != SOCKS5_VER:
            raise RuntimeError(f"Bad SOCKS version from upstream: {ver}")

        # ── Step 2: Authenticate if needed ──
        if chosen == AUTH_USERPASS:
            uname_bytes = proxy.username.encode()
            passwd_bytes = proxy.password.encode()
            auth_msg = b"\x01" + struct.pack("B", len(uname_bytes)) + uname_bytes + \
                       struct.pack("B", len(passwd_bytes)) + passwd_bytes
            up_writer.write(auth_msg)
            await up_writer.drain()

            ver, status = await _read_exact(up_reader, 2)
            if status != 0x00:
                raise RuntimeError(f"Upstream proxy auth failed (status={status})")

        elif chosen != AUTH_NO_AUTH:
            raise RuntimeError(f"Upstream proxy rejected no-auth, got method={chosen}")

        # ── Step 3: Send CONNECT request ──
        if isinstance(dst_host, str) and dst_host.count(".") != 4:
            # Domain name
            host_bytes = dst_host.encode()
            req = struct.pack("!BBBB", SOCKS5_VER, CMD_CONNECT, 0x00, ATYP_DOMAIN)
            req += struct.pack("B", len(host_bytes)) + host_bytes
        else:
            # IPv4
            parts = dst_host.split(".")
            req = struct.pack("!BBBB", SOCKS5_VER, CMD_CONNECT, 0x00, ATYP_IPV4)
            req += bytes(int(p) for p in parts)

        req += struct.pack("!H", dst_port)
        up_writer.write(req)
        await up_writer.drain()

        # ── Step 4: Read response ──
        header = await _read_exact(up_reader, 4)
        if header[1] != REPLY_SUCCESS:
            error_names = {
                0x01: "general failure",
                0x02: "connection not allowed",
                0x03: "network unreachable",
                0x04: "host unreachable",
                0x05: "connection refused",
                0x06: "TTL expired",
                0x07: "command not supported",
                0x08: "address type not supported",
            }
            raise RuntimeError(f"Upstream proxy error: {error_names.get(header[1], f'reply={header[1]}')}")

        # Read the rest of the bind address (atype + addr + port)
        atype = header[3]
        if atype == ATYP_IPV4:
            await _read_exact(up_reader, 6)
        elif atype == ATYP_DOMAIN:
            domain_len = await _read_exact(up_reader, 1)
            await _read_exact(up_reader, domain_len[0] + 2)
        elif atype == ATYP_IPV6:
            await _read_exact(up_reader, 18)

        return up_reader, up_writer

    except Exception:
        up_writer.close()
        raise


async def send_socks5_reply(writer: asyncio.StreamWriter, reply_code: int):
    """Send a SOCKS5 reply to the local client."""
    writer.write(bytes([SOCKS5_VER, reply_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
    await writer.drain()


async def check_proxy_health(
    proxy: UpstreamProxy,
    test_url: str = "https://api.ipify.org",
    timeout: int = 10,
) -> bool:
    """Test if a proxy is working by connecting through it.
    Returns True if the proxy responded successfully.
    """
    try:
        up_reader, up_writer = await socks5_connect_upstream(
            proxy, "api.ipify.org", 443,
            connect_timeout=timeout,
        )
        # Send a minimal HTTPS request (just to verify the tunnel works)
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: api.ipify.org\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        up_writer.write(request)
        await up_writer.drain()
        response = await asyncio.wait_for(up_reader.read(1024), timeout=timeout)
        up_writer.close()
        return len(response) > 0
    except Exception as e:
        err_type = type(e).__name__
        err_msg = str(e) or "no details"
        log.debug("Health check %s failed [%s: %s]", proxy.display, err_type, err_msg)
        return False


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    pool: ProxyPool,
    connect_timeout: int = 15,
):
    """Handle a single SOCKS5 client connection."""
    client_addr = writer.get_extra_info("peername")
    log.debug("New connection from %s:%s", *client_addr or ("?", "?"))

    try:
        # ── Receive greeting ──
        data = await _read_exact(reader, 2)
        if data[0] != SOCKS5_VER:
            writer.close()
            return
        nmethods = data[1]
        methods = await _read_exact(reader, nmethods)

        # We support no-auth only (the upstream handles auth)
        writer.write(bytes([SOCKS5_VER, AUTH_NO_AUTH]))
        await writer.drain()

        # ── Receive request ──
        header = await _read_exact(reader, 4)
        ver, cmd, rsv, atype = header

        if cmd != CMD_CONNECT:
            await send_socks5_reply(writer, REPLY_CMD_NOT_SUPPORTED)
            writer.close()
            return

        # Parse destination address
        if atype == ATYP_IPV4:
            addr_bytes = await _read_exact(reader, 4)
            dst_host = ".".join(str(b) for b in addr_bytes)
        elif atype == ATYP_DOMAIN:
            domain_len = await _read_exact(reader, 1)
            dst_host = (await _read_exact(reader, domain_len[0])).decode()
        elif atype == ATYP_IPV6:
            dst_host = await _read_exact(reader, 16)
        else:
            await send_socks5_reply(writer, REPLY_ATYPE_NOT_SUPPORTED)
            writer.close()
            return

        dst_port = struct.unpack("!H", await _read_exact(reader, 2))[0]

        # ── Get current proxy and connect through it ──
        proxy = pool.current
        log.debug("Proxying %s:%d → %s ...", dst_host, dst_port, proxy.display)

        try:
            up_reader, up_writer = await socks5_connect_upstream(
                proxy, dst_host, dst_port,
                connect_timeout=connect_timeout,
            )
        except Exception as e:
            err_type = type(e).__name__
            err_msg = str(e) or "no details"
            log.warning("✗ %s → %s:%s failed [%s: %s]", proxy.display, dst_host, dst_port, err_type, err_msg)
            await send_socks5_reply(writer, REPLY_HOST_UNREACHABLE)
            writer.close()
            return

        # Tell client success
        await send_socks5_reply(writer, REPLY_SUCCESS)

        # ── Bidirectional pipe ──
        async def _piped(src, dst, label):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                pass
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except OSError:
                    pass

        await asyncio.gather(
            _piped(reader, up_writer, "C→U"),
            _piped(up_reader, writer, "U→C"),
        )

    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        log.debug("Client handler error: %s", e)
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def rotation_loop(pool: ProxyPool, check_interval: float = 5.0,
                        health_check_fn=None, health_check_interval: int = 300):
    """Background task that checks the timer and rotates when due.
    If health_check_fn is provided, it tests the next proxy before switching
    and skips dead ones.
    """
    last_full_check = 0.0
    while True:
        await asyncio.sleep(check_interval)

        # Timer-based rotation
        if time.monotonic() - pool._last_rotate >= pool.interval:
            if health_check_fn:
                # health-checked rotation
                if not pool.rotate_healthy(health_check_fn):
                    log.error("Rotation failed — all proxies dead!")
            else:
                pool.tick()

        # Periodically re-check current proxy health
        if health_check_fn and time.monotonic() - last_full_check >= health_check_interval:
            last_full_check = time.monotonic()
            if not health_check_fn(pool.current):
                log.warning("⚠ Current proxy %s failed periodic health check — rotating",
                            pool.current.display)
                if not pool.rotate_healthy(health_check_fn):
                    log.error("All proxies dead after periodic check!")


async def status_server(host: str, port: int, pool: ProxyPool):
    """Simple HTTP status endpoint — curl http://localhost:PORT/"""
    import json

    HTML = """<!DOCTYPE html>
<html><head><title>proxy-rotator</title>
<style>body{{font:14px/1.6 sans-serif;margin:2em}}
pre{{background:#f5f5f5;padding:1em;border-radius:4px}}
.status-ok{{color:#090}} .status-err{{color:#c00}}
</style></head><body>
<h1>🔄 proxy-rotator</h1>
<pre>{json}</pre>
</body></html>"""

    async def handle(rd: asyncio.StreamReader, wr: asyncio.StreamWriter):
        try:
            await rd.readuntil(b"\r\n")
            # drain the rest
            while True:
                line = await rd.readuntil(b"\n")
                if line in (b"\r\n", b"\n"):
                    break
            status = pool.status()
            body = json.dumps(status, indent=2)
            html = HTML.format(json=body)
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(html)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{html}"
            ).encode()
            wr.write(resp)
            await wr.drain()
        except Exception:
            pass
        finally:
            try:
                wr.close()
            except OSError:
                pass

    server = await asyncio.start_server(handle, host, port)
    log.info("📊 Status page at http://%s:%d/  (curl %s:%d/)", host, port, host, port)
    async with server:
        await server.serve_forever()


def load_proxies(path: str) -> list[UpstreamProxy]:
    """Load proxy list from a text file."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        print(f"✗ Proxy file not found: {p}")
        sys.exit(1)

    proxies = []
    with open(p) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                proxies.append(UpstreamProxy.from_string(line))
            except ValueError as e:
                print(f"✗ {p}:{lineno}: {e}")
                sys.exit(1)

    if not proxies:
        print(f"✗ No proxies found in {p}")
        sys.exit(1)

    return proxies


async def main():
    parser = argparse.ArgumentParser(
        description="Timer-based SOCKS5 proxy rotator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                         # auto-detect proxies.txt, 5min rotation\n"
            "  %(prog)s --interval 180          # rotate every 3 minutes\n"
            "  %(prog)s --port 2080 --status 9090\n"
        ),
    )
    parser.add_argument("--proxies", default="proxies.txt",
                        help="Proxy list file (ip:port or ip:port:user:pass per line)")
    parser.add_argument("--interval", type=int, default=300,
                        help="Rotation interval in seconds (default: 300 = 5 min)")
    parser.add_argument("--port", type=int, default=18800,
                        help="Local SOCKS5 proxy port (default: 18800)")
    parser.add_argument("--listen", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--status-port", type=int, default=0,
                        help="HTTP status page port (0 = disabled)")
    parser.add_argument("--status-listen", default="127.0.0.1",
                        help="Status page bind address")
    parser.add_argument("--connect-timeout", type=int, default=15,
                        help="Connection timeout per upstream (default: 15s)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--log-file",
                        help="Log to file instead of stderr")
    parser.add_argument("--health-check", action="store_true", default=True,
                        help="Enable proxy health checks on rotation and startup (default: on)")
    parser.add_argument("--no-health-check", action="store_false", dest="health_check",
                        help="Disable proxy health checks")
    parser.add_argument("--health-check-timeout", type=int, default=8,
                        help="Seconds to wait per health check (default: 8)")
    parser.add_argument("--health-check-interval", type=int, default=600,
                        help="Seconds between periodic full health re-checks (default: 600)")

    args = parser.parse_args()

    # ── Logging ──
    level = logging.DEBUG if args.debug else logging.INFO
    handlers = []
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    elif sys.stderr.isatty() or args.debug:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers or [logging.StreamHandler(sys.stdout)],
    )

    # ── Load proxies ──
    proxies = load_proxies(args.proxies)
    log.info("Loaded %d proxies from %s", len(proxies), args.proxies)

    # ── Build pool ──
    pool = ProxyPool(proxies, interval_sec=args.interval)
    pool.start()
    status = pool.status()

    # ── Health check setup ──
    health_check_fn = None
    if args.health_check:
        health_test_host = "api.ipify.org"
        health_test_port = 443

        async def _health_check(proxy: UpstreamProxy) -> bool:
            return await check_proxy_health(
                proxy,
                timeout=args.health_check_timeout,
            )

        health_check_fn = _health_check

        # On startup: find the first working proxy
        log.info("🔍 Testing proxies for health (timeout: %ds)...", args.health_check_timeout)
        if pool.set_working_index(health_check_fn):
            log.info("✅ Starting with healthy proxy: %s", pool.current.display)
        else:
            log.error("✗ No working proxies found! Starting anyway...")

    log.info("Starting with proxy %s  (rotate every %ds)",
              status["current"], args.interval)
    if status["total"] > 1:
        log.info("Rotation order: %s",
                  ", ".join(p.display for p in proxies))

    # ── Start SOCKS5 server ──
    socks_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, pool, connect_timeout=args.connect_timeout),
        host=args.listen,
        port=args.port,
    )

    addr = socks_server.sockets[0].getsockname()
    log.info("🚀 SOCKS5 proxy listening on %s:%s", addr[0], addr[1])
    log.info("ℹ  Point SearXNG at socks5h://%s:%s", args.listen, args.port)

    # ── Start rotation loop ──
    health_check_interval = args.health_check_interval if args.health_check else 0
    rotation_task = asyncio.create_task(
        rotation_loop(pool, health_check_fn=health_check_fn,
                      health_check_interval=health_check_interval)
    )

    # ── Start status page if requested ──
    status_task = None
    if args.status_port:
        status_task = asyncio.create_task(
            status_server(args.status_listen, args.status_port, pool)
        )

    # ── Graceful shutdown ──
    stop_event = asyncio.Event()

    def _shutdown():
        log.info("Shutting down...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    # Also handle KeyboardInterrupt gracefully
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass

    rotation_task.cancel()
    socks_server.close()
    await socks_server.wait_closed()
    final_status = pool.status()
    log.info("Stopped after %d rotations over %d proxies. Last proxy: %s",
              final_status["rotations"], final_status["total"], final_status["current"])
    log.info("Bye!")


if __name__ == "__main__":
    asyncio.run(main())
