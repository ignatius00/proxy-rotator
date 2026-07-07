# proxy-rotator

Timer-based SOCKS5 proxy rotator. Runs a local SOCKS5 proxy that chains
through a rotating pool of upstream SOCKS5 proxies.

## How it works

```
Your app (SearXNG, curl, etc.)
    ↓ socks5h://127.0.0.1:18800
proxy-rotator (local SOCKS5 server)
    ↓ chains through current upstream proxy
pool[0..N] → rotated every 5 minutes
    ↓
internet
```

The rotation is purely timer-based — no error monitoring, no detection,
no state tracking. Every N seconds (default: 300 = 5 min) it picks the
next proxy from the list and uses it for all new connections.

## Files

| File | Purpose |
|------|---------|
| `rotator.py` | Main proxy server (zero dependencies) |
| `proxies.txt` | SOCKS5 proxy list (ip:port:user:pass per line) |
| `Dockerfile` | Docker build |
| `docker-compose.yml` | Docker Compose config |

## Quick Start

### Local (requires Python 3.10+)

```bash
python3 rotator.py
```

### Docker

```bash
docker compose up -d
```

The local SOCKS5 proxy is now available at `127.0.0.1:18800`.

## Usage

```
python3 rotator.py [options]

Options:
  --proxies FILE       Proxy list file (default: proxies.txt)
  --interval SECONDS   Rotation interval (default: 300 = 5 min)
  --port PORT          Local SOCKS5 port (default: 18800)
  --listen ADDR        Bind address (default: 127.0.0.1)
  --status-port PORT   Status HTTP page (default: 9090)
  --connect-timeout S  Upstream connection timeout (default: 15s)
  --debug              Verbose logging
  --log-file FILE      Log to file
```

### Status page

When running, visit `http://127.0.0.1:9090/` or curl it:

```bash
curl http://127.0.0.1:9090/
```

Returns JSON like:
```json
{
  "current": "198.105.121.200:6462",
  "index": 3,
  "total": 10,
  "rotations": 47,
  "uptime_sec": 180,
  "next_rotation_sec": 120
}
```

## Connecting SearXNG

In your SearXNG `settings.yml`:

```yaml
outgoing:
  proxies:
    all://:
      - socks5h://proxy-rotator:18800
```

Or if running natively:
```yaml
      - socks5h://127.0.0.1:18800
```

## Rotation Interval

**5 minutes (300s)** is recommended for search engine use:
- Frequent enough to dodge rate limits and CAPTCHAs
- Slow enough to not burn through all proxies too fast
- With 10 proxies → full cycle takes 50 min; each IP gets ~5 min of use before cooldown
