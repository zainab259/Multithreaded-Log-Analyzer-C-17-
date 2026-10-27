#!/usr/bin/env python3
"""Generate deterministic-ish synthetic combined access logs using reserved IP ranges."""
import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

IPS = [f"192.0.2.{i}" for i in range(1, 20)] + [f"198.51.100.{i}" for i in range(1, 10)]
URLS = ["/", "/index.html", "/api/users", "/login", "/admin", "/missing", "/health"]
STATUSES = [200, 200, 200, 301, 302, 401, 403, 404, 404, 500, 503]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, choices=(10_000, 100_000, 1_000_000), default=10_000)
    parser.add_argument("--output", type=Path, default=Path("logs/generated.log"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    random.seed(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with args.output.open("w", encoding="utf-8") as out:
        for i in range(args.count):
            # Make a small pattern of repeated auth failures and server errors.
            ip = "203.0.113.7" if i % 37 < 7 else random.choice(IPS)
            status = 401 if i % 37 < 7 else (500 if i % 211 == 0 else random.choice(STATUSES))
            stamp = start + timedelta(seconds=i * 2)
            url = "/login" if status == 401 else ("/missing" if status == 404 else random.choice(URLS))
            out.write(f'{ip} - - [{stamp.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {url} HTTP/1.1" {status} {random.randint(128, 4096)}\n')
            if i and i % 100_000 == 0:
                out.write("malformed synthetic entry\n")
    print(f"Wrote {args.count} log entries to {args.output}")

if __name__ == "__main__":
    main()
