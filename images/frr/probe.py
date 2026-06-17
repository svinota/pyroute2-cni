#!/usr/bin/env python3
"""Minimal HTTP probe server for Kubernetes liveness/readiness checks."""

import argparse
import asyncio
import subprocess
from typing import List, Tuple

DAEMONS = ("watchfrr", "zebra", "bgpd", "staticd")
READINESS_HOST = '0.0.0.0'
READINESS_PORT = '24801'


def _pidof(name: str) -> bool:
    return (
        subprocess.run(
            ["pidof", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _readiness_output() -> str:
    proc = subprocess.run(
        ["vtysh", "-c", "show watchfrr"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return proc.stdout


def _parse_status(output: str, count: int = 3) -> List[Tuple[str, str]]:
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    if len(lines) < count:
        raise ValueError("show watchfrr output too short")

    result = []
    for line in lines[-count:]:
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"cannot parse line: {line!r}")
        result.append((parts[0], parts[-1]))
    return result


async def liveness() -> Tuple[int, bytes]:
    """Check that all FRR daemons are running."""
    missing = [name for name in DAEMONS if not _pidof(name)]
    if missing:
        return 503, ("missing daemons: " + ", ".join(missing) + "\n").encode(
            "ascii"
        )
    return 200, b"ok\n"


async def readiness() -> Tuple[int, bytes]:
    """Check watchfrr state via vtysh output."""
    try:
        parsed = _parse_status(_readiness_output())
    except Exception as exc:
        return 503, (f"unhealthy: {exc}\n").encode("ascii", "ignore")

    expected = [("zebra", "Up"), ("staticd", "Up"), ("bgpd", "Up")]
    if parsed != expected:
        return 503, (f"unexpected watchfrr state: {parsed!r}\n").encode(
            "ascii", "ignore"
        )

    return 200, b"ok\n"


async def handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        request_line = await reader.readline()
        if not request_line:
            return

        parts = request_line.decode("ascii", "ignore").strip().split()
        path = parts[1] if len(parts) >= 2 else ""

        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        if path == "/livez":
            status, body = await liveness()
        elif path == "/readyz":
            status, body = await readiness()
        else:
            status, body = 404, b"not found\n"

        reason = {200: "OK", 404: "Not Found"}.get(status, "OK")
        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + body
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes probe server")
    parser.add_argument("--host", default=READINESS_HOST)
    parser.add_argument("--port", type=int, default=READINESS_PORT)
    args = parser.parse_args()

    server = await asyncio.start_server(handle_client, args.host, args.port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
