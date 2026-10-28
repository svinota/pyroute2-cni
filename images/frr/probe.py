#!/usr/bin/env python3
"""Minimal HTTP probe server for Kubernetes liveness/readiness checks."""

import argparse
import asyncio
import json
import re
import subprocess
from typing import Any, Iterable, List, Optional, Tuple

DAEMONS = ("watchfrr", "zebra", "bgpd", "staticd")
READINESS_HOST = '0.0.0.0'
READINESS_PORT = '24801'
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RMAC_RE = re.compile(r"(?:^|[ ,])Rmac:([0-9a-fA-F:]{17})(?:$|[ ,])")


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


def _run_json_cmd(cmd: list[str]) -> Any:
    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed rc={proc.returncode}: {' '.join(cmd)}: "
            f"{proc.stderr.strip()}"
        )
    raw = ANSI_RE.sub("", proc.stdout).strip()
    if not raw:
        raise RuntimeError(f"empty output from {' '.join(cmd)}")
    return json.loads(raw)


def _iter_path_objs(paths: Any) -> Iterable[dict[str, Any]]:
    if isinstance(paths, dict):
        yield paths
        return
    if isinstance(paths, list):
        for item in paths:
            yield from _iter_path_objs(item)


def _extract_rmac(ext_community: str) -> Optional[str]:
    match = RMAC_RE.search(ext_community)
    if match is None:
        return None
    return match.group(1).lower()


def _mac_ip_from_type5(vtysh_json: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for _, rd_block in vtysh_json.items():
        if not isinstance(rd_block, dict):
            continue
        for _, route_block in rd_block.items():
            if not isinstance(route_block, dict):
                continue
            paths = route_block.get("paths")
            if paths is None:
                continue
            for path in _iter_path_objs(paths):
                if not isinstance(path, dict):
                    continue
                if int(path.get("routeType", 0)) != 5:
                    continue
                if not path.get("valid", True):
                    continue
                if path.get("peerId") == "(unspec)":
                    continue
                ext = path.get("extendedCommunity", {})
                ext_string = (
                    ext.get("string", "") if isinstance(ext, dict) else ""
                )
                mac = _extract_rmac(ext_string)
                if mac is None:
                    continue
                for nexthop in path.get("nexthops", []):
                    if not isinstance(nexthop, dict):
                        continue
                    ip = nexthop.get("ip")
                    if isinstance(ip, str) and ip:
                        result.setdefault(mac, set()).add(ip)
    return result


def _mac_ip_from_fdb(fdb_json: list[dict[str, Any]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for entry in fdb_json:
        if not isinstance(entry, dict):
            continue
        mac = entry.get("mac")
        dst = entry.get("dst")
        if not isinstance(mac, str) or not isinstance(dst, str):
            continue
        if not mac or not dst:
            continue
        result.setdefault(mac.lower(), set()).add(dst)
    return result


def _vxlan_interfaces() -> list[str]:
    links = _run_json_cmd(["ip", "-j", "link", "show", "type", "vxlan"])
    if not isinstance(links, list):
        raise RuntimeError(
            "unexpected output from: ip -j link show type vxlan"
        )
    result: list[str] = []
    for link in links:
        if not isinstance(link, dict):
            continue
        ifname = link.get("ifname")
        if isinstance(ifname, str) and ifname:
            result.append(ifname)
    return result


def _check_type5_fdb() -> Tuple[int, bytes]:
    try:
        vtysh_json = _run_json_cmd(
            ["vtysh", "-c", "show bgp l2vpn evpn route type 5 json"]
        )
        cp_map = _mac_ip_from_type5(vtysh_json)
        if not cp_map:
            return 200, b"ok\n"

        vxlan_devs = _vxlan_interfaces()
        if not vxlan_devs:
            return 503, b"type5/fdb mismatch: no vxlan interfaces found\n"

        dp_map: dict[str, set[str]] = {}
        for dev in vxlan_devs:
            fdb_json = _run_json_cmd(
                ["bridge", "-j", "fdb", "show", "dev", dev]
            )
            part = _mac_ip_from_fdb(fdb_json)
            for mac, dst_ips in part.items():
                dp_map.setdefault(mac, set()).update(dst_ips)

        missing: list[str] = []
        for mac, next_hops in cp_map.items():
            present = dp_map.get(mac, set())
            for ip in next_hops:
                if ip not in present:
                    missing.append(f"{mac}->{ip}")

        if missing:
            return 503, (
                "type5/fdb mismatch: missing " + ", ".join(missing[:20]) + "\n"
            ).encode("ascii", "ignore")
        return 200, b"ok\n"
    except Exception as exc:
        return 503, (f"type5/fdb check failed: {exc}\n").encode(
            "ascii", "ignore"
        )


async def liveness() -> Tuple[int, bytes]:

    # Check that all FRR daemons are running.
    missing_processes = [name for name in DAEMONS if not _pidof(name)]
    if missing_processes:
        return 503, (
            "missing daemons: " + ", ".join(missing_processes) + "\n"
        ).encode("ascii")

    # Check FDB mac:ip pairs
    status, body = _check_type5_fdb()
    if status != 200:
        return status, body
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

        reason = {200: "OK", 404: "Not Found", 503: "Service Unavailable"}.get(
            status, "OK"
        )
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
