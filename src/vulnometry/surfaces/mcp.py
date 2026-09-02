"""MCP server over stdio, implemented directly on JSON-RPC 2.0."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from .. import __version__
from ..registry import action_specs, invoke

PROTOCOL_VERSION = "2024-11-05"


def _log(message: str) -> None:
    print(f"[vulnometry-mcp] {message}", file=sys.stderr, flush=True)


def _response(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


async def handle(request: dict) -> dict | None:
    method = request.get("method", "")
    request_id = request.get("id")
    params = request.get("params", {}) or {}

    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "vulnometry", "version": __version__},
                "instructions": (
                    "Exposure measurement for vulnerabilities. Use measure_exposure for one "
                    "CVE and measure_portfolio for many. Both return a Business Exposure "
                    "Index (Threat x Reachability x Consequence, 0-1000) and a verdict of "
                    "Contain, Remediate, Schedule or Accept. Call read_inventory first to "
                    "learn what the organisation runs, and always pass the `asset` argument "
                    "when the user describes their environment: it changes the measurement."
                ),
            },
        )

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return _response(request_id, {})

    if method == "tools/list":
        return _response(
            request_id,
            {
                "tools": [
                    {
                        "name": spec["name"],
                        "description": spec["description"],
                        "inputSchema": spec["input_schema"],
                    }
                    for spec in action_specs()
                ]
            },
        )

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments", {}) or {}
        result = await invoke(name, arguments)
        is_error = isinstance(result, dict) and "error" in result and len(result) <= 2
        return _response(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}],
                "isError": bool(is_error),
            },
        )

    if request_id is None:
        return None
    return _error(request_id, -32601, f"method not found: {method}")


async def serve() -> None:
    _log(f"v{__version__} ready with {len(action_specs())} actions on stdio")

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            continue
        try:
            request = json.loads(text)
        except json.JSONDecodeError:
            _log(f"skipping non-JSON line: {text[:120]}")
            continue

        try:
            reply = await handle(request)
        except Exception as exc:  # noqa: BLE001
            _log(f"handler error: {exc}")
            reply = _error(request.get("id"), -32603, f"internal error: {exc}")

        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()

    _log("stdin closed, exiting")


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
