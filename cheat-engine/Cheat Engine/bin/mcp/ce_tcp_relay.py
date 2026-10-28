#!/usr/bin/env python3
r"""TCP-to-named-pipe relay for the Cheat Engine MCP bridge.

Run this script on Windows while ``ce_mcp_bridge.lua`` is loaded in Cheat
Engine. It accepts the same length-prefixed JSON-RPC frames used by
``mcp_cheatengine.py`` and forwards them to ``\\.\pipe\CE_MCP_Bridge_v99``.

Use this when the MCP server cannot open the Windows named pipe directly, such
as from WSL, a container, or another host.

Bind to 127.0.0.1 unless you intentionally want to expose Cheat Engine control
to another machine.

Issue #5 — resilience additions:
  * Transparent pipe reconnection: if the CE pipe closes mid-session (CE
    restarts, user toggles the bridge, etc.) the relay re-opens it with
    exponential backoff and keeps the TCP client alive.
  * Heartbeat sender: when the TCP side is idle, the relay sends
    ``__heartbeat__`` JSON-RPC frames into the pipe every 5s to detect pipe
    death quickly and to keep the ``[MCP Engine]`` status indicator fresh.
  * Pipe access is serialized by a per-connection ``threading.Lock`` so the
    heartbeat sender and the client-forwarder cannot interleave frames.
  * Framing stays 4-byte little-endian length prefix + body — unchanged, so
    ``test_mcp.py`` and ``mcp_cheatengine.py`` keep working byte-for-byte.
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct
import sys
import threading
import time
from typing import Optional

try:
    import pywintypes
    import win32file
except ImportError as exc:  # pragma: no cover - Windows-only helper
    print("ce_tcp_relay.py must run on Windows with pywin32 installed.", file=sys.stderr)
    raise SystemExit(1) from exc


PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9876
MAX_FRAME_SIZE_BYTES = 32 * 1024 * 1024

# Issue #5: resilience tunables.
HEARTBEAT_INTERVAL_SEC = 5.0
PIPE_RECONNECT_MAX_ATTEMPTS = 10
PIPE_RECONNECT_INITIAL_DELAY_SEC = 0.25
PIPE_RECONNECT_MAX_DELAY_SEC = 2.0
HEARTBEAT_METHOD = "__heartbeat__"


def read_socket_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    """Read exactly size bytes, returning None on clean peer disconnect."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            if remaining == size:
                return None
            raise ConnectionError("TCP client disconnected mid-frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_pipe_exact(handle, size: int) -> bytes:
    """Read exactly size bytes from a Windows named pipe."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = win32file.ReadFile(handle, remaining)[1]
        if not chunk:
            raise ConnectionError("Cheat Engine pipe closed mid-frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def validate_frame_size(size: int, direction: str) -> None:
    if size > MAX_FRAME_SIZE_BYTES:
        raise ConnectionError(
            f"{direction} frame too large: {size} bytes "
            f"(max {MAX_FRAME_SIZE_BYTES} bytes)."
        )


def open_pipe():
    return win32file.CreateFile(
        PIPE_NAME,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0,
        None,
        win32file.OPEN_EXISTING,
        0,
        None,
    )


def open_pipe_with_retry(peer: str, stop_event: threading.Event):
    """Open the CE named pipe, retrying with exponential backoff.

    Returns an open pipe handle, or None if ``stop_event`` fires or all
    retries are exhausted.
    """
    delay = PIPE_RECONNECT_INITIAL_DELAY_SEC
    for attempt in range(1, PIPE_RECONNECT_MAX_ATTEMPTS + 1):
        if stop_event.is_set():
            return None
        try:
            handle = open_pipe()
            if attempt > 1:
                print(
                    f"[relay] Pipe reconnected for {peer} on attempt {attempt}.",
                    file=sys.stderr,
                    flush=True,
                )
            return handle
        except pywintypes.error as exc:
            if attempt == 1:
                print(
                    f"[relay] Pipe unavailable for {peer}: {exc}. Retrying...",
                    file=sys.stderr,
                    flush=True,
                )
            if attempt == PIPE_RECONNECT_MAX_ATTEMPTS:
                print(
                    f"[relay] Giving up pipe reconnect for {peer} after "
                    f"{attempt} attempts: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                return None
            stop_event.wait(delay)
            delay = min(delay * 2, PIPE_RECONNECT_MAX_DELAY_SEC)
    return None


class RelayHandler(socketserver.BaseRequestHandler):
    """Relay one TCP client connection to one persistent CE pipe connection.

    The handle thread owns both the TCP side and the CE pipe. A sibling
    heartbeat thread periodically injects ``__heartbeat__`` frames into the
    pipe (serialized with ``_pipe_lock``) so that:
      * CE drops are detected within ``HEARTBEAT_INTERVAL_SEC`` even when the
        TCP client is idle;
      * the Lua side updates ``last_rx`` so the ``[MCP Engine]`` menu label
        stays fresh.
    """

    pipe_handle = None

    def setup(self) -> None:
        self.pipe_handle = None
        self._pipe_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None
        self._hb_id = 0
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # ------------------------------------------------------------------ pipe

    def _reopen_pipe_locked(self, peer: str) -> bool:
        """Replace ``self.pipe_handle``. Must be called with ``_pipe_lock``."""
        self._close_pipe_locked()
        handle = open_pipe_with_retry(peer, self._stop_event)
        if handle is None:
            return False
        self.pipe_handle = handle
        return True

    def _close_pipe_locked(self) -> None:
        if self.pipe_handle is None:
            return
        try:
            win32file.CloseHandle(self.pipe_handle)
        except pywintypes.error:
            pass
        finally:
            self.pipe_handle = None

    def _close_pipe(self) -> None:
        with self._pipe_lock:
            self._close_pipe_locked()

    # -------------------------------------------------------------- heartbeat

    def _heartbeat_loop(self, peer: str) -> None:
        while not self._stop_event.wait(HEARTBEAT_INTERVAL_SEC):
            try:
                self._send_heartbeat(peer)
            except Exception as exc:  # noqa: BLE001 - defensive, logged
                print(
                    f"[relay] Heartbeat error for {peer}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )

    def _send_heartbeat(self, peer: str) -> None:
        self._hb_id += 1
        req = {
            "jsonrpc": "2.0",
            "method": HEARTBEAT_METHOD,
            "params": {},
            "id": f"relay-hb-{self._hb_id}",
        }
        body = json.dumps(req).encode("utf-8")
        header = struct.pack("<I", len(body))

        with self._pipe_lock:
            if self.pipe_handle is None:
                # No pipe yet: try to open one so the next client frame has
                # a live handle.
                if not self._reopen_pipe_locked(peer):
                    return
            try:
                win32file.WriteFile(self.pipe_handle, header)
                win32file.WriteFile(self.pipe_handle, body)
                resp_header = read_pipe_exact(self.pipe_handle, 4)
                resp_len = struct.unpack("<I", resp_header)[0]
                validate_frame_size(resp_len, "response")
                # Drain and drop the heartbeat response; the TCP client never
                # asked for it.
                read_pipe_exact(self.pipe_handle, resp_len)
            except (pywintypes.error, ConnectionError, OSError) as exc:
                print(
                    f"[relay] Heartbeat lost pipe for {peer}: {exc}. "
                    f"Marking pipe for reconnect.",
                    file=sys.stderr,
                    flush=True,
                )
                self._close_pipe_locked()

    # ------------------------------------------------------------------ main

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[relay] TCP client connected: {peer}", file=sys.stderr, flush=True)
        try:
            with self._pipe_lock:
                if not self._reopen_pipe_locked(peer):
                    raise ConnectionError("Could not open CE pipe for new client.")

            self._hb_thread = threading.Thread(
                target=self._heartbeat_loop,
                args=(peer,),
                name=f"mcp-hb-{peer}",
                daemon=True,
            )
            self._hb_thread.start()

            while True:
                req_header = read_socket_exact(self.request, 4)
                if req_header is None:
                    break
                req_len = struct.unpack("<I", req_header)[0]
                validate_frame_size(req_len, "request")
                req_body = read_socket_exact(self.request, req_len)
                if req_body is None:
                    raise ConnectionError("TCP client disconnected before request body.")

                resp_header, resp_body = self._forward_with_reconnect(
                    peer, req_header, req_body
                )
                self.request.sendall(resp_header + resp_body)
        except pywintypes.error as exc:
            print(f"[relay] Windows pipe error for {peer}: {exc}", file=sys.stderr, flush=True)
        except (ConnectionError, OSError) as exc:
            print(f"[relay] Connection ended for {peer}: {exc}", file=sys.stderr, flush=True)
        finally:
            self._stop_event.set()
            if self._hb_thread is not None:
                # Join must outlast one full wait interval so the heartbeat
                # thread has a real chance to wake from stop_event.wait()
                # and exit cleanly instead of being leaked as a daemon.
                self._hb_thread.join(timeout=HEARTBEAT_INTERVAL_SEC + 1.0)
            self._close_pipe()
            print(f"[relay] TCP client disconnected: {peer}", file=sys.stderr, flush=True)

    def _forward_with_reconnect(self, peer: str, req_header: bytes, req_body: bytes):
        """Forward one framed request/response pair.

        Retries once across a pipe reopen so that a CE restart does not drop
        the client connection — the TCP side only sees an error if the pipe
        cannot be reopened at all.
        """
        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            with self._pipe_lock:
                if self.pipe_handle is None:
                    if not self._reopen_pipe_locked(peer):
                        raise ConnectionError(
                            "CE pipe unavailable after reconnect attempts."
                        )
                try:
                    win32file.WriteFile(self.pipe_handle, req_header)
                    win32file.WriteFile(self.pipe_handle, req_body)

                    resp_header = read_pipe_exact(self.pipe_handle, 4)
                    resp_len = struct.unpack("<I", resp_header)[0]
                    validate_frame_size(resp_len, "response")
                    resp_body = read_pipe_exact(self.pipe_handle, resp_len)
                    return resp_header, resp_body
                except (pywintypes.error, ConnectionError, OSError) as exc:
                    last_exc = exc
                    print(
                        f"[relay] Pipe I/O failed for {peer} (attempt {attempt + 1}): "
                        f"{exc}. Reconnecting pipe...",
                        file=sys.stderr,
                        flush=True,
                    )
                    self._close_pipe_locked()
            # fall through: next attempt will reopen the pipe
            time.sleep(PIPE_RECONNECT_INITIAL_DELAY_SEC)
        raise ConnectionError(
            f"CE pipe forward failed after retry: {last_exc!r}"
        )


class RelayServer(socketserver.ThreadingTCPServer):
    """Threaded TCP server so multiple clients each get their own pipe."""

    allow_reuse_address = True
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Relay TCP frames to the Cheat Engine MCP Windows named pipe."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"TCP bind host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP bind port (default: {DEFAULT_PORT})")
    parser.add_argument("--pipe", default=PIPE_NAME, help=f"Named pipe path (default: {PIPE_NAME})")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        print("--port must be between 1 and 65535.", file=sys.stderr)
        return 2

    global PIPE_NAME
    PIPE_NAME = args.pipe

    print(
        f"[relay] Listening on {args.host}:{args.port}; forwarding to {PIPE_NAME}",
        file=sys.stderr,
        flush=True,
    )
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "[relay] WARNING: non-loopback bind exposes Cheat Engine control to the network.",
            file=sys.stderr,
            flush=True,
        )

    with RelayServer((args.host, args.port), RelayHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[relay] Stopping.", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
