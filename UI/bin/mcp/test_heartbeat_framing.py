#!/usr/bin/env python3
"""Standalone smoke test for the MCP heartbeat framing primitives.

Does NOT require Cheat Engine, a named pipe or network access. Validates
the pure helpers exported by ``ce_tcp_relay`` so CI and devs can prove
the protocol pieces still line up before deploying.

Run:
    python test_heartbeat_framing.py
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Importing ce_tcp_relay pulls in pywin32 at module import. On non-Windows
# or minimal CI boxes we stub it with a tiny shim so the pure helpers
# remain testable. The shim is only installed when the real module is
# missing so Windows CI still exercises the real code path.
try:
    import pywintypes  # noqa: F401
    import win32file  # noqa: F401
except ImportError:
    import types

    pywintypes_stub = types.ModuleType("pywintypes")

    class _StubError(Exception):
        pass

    pywintypes_stub.error = _StubError
    sys.modules["pywintypes"] = pywintypes_stub

    win32file_stub = types.ModuleType("win32file")
    win32file_stub.GENERIC_READ = 0
    win32file_stub.GENERIC_WRITE = 0
    win32file_stub.OPEN_EXISTING = 0

    def _stub_create_file(*_a, **_kw):
        raise _StubError("pywin32 unavailable in this environment")

    def _stub_read_file(*_a, **_kw):
        raise _StubError("pywin32 unavailable in this environment")

    def _stub_write_file(*_a, **_kw):
        raise _StubError("pywin32 unavailable in this environment")

    def _stub_close_handle(*_a, **_kw):
        return None

    win32file_stub.CreateFile = _stub_create_file
    win32file_stub.ReadFile = _stub_read_file
    win32file_stub.WriteFile = _stub_write_file
    win32file_stub.CloseHandle = _stub_close_handle
    sys.modules["win32file"] = win32file_stub

import ce_tcp_relay as relay  # noqa: E402


HEARTBEAT_METHOD = relay.HEARTBEAT_METHOD


def build_heartbeat_frame(request_id: str) -> bytes:
    """Build a framed heartbeat request the way the relay does."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": HEARTBEAT_METHOD,
            "params": {},
            "id": request_id,
        }
    ).encode("utf-8")
    header = struct.pack("<I", len(body))
    return header + body


class HeartbeatFrameTests(unittest.TestCase):
    def test_method_name_is_namespaced(self):
        self.assertEqual(HEARTBEAT_METHOD, "__heartbeat__")

    def test_frame_header_is_little_endian_length(self):
        frame = build_heartbeat_frame("hb-1")
        header, body = frame[:4], frame[4:]
        (declared_len,) = struct.unpack("<I", header)
        self.assertEqual(declared_len, len(body))
        self.assertGreater(declared_len, 0)

    def test_frame_body_roundtrips_as_jsonrpc(self):
        frame = build_heartbeat_frame("hb-42")
        body = frame[4:]
        decoded = json.loads(body.decode("utf-8"))
        self.assertEqual(decoded["jsonrpc"], "2.0")
        self.assertEqual(decoded["method"], HEARTBEAT_METHOD)
        self.assertEqual(decoded["id"], "hb-42")
        self.assertIn("params", decoded)

    def test_heartbeat_interval_is_five_seconds(self):
        # Contract with the Lua side's menu refresh thresholds.
        self.assertEqual(relay.HEARTBEAT_INTERVAL_SEC, 5.0)


class ValidateFrameSizeTests(unittest.TestCase):
    def test_zero_is_accepted(self):
        # validate_frame_size only rejects oversize frames; 0 is the
        # relay's "clean disconnect" sentinel and must not raise.
        self.assertIsNone(relay.validate_frame_size(0, "request"))

    def test_max_is_accepted(self):
        self.assertIsNone(
            relay.validate_frame_size(relay.MAX_FRAME_SIZE_BYTES, "request")
        )

    def test_above_max_is_rejected(self):
        with self.assertRaises(ConnectionError) as ctx:
            relay.validate_frame_size(
                relay.MAX_FRAME_SIZE_BYTES + 1, "response"
            )
        self.assertIn("too large", str(ctx.exception))
        self.assertIn("response", str(ctx.exception))


class OpenPipeWithRetryTests(unittest.TestCase):
    def test_stop_event_short_circuits(self):
        """A pre-set stop_event must make the helper return None fast."""
        stop = threading.Event()
        stop.set()
        start_delay = relay.PIPE_RECONNECT_INITIAL_DELAY_SEC
        # Sanity check so the test fails loudly if the module tunables drift.
        self.assertLessEqual(start_delay, 1.0)

        import time

        t0 = time.monotonic()
        result = relay.open_pipe_with_retry("test-peer", stop)
        elapsed = time.monotonic() - t0

        self.assertIsNone(result)
        # Must not sit through a full backoff cycle: ten attempts at the
        # capped delay would take tens of seconds; a healthy early exit
        # is well under one second.
        self.assertLess(elapsed, 1.0, f"open_pipe_with_retry blocked {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
