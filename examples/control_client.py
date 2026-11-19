#!/usr/bin/env python3
"""Reka API v1 client for Unix sockets; uses only Python's standard library."""

import argparse
import json
import socket
import struct
import sys

MAX_FRAME = 16 << 20


class APIError(Exception):
    def __init__(self, detail):
        self.detail = detail
        super().__init__(f"{detail.get('code', 'unknown')}: {detail.get('message', '')}")


class Client:
    """Sequential client: do not call it concurrently from multiple threads."""

    def __init__(self, address, timeout=70, on_event=None):
        if address.startswith("unix://"):
            address = address[7:]
        if "://" in address:
            raise ValueError("this example supports Unix sockets only")
        self.on_event = on_event
        self.sequence = 0
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        try:
            self.socket.connect(address)
            self.hello = self.call("Hello", {"versions": [1], "client": "reka-python-example/1"})
        except Exception:
            self.close()
            raise

    def _exact(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise ConnectionError("control connection closed")
            chunks.extend(chunk)
        return bytes(chunks)

    def receive(self):
        size = struct.unpack(">I", self._exact(4))[0]
        if size > MAX_FRAME:
            raise ValueError("response exceeds 16 MiB")
        return json.loads(self._exact(size))

    def call(self, method, params=None):
        self.sequence += 1
        ident = self.sequence
        payload = json.dumps(
            {"id": ident, "method": method, "params": {} if params is None else params},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        if len(payload) > MAX_FRAME:
            raise ValueError("request exceeds 16 MiB")
        self.socket.sendall(struct.pack(">I", len(payload)) + payload)
        while True:
            message = self.receive()
            if "event" in message:
                if self.on_event is not None:
                    self.on_event(message["event"])
                continue
            if message.get("id") != ident:
                raise ValueError("response ID does not match this request")
            if "error" in message:
                raise APIError(message["error"])
            return message.get("result")

    def close(self):
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="socket path or unix:///absolute/path")
    parser.add_argument("--timeout", type=float, default=70, help="socket I/O timeout in seconds")
    parser.add_argument("--watch", action="store_true", help="keep receiving after Subscribe")
    parser.add_argument("method", nargs="?", default="GetStatus")
    parser.add_argument("params", nargs="?", default="{}", help="JSON object, @file.json, or - for stdin")
    args = parser.parse_args()
    if args.watch and args.method != "Subscribe":
        parser.error("--watch requires the Subscribe method")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.params == "-":
            params = json.load(sys.stdin)
        elif args.params.startswith("@"):
            with open(args.params[1:], encoding="utf-8") as stream:
                params = json.load(stream)
        else:
            params = json.loads(args.params)
        if not isinstance(params, dict):
            raise ValueError("params must be a JSON object")

        def show_event(event):
            print(json.dumps({"event": event}, ensure_ascii=False), flush=True)

        with Client(args.socket, args.timeout, show_event) as client:
            result = client.call(args.method, params)
            print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
            if isinstance(result, dict) and result.get("state") in ("rejected", "failed"):
                return 1
            while args.watch:
                try:
                    message = client.receive()
                except socket.timeout:
                    continue
                if "event" in message:
                    show_event(message["event"])
    except (APIError, OSError, ValueError, ConnectionError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
