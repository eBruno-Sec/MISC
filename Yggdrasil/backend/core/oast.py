"""
Out-of-band (OAST) callback listener for blind-vulnerability detection.

A blind SSRF / OS command injection / XXE produces no visible response — the only
signal is the target reaching out to a host the tester controls. This is a small
in-process HTTP listener: inject a payload that makes the target fetch
http://<host>:<port>/<token>; a hit here confirms the blind vuln and ties it to the
exact injection point.

Reachability: the target must be able to reach <host>. Set YGGDRASIL_OAST_HOST to an
address the target can route to (a LAN IP, or a public host / tunnel for external
targets). Defaults to 127.0.0.1 (self-test / same-host targets only). When the
target cannot reach back, no interactions arrive and nothing is reported — which is
the correct, honest outcome. Authorized targets only.
"""
import asyncio
import os
import secrets
import time


class OASTListener:
    def __init__(self, host: str = None, port: int = 0):
        self.host = host or os.getenv("YGGDRASIL_OAST_HOST") or "127.0.0.1"
        self.port = port
        self.hits = {}          # token -> list of interaction records
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=3)
            first = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
            bits = first.split(" ")
            path = bits[1] if len(bits) > 1 else "/"
            token = path.strip("/").split("/")[0].split("?")[0].lower()
            if token:
                self.hits.setdefault(token, []).append({"at": time.time(), "path": path})
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def new_token(self) -> str:
        return "ygg" + secrets.token_hex(6)

    def url_for(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/{token}"

    def got(self, token: str) -> bool:
        return bool(self.hits.get(token.lower()))

    async def stop(self):
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
