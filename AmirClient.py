#!/usr/bin/env python3
"""
Local SOCKS5 proxy that tunnels traffic through a Cloudflare Worker
WebSocket endpoint. The worker terminates the connection to the
requested destination; the local side just speaks SOCKS5 to clients.
"""

import asyncio
import hashlib
import hmac
import os
import socket
import struct
import sys

import websockets

# Prefer uvloop when it's available - noticeably faster on Linux.
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass


# ---- configuration -------------------------------------------------------
UUID        = "inputUUID"
WORKER_HOST = "inputWorkerUrl"
WORKER_URL  = f"wss://{WORKER_HOST}/"
CLEAN_IP    = "172.67.70.244"          # connect to the worker via this IP
LISTEN      = ("127.0.0.1", 40446)
SUBPROTO    = "chat.v2"
MAX_CHUNK   = 16384
BUFFER_MAX  = 1048576

BYTEORDER = sys.byteorder
from_bytes = int.from_bytes

# websockets renamed extra_headers -> additional_headers in v14.
_ws_ver = getattr(websockets, "__version__", "12")
_ws_major = int(_ws_ver.split(".")[0])
HEADERS_KW = "additional_headers" if _ws_major >= 14 else "extra_headers"


# ---- crypto helpers ------------------------------------------------------
def derive_key(nonce):
    """XOR the UUID bytes with a 16-byte nonce to get a per-session key."""
    u = UUID.encode()
    return bytes(u[i % len(u)] ^ nonce[i] for i in range(16))


def build_init(host, port, payload=b""):
    """
    Build the initial packet: nonce || encrypted(header) || hmac_tag.
    The header carries the target host and port in a compact form.
    """
    nonce = os.urandom(16)
    key = derive_key(nonce)

    # Encode the destination address.
    try:
        socket.inet_pton(socket.AF_INET, host)
        addr_type, addr = 1, socket.inet_aton(host)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            addr_type, addr = 3, socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            hb = host.encode()
            addr_type, addr = 2, bytes([len(hb)]) + hb

    body = bytes([1]) + struct.pack("!H", port) + bytes([addr_type]) + addr + payload

    # Expand the key to cover the whole body, then XOR.
    expanded = key * (len(body) // len(key)) + key[: len(body) % len(key)]
    enc = (from_bytes(body, BYTEORDER) ^ from_bytes(expanded, BYTEORDER)).to_bytes(
        len(body), BYTEORDER
    )
    tag = hmac.new(key, enc, hashlib.sha256).digest()[:8]
    return nonce + enc + tag, key


# ---- networking helpers --------------------------------------------------
def tune_socket(ws):
    """Disable Nagle on the underlying TCP socket for lower latency."""
    try:
        sock = ws.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


async def open_ws():
    """Connect to the worker, preferring the clean IP when one is set."""
    base_kw = {
        "max_size": None,
        "open_timeout": 15,
        "subprotocols": [SUBPROTO],
        "server_hostname": WORKER_HOST,
        "compression": None,
        "ping_interval": None,
    }

    if CLEAN_IP:
        ip = f"[{CLEAN_IP}]" if ":" in CLEAN_IP else CLEAN_IP
        url = WORKER_URL.replace(WORKER_HOST, ip)
        base_kw[HEADERS_KW] = {"Host": WORKER_HOST}
        try:
            ws = await websockets.connect(url, **base_kw)
            tune_socket(ws)
            return ws
        except Exception:
            pass  # fall back to the normal hostname

    base_kw[HEADERS_KW] = {}
    ws = await websockets.connect(WORKER_URL, **base_kw)
    tune_socket(ws)
    return ws


# ---- SOCKS5 handler ------------------------------------------------------
async def handle_client(reader, writer):
    try:
        # --- SOCKS5 greeting ---
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if hdr[0] != 5:
                return
            await asyncio.wait_for(reader.readexactly(hdr[1]), timeout=5)
        except Exception:
            return

        writer.transport.write(b"\x05\x00")  # no auth

        # --- CONNECT request ---
        try:
            req = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            if req[0] != 5 or req[1] != 1:
                return
            addr_type = req[3]
            if addr_type == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif addr_type == 3:
                n = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode()
            elif addr_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                return
            port = struct.unpack("!H", await reader.readexactly(2))[0]
        except Exception:
            return

        # Tune the client socket as well.
        client_sock = writer.get_extra_info("socket")
        if client_sock:
            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if hasattr(socket, "TCP_QUICKACK"):
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            except Exception:
                pass

        # --- connect to the worker ---
        try:
            ws = await open_ws()
        except Exception:
            return

        init, key = build_init(host, port)
        await ws.send(init)

        # Pre-build a reusable key buffer for fast XOR on fixed chunk sizes.
        raw = key * ((MAX_CHUNK // len(key)) + 1)
        mv_key = memoryview(raw)
        key_cache = {}

        # --- verify the worker's acknowledgement ---
        try:
            ack = await asyncio.wait_for(ws.recv(), timeout=10)
            if len(ack) < 16:
                return
        except Exception:
            return

        ack_len = len(ack)
        ack_xor = from_bytes(mv_key[:ack_len], BYTEORDER)
        expect = hmac.new(key, b"OK", hashlib.sha256).digest()[:16]
        if (from_bytes(ack, BYTEORDER) ^ ack_xor).to_bytes(ack_len, BYTEORDER) != expect:
            return

        # Tell the client the tunnel is up.
        writer.transport.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        # --- bidirectional pump ---
        async def pump_up():
            read = reader.read
            send = ws.send
            try:
                while True:
                    data = await read(MAX_CHUNK)
                    if not data:
                        break
                    n = len(data)
                    k = key_cache.get(n)
                    if k is None:
                        k = from_bytes(mv_key[:n], BYTEORDER)
                        key_cache[n] = k
                    await send((from_bytes(data, BYTEORDER) ^ k).to_bytes(n, BYTEORDER))
            except Exception:
                pass
            finally:
                try:
                    await ws.close()
                except Exception:
                    pass

        async def pump_down():
            transport = writer.transport
            write = transport.write
            drain = writer.drain
            buffered = transport.get_write_buffer_size
            try:
                async for msg in ws:
                    if not msg:
                        continue
                    n = len(msg)
                    k = key_cache.get(n)
                    if k is None:
                        k = from_bytes(mv_key[:n], BYTEORDER)
                        key_cache[n] = k
                    write((from_bytes(msg, BYTEORDER) ^ k).to_bytes(n, BYTEORDER))
                    if buffered() > BUFFER_MAX:
                        await drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(pump_up(), pump_down())
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    print(f"[*] SOCKS5 listening on 127.0.0.1:{LISTEN[1]} -> {WORKER_HOST}")
    server = await asyncio.start_server(handle_client, LISTEN[0], LISTEN[1], backlog=1024)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass