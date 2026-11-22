
"""Independent Litecoin Cash P2P peer discovery."""

import asyncio
import ipaddress
import os
import time
import struct

from .lcc_p2p_blocks import (
    pack_message,
    make_version,
    read_message,
    DEFAULT_PORT,
)

NODE_NETWORK = 1
NODE_WITNESS = 8


def _compact(data):
    if not data:
        raise ValueError("Empty CompactSize")

    prefix = data[0]

    if prefix < 253:
        return prefix, 1

    size = {253: 2, 254: 4, 255: 8}[prefix]

    if len(data) < size + 1:
        raise ValueError("Truncated CompactSize")

    value = int.from_bytes(data[1:1 + size], "little")

    if (
        prefix == 253 and value < 253
        or prefix == 254 and value <= 65535
        or prefix == 255 and value <= 4294967295
    ):
        raise ValueError("Noncanonical CompactSize")

    return value, size + 1


def parse_addr(payload):
    """Parse Bitcoin-compatible legacy P2P addr messages."""
    count, offset = _compact(payload)

    if count > 1000 or len(payload) != offset + count * 30:
        raise ValueError("Invalid P2P address payload")

    found = []

    for i in range(count):
        item = payload[offset + i * 30:offset + (i + 1) * 30]

        services = int.from_bytes(item[4:12], "little")
        address = ipaddress.IPv6Address(item[12:28])
        port = int.from_bytes(item[28:30], "big")

        if address.ipv4_mapped:
            address = address.ipv4_mapped

        if (
            address.is_global
            and port > 0
            and services & NODE_NETWORK
            and services & NODE_WITNESS
        ):
            found.append((str(address), port))

    return found


async def request_peer_addresses(host, port=DEFAULT_PORT, timeout=7):
    """Discover public peers through a normal P2P getaddr exchange."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )

    async def receive(deadline):
        remaining = deadline - asyncio.get_running_loop().time()

        if remaining <= 0:
            raise asyncio.TimeoutError()

        return await read_message(reader, remaining)

    try:
        writer.write(pack_message("version", make_version()))
        await writer.drain()

        deadline = asyncio.get_running_loop().time() + timeout
        version_seen = False
        verack_seen = False

        while not (version_seen and verack_seen):
            command, payload = await receive(deadline)

            if command == "version":
                if version_seen or len(payload) < 20:
                    raise ValueError("Invalid peer version")

                protocol = struct.unpack_from("<i", payload)[0]

                if protocol < 70002:
                    raise ValueError("Unsupported peer protocol")

                version_seen = True
                writer.write(pack_message("verack"))
                await writer.drain()

            elif command == "verack":
                if not version_seen:
                    raise ValueError("Unexpected verack")
                verack_seen = True

            elif command == "ping":
                writer.write(pack_message("pong", payload))
                await writer.drain()

        writer.write(pack_message("getaddr"))
        await writer.drain()

        deadline = asyncio.get_running_loop().time() + timeout

        while True:
            command, payload = await receive(deadline)

            if command == "addr":
                return parse_addr(payload)

            if command == "ping":
                writer.write(pack_message("pong", payload))
                await writer.drain()

    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, asyncio.TimeoutError):
            pass


# LCC_P2P_DISCOVERY_CACHE_V1
_LCC_DISCOVERY_CACHE = {}
_LCC_DISCOVERY_TTL = 300

async def discover_mainnet_peers(limit=20, timeout=7):
    """Discover peers without Core RPC.

    LCC_P2P_BOOTSTRAP optionally selects an initial P2P
    address. This is not a trusted consensus authority.
    """
    configured = os.environ.get(
        "LCC_P2P_BOOTSTRAP",
        "seeds.litecoinca.sh:62458",
    )

    host, separator, port_text = configured.rpartition(":")

    if not separator or not host:
        raise ValueError("Invalid P2P bootstrap address")

    port = int(port_text)

    if not 1 <= port <= 65535:
        raise ValueError("Invalid P2P bootstrap port")

    bootstrap = (host, port)
    now = time.monotonic()
    cached = _LCC_DISCOVERY_CACHE.get(bootstrap)

    if cached is not None:
        timestamp, addresses = cached
        if now - timestamp < _LCC_DISCOVERY_TTL:
            return addresses[:limit]

    peers = [bootstrap]

    try:
        discovered = await request_peer_addresses(
            host, port, timeout=timeout
        )
        peers.extend(discovered)
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        print(
            "DESCOBERTA GETADDR:",
            type(exc).__name__,
            str(exc),
            flush=True,
        )

    unique_peers = list(dict.fromkeys(peers))
    _LCC_DISCOVERY_CACHE[bootstrap] = (
        time.monotonic(), unique_peers
    )
    return unique_peers[:limit]
