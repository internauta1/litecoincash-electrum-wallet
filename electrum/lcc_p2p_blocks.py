"""Litecoin Cash mainnet P2P block retrieval.

Uses Bitcoin-compatible P2P messages.
Downloaded data is untrusted until verified locally.

No Litecoin Cash Core RPC dependency.
"""

import asyncio
import hashlib
import secrets
import struct
import time

from .blockchain import hash_header
from .lcc_hive_block import verify_hive_full_block_structure


MAGIC = bytes.fromhex("c7e4baf8")
DEFAULT_PORT = 62458
PROTOCOL_VERSION = 70015

MAX_MESSAGE_SIZE = 8_000_000
NODE_WITNESS = 1 << 3
MSG_WITNESS_BLOCK = 0x40000002


class LCCP2PError(Exception):
    pass


def sha256d(data):
    return hashlib.sha256(
        hashlib.sha256(data).digest()
    ).digest()


def pack_message(command, payload=b""):
    if not command.isascii() or len(command) > 12:
        raise LCCP2PError("Invalid P2P command")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise LCCP2PError("P2P payload too large")

    return (
        MAGIC
        + command.encode("ascii").ljust(12, b"\x00")
        + struct.pack("<I", len(payload))
        + sha256d(payload)[:4]
        + payload
    )


def make_version():
    """Construct protocol 70015 version handshake."""
    addr = (
        struct.pack("<Q", 0)
        + bytes(16)
        + struct.pack(">H", DEFAULT_PORT)
    )

    agent = b"/Electrum-LCC:0.9.0/"

    return (
        struct.pack(
            "<iQq",
            PROTOCOL_VERSION,
            NODE_WITNESS,
            int(time.time()),
        )
        + addr
        + addr
        + secrets.token_bytes(8)
        + bytes([len(agent)])
        + agent
        + struct.pack("<i", 0)
        + b"\x00"
    )


async def read_message(reader, timeout):
    header = await asyncio.wait_for(
        reader.readexactly(24),
        timeout=timeout,
    )

    if header[:4] != MAGIC:
        raise LCCP2PError("Incorrect network magic")

    raw_command = header[4:16]
    command = raw_command.split(b"\x00", 1)[0]

    if not command or any(
        c < 32 or c > 126 for c in command
    ):
        raise LCCP2PError("Invalid message command")

    length = struct.unpack("<I", header[16:20])[0]

    if length > MAX_MESSAGE_SIZE:
        raise LCCP2PError("Oversized P2P message")

    payload = await asyncio.wait_for(
        reader.readexactly(length),
        timeout=timeout,
    )

    if sha256d(payload)[:4] != header[20:24]:
        raise LCCP2PError("Incorrect P2P checksum")

    return command.decode("ascii"), payload


async def request_block_from_peer(
    *,
    host,
    block_hash,
    port=DEFAULT_PORT,
    timeout=20,
):
    """Request a complete witness block from an independent peer."""
    if (
        not isinstance(block_hash, str)
        or len(block_hash) != 64
    ):
        raise LCCP2PError("Invalid block hash")

    try:
        requested_hash = bytes.fromhex(block_hash)[::-1]
    except ValueError as exc:
        raise LCCP2PError("Invalid block hash") from exc

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )

    try:
        writer.write(
            pack_message("version", make_version())
        )
        await asyncio.wait_for(
            writer.drain(), timeout=timeout
        )

        received_version = False
        received_verack = False
        peer_services = 0

        deadline = asyncio.get_running_loop().time() + timeout

        while not (received_version and received_verack):
            remaining = deadline - asyncio.get_running_loop().time()

            if remaining <= 0:
                raise LCCP2PError("Handshake timeout")

            command, payload = await read_message(
                reader, remaining
            )

            if command == "version":
                if received_version or len(payload) < 20:
                    raise LCCP2PError("Invalid version handshake")

                peer_version = struct.unpack_from(
                    "<i", payload, 0
                )[0]
                peer_services = struct.unpack_from(
                    "<Q", payload, 4
                )[0]

                if peer_version < 70002:
                    raise LCCP2PError("Peer protocol too old")

                received_version = True

                writer.write(
                    pack_message("verack")
                )
                await writer.drain()

            elif command == "verack":
                if not received_version:
                    raise LCCP2PError("Unexpected verack")
                received_verack = True

            elif command == "ping":
                writer.write(
                    pack_message("pong", payload)
                )
                await writer.drain()

        if not (peer_services & NODE_WITNESS):
            raise LCCP2PError(
                "Peer does not advertise witness support"
            )

        # Request the full block including witness information.
        inventory = (
            b"\x01"
            + struct.pack("<I", MSG_WITNESS_BLOCK)
            + requested_hash
        )

        writer.write(
            pack_message("getdata", inventory)
        )
        await asyncio.wait_for(
            writer.drain(), timeout=timeout
        )

        deadline = asyncio.get_running_loop().time() + timeout

        while True:
            remaining = deadline - asyncio.get_running_loop().time()

            if remaining <= 0:
                raise LCCP2PError("Block download timeout")

            command, payload = await read_message(
                reader, remaining
            )

            if command == "block":
                if len(payload) < 81:
                    raise LCCP2PError("Incomplete block")

                actual_hash = sha256d(
                    payload[:80]
                )[::-1].hex()

                if actual_hash != block_hash.lower():
                    raise LCCP2PError(
                        "Peer returned an unexpected block"
                    )

                return payload

            if command == "notfound":
                raise LCCP2PError(
                    "Historical block not available from peer"
                )

            if command == "ping":
                writer.write(
                    pack_message("pong", payload)
                )
                await writer.drain()

    finally:
        writer.close()
        try:
            await asyncio.wait_for(
                writer.wait_closed(), timeout=5
            )
        except (OSError, asyncio.TimeoutError):
            pass


async def fetch_verified_hive_block(
    *,
    candidate_header,
    peers=None,
    timeout=20,
):
    """Download Hive block and verify structural commitments.

    A successful result is NOT full consensus validation.
    """
    if not isinstance(candidate_header, dict):
        raise LCCP2PError("Invalid candidate header")

    height = candidate_header.get("block_height")

    if type(height) is not int or height <= 0:
        raise LCCP2PError("Invalid candidate height")

    expected_hash = hash_header(candidate_header)
    if peers is None:
        from .lcc_p2p_discovery import discover_mainnet_peers
        peers = await discover_mainnet_peers()
        timeout = min(timeout, 10)

    errors = []

    for peer in peers:
        if isinstance(peer, str):
            host, port = peer, DEFAULT_PORT
        else:
            host, port = peer

        try:
            raw = await request_block_from_peer(
                host=host,
                port=port,
                block_hash=expected_hash,
                timeout=timeout,
            )

            structure = verify_hive_full_block_structure(
                raw_block=raw,
                candidate_header=candidate_header,
            )

            if structure["candidate_header_hash"] != expected_hash:
                raise LCCP2PError("Block identity mismatch")

            return {
                "raw_block": raw,
                "peer": host,
                "structure": structure,
                "block_hash": expected_hash,
                "consensus_validated": False,
            }

        except (OSError, asyncio.TimeoutError, LCCP2PError,
                ValueError, EOFError) as exc:
            errors.append(f"{host}: {exc}")

    raise LCCP2PError(
        "No peer supplied a valid requested block: "
        + "; ".join(errors)
    )
