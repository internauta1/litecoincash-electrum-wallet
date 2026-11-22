
"""Experimental LCC shallow reorganization recovery.

Only for isolated Beta 2 laboratories. Not full consensus verification.
"""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


MAX_REORG_DEPTH = 48
HEADER_SIZE = 80


def _hash(raw):
    return hashlib.sha256(
        hashlib.sha256(raw).digest()
    ).digest()[::-1].hex()


def _sha256_file(path):
    result = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


async def reconcile_reorg_v9(interface, server_tip):
    """Check the local tip against ElectrumX, recover shallow forks."""

    if type(server_tip) is not int or server_tip < 0:
        raise RuntimeError("V9 invalid remote height")

    chain = interface.blockchain
    network = interface.network

    if chain is None or chain is not network.blockchain():
        raise RuntimeError("V9 selected blockchain changed")

    if chain.parent is not None:
        raise RuntimeError("V9 only supports the main laboratory chain")

    path = Path(chain.path()).resolve(strict=True)
    root = (
        Path.home() / "electrum-lcc-development"
    ).resolve()

    if (
        path.name != "blockchain_headers"
        or path.parent.parent != root
        or not path.parent.name.startswith(
            "beta2-hive-experimental-"
        )
        or path.is_symlink()
    ):
        raise RuntimeError("V9 outside isolated laboratory")

    checkpoint_path = path.parent / "checkpoint-core.json"

    if not checkpoint_path.is_file():
        raise RuntimeError("V9 checkpoint missing")

    checkpoint = json.loads(
        checkpoint_path.read_text(encoding="utf-8")
    )

    anchor = checkpoint["height"]
    anchor_hash = checkpoint["hash"].lower()

    if type(anchor) is not int or anchor < 0:
        raise RuntimeError("V9 invalid checkpoint")

    if len(anchor_hash) != 64:
        raise RuntimeError("V9 invalid checkpoint hash")

    local_tip = chain.height()

    if local_tip < anchor:
        raise RuntimeError("V9 local chain below checkpoint")

    if chain.get_hash(anchor) != anchor_hash:
        raise RuntimeError("V9 checkpoint mismatch")

    # A server behind our local tip must not cause a rollback.
    if server_tip < local_tip:
        return False

    async def remote_header(height):
        reply = await interface.session.send_request(
            "blockchain.block.header",
            [height],
            timeout=20,
        )

        if isinstance(reply, dict):
            reply = reply.get("hex")

        if not isinstance(reply, str) or len(reply) != 160:
            raise RuntimeError(
                f"V9 invalid ElectrumX header at {height}"
            )

        raw = bytes.fromhex(reply)

        if len(raw) != HEADER_SIZE:
            raise RuntimeError("V9 invalid header length")

        return raw

    # Check whether the local tip is still on the server's chain.
    first_remote = await remote_header(local_tip)
    first_hash = _hash(first_remote)
    local_hash = chain.get_hash(local_tip)

    if first_hash == local_hash:
        return False

    interface.logger.warning(
        "LCC V9: divergent tip at height %d: local=%s remote=%s",
        local_tip,
        local_hash,
        first_hash,
    )

    # Find a common ancestor, never crossing the trusted checkpoint.
    minimum = max(anchor, local_tip - MAX_REORG_DEPTH)
    ancestor = None

    for height in range(local_tip - 1, minimum - 1, -1):
        raw = await remote_header(height)

        if _hash(raw) == chain.get_hash(height):
            ancestor = height
            break

    if ancestor is None:
        raise RuntimeError(
            "V9 common ancestor not found within permitted depth"
        )

    # Confirm that the server's next header connects to the ancestor.
    next_header = await remote_header(ancestor + 1)
    next_parent = next_header[4:36][::-1].hex()

    if next_parent != chain.get_hash(ancestor):
        raise RuntimeError("V9 remote branch ancestry changed")

    # Check the original divergent tip again to detect an unstable server.
    confirmation = await remote_header(local_tip)

    if _hash(confirmation) != first_hash:
        raise RuntimeError("V9 remote chain changed during analysis")

    interface.logger.warning(
        "LCC V9: common ancestor=%d rollback=%d blocks",
        ancestor,
        local_tip - ancestor,
    )

    # No network request is made while holding bhi_lock.
    async with network.bhi_lock:
        if (
            chain is not interface.blockchain
            or chain is not network.blockchain()
        ):
            raise RuntimeError("V9 chain changed before recovery")

        if (
            chain.height() != local_tip
            or chain.get_hash(local_tip) != local_hash
            or chain.get_hash(anchor) != anchor_hash
        ):
            raise RuntimeError("V9 local chain changed before recovery")

        if path.is_symlink() or not path.is_file():
            raise RuntimeError("V9 invalid headers file")

        size = path.stat().st_size

        if size != (local_tip + 1) * HEADER_SIZE:
            raise RuntimeError("V9 headers size mismatch")

        if shutil.disk_usage(path.parent).free < (
            size + 32 * 1024 * 1024
        ):
            raise RuntimeError("V9 insufficient backup space")

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        backup = path.parent / (
            f"blockchain_headers.before-reorg-v9-{timestamp}.bak"
        )

        # Independent copy, not a hard link.
        with path.open("rb") as src, backup.open("xb") as dst:
            shutil.copyfileobj(src, dst, 4 * 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())

        if (
            backup.stat().st_size != size
            or _sha256_file(path) != _sha256_file(backup)
        ):
            raise RuntimeError("V9 backup verification failed")

        interface.logger.warning(
            "LCC V9: verified backup=%s",
            backup,
        )

        # Blockchain.write updates its internal _size.
        # Never truncate the file directly while Electrum is running.
        chain.write(
            b"",
            (ancestor + 1) * HEADER_SIZE,
            truncate=True,
        )

        if (
            chain.height() != ancestor
            or chain.get_hash(ancestor) != next_parent
        ):
            raise RuntimeError("V9 post-rollback verification failed")

    interface.logger.warning(
        "LCC V9: rollback finished at %d; resuming verified catchup",
        ancestor,
    )

    return True
