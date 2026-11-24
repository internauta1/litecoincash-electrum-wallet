
"""Isolated experimental LCC PoW/Hive header catchup.

Not a full-consensus validator. Never enabled by default.
"""

import asyncio
import os

from .blockchain import deserialize_header, hash_header
from .lcc_header_rules import (
    FIRST_HIVE_BLOCK_HEIGHT,
    classify_header,
)
from .lcc_experimental_hive_spv import accept_first_hive_spv



# LCC_EXPERIMENTAL_HEADER_BATCH_V1
def _lcc_decode_header_batch(reply, requested):
    """Decode ElectrumX headers without trusting remote metadata."""
    if (
        type(requested) is not int
        or not 1 <= requested <= 96
        or not isinstance(reply, dict)
    ):
        raise ValueError("Invalid header batch arguments")

    count = reply.get("count")

    if (
        type(count) is not int
        or not 0 <= count <= requested
    ):
        raise ValueError("Invalid ElectrumX header count")

    has_hex = "hex" in reply
    has_list = "headers" in reply

    if has_hex == has_list:
        raise ValueError("Ambiguous ElectrumX header encoding")

    if has_hex:
        value = reply["hex"]

        if (
            not isinstance(value, str)
            or len(value) != count * 160
        ):
            raise ValueError("Invalid concatenated headers")

        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("Invalid header hex") from exc

        if len(raw) != count * 80:
            raise ValueError("Incorrect header byte count")

        return tuple(
            raw[i * 80:(i + 1) * 80]
            for i in range(count)
        )

    values = reply["headers"]

    if not isinstance(values, (list, tuple)):
        raise ValueError("Invalid header array")

    if len(values) != count:
        raise ValueError("Header array count mismatch")

    decoded = []

    for item in values:
        if not isinstance(item, str) or len(item) != 160:
            raise ValueError("Invalid individual header")

        try:
            raw = bytes.fromhex(item)
        except ValueError as exc:
            raise ValueError("Invalid header hex") from exc

        if len(raw) != 80:
            raise ValueError("Invalid header length")

        decoded.append(raw)

    return tuple(decoded)



# LCC_EXPERIMENTAL_HIVE_FULLBLOCK_PREFETCH_V1
class _LCCExperimentalHiveP2PPrefetch:
    """Fetch P2P blocks ahead; never pre-accept Hive headers."""

    def __init__(self, batch_headers, start_height, chain_path):
        import asyncio
        import ipaddress
        import os
        from pathlib import Path

        from .blockchain import deserialize_header
        from .lcc_header_rules import classify_header

        self.enabled = (
            os.environ.get(
                "ELECTRUM_LCC_EXPERIMENTAL_HIVE_PREFETCH"
            ) == "1"
        )

        self.tasks = {}
        self.peers = None
        self.specs = []
        self.specs_by_height = {}
        self.retries = 0
        self.semaphore = asyncio.Semaphore(3)

        if not self.enabled:
            return

        if os.environ.get(
            "ELECTRUM_LCC_EXPERIMENTAL_HIVE_SPV"
        ) != "1":
            raise ValueError("Experimental SPV opt-in required")

        path = Path(chain_path)

        if (
            path.name != "blockchain_headers"
            or not path.parent.name.startswith(
                "beta2-hive-experimental-"
            )
        ):
            raise ValueError("Non-isolated blockchain path")

        value = os.environ.get(
            "ELECTRUM_LCC_EXPERIMENTAL_HIVE_PREFETCH_PEERS",
            "",
        )

        parts = [x.strip() for x in value.split(",") if x.strip()]

        if not 1 <= len(parts) <= 4:
            raise ValueError(
                "Configure 1-4 explicit IPv4 P2P peers"
            )

        peers = []

        for item in parts:
            address, separator, port_text = item.rpartition(":")

            if not separator or not port_text.isdecimal():
                raise ValueError("Invalid P2P peer address")

            address = str(ipaddress.IPv4Address(address))
            port = int(port_text)

            if not 1 <= port <= 65535:
                raise ValueError("Invalid P2P peer port")

            peer = (address, port)

            if peer not in peers:
                peers.append(peer)

        self.peers = tuple(peers)

        for offset, raw in enumerate(batch_headers):
            height = start_height + offset
            header = deserialize_header(raw, height)

            kind = classify_header(
                height,
                header["version"],
                header["nonce"],
            )

            if kind == "hive":
                self.specs.append((height, header))
                self.specs_by_height[height] = header

    async def _fetch(self, candidate):
        import asyncio
        from .lcc_p2p_blocks import fetch_verified_hive_block

        async with self.semaphore:
            return await asyncio.wait_for(
                fetch_verified_hive_block(
                    candidate_header=candidate,
                    peers=self.peers,
                ),
                timeout=45,
            )

    def start(self):
        if not self.enabled:
            return

        import asyncio

        try:
            for height, header in self.specs:
                self.tasks[height] = asyncio.create_task(
                    self._fetch(header)
                )
        except BaseException:
            for task in self.tasks.values():
                task.cancel()
            raise

    async def get(self, height):
        if not self.enabled:
            return None

        task = self.tasks.get(height)

        if task is None:
            raise RuntimeError(
                f"Missing prefetched Hive block at {height}"
            )

        from .lcc_p2p_blocks import LCCP2PError

        try:
            return await task
        except (OSError, asyncio.TimeoutError, LCCP2PError):
            pass

        # DEBUG2: transient peer failures are retried locally once
        # instead of throwing away the entire validated header batch.
        # Neither failed attempt writes headers or bypasses checks.
        candidate = self.specs_by_height[height]
        self.retries += 1
        await asyncio.sleep(0.3)
        retry = asyncio.create_task(self._fetch(candidate))
        self.tasks[height] = retry
        return await retry

    async def close(self):
        if not self.tasks:
            return

        import asyncio

        for task in self.tasks.values():
            if not task.done():
                task.cancel()

        await asyncio.gather(
            *self.tasks.values(),
            return_exceptions=True,
        )



# LCC_BETA2_BHI_DEADLOCK_FIX_V4
import asyncio as _lcc_asyncio
from contextvars import ContextVar as _LCCContextVar

_lcc_bhi_owner = _LCCContextVar(
    "lcc_beta2_bhi_owner",
    default=None,
)

class _LCCAlreadyLockedContext:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


async def run_experimental_catchup(
    interface,
    *,
    start_height,
    max_headers=96,
    max_seconds=70,
):
    if os.environ.get(
        "ELECTRUM_LCC_EXPERIMENTAL_HIVE_SPV"
    ) != "1":
        raise RuntimeError("Experimental mode disabled")

    chain = interface.blockchain

    if (
        chain is None
        or "beta2-hive-experimental-" not in str(chain.path())
        or chain is not interface.network.blockchain()
    ):
        raise RuntimeError("Not an isolated selected chain")

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    deadline = started_at + max_seconds

    accepted_pow = 0
    accepted_hive = 0
    already_present = 0
    height = start_height

    try:
        # LCC_EXPERIMENTAL_HEADER_BATCH_V1
        # Fetch together; verify and save strictly one by one.
        # Never treat downloaded headers as consensus-valid.
        if type(max_headers) is not int or not 1 <= max_headers <= 96:
            raise ValueError("Invalid experimental batch size")

        batch_reply = await interface.session.send_request(
            "blockchain.block.headers",
            [start_height, max_headers],
            timeout=20,
        )

        batch_headers = _lcc_decode_header_batch(
            batch_reply, max_headers
        )

        # Prefetch only P2P evidence, never header acceptance.
        prefetch = _LCCExperimentalHiveP2PPrefetch(
            batch_headers,
            start_height,
            interface.blockchain.path(),
        )

        height = start_height
        prefetch.start()

        try:
            for height in range(
                start_height, start_height + len(batch_headers)
            ):
                if loop.time() >= deadline:
                    break

                if height > FIRST_HIVE_BLOCK_HEIGHT + 2048:
                    # LCC_EXPERIMENTAL_POSTFORK_CATCHUP_V1
                    # Additional opt-in for MinotaurX/Hive 1.2.
                    if os.environ.get(
                        "ELECTRUM_LCC_EXPERIMENTAL_HIVE11_CONTINUATION"
                    ) != "1":
                        break

                    if (
                        height >= 2540160
                        and os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_MINOTAURX_CONTINUATION"
                        ) != "1"
                    ):
                        break

                raw_hex = batch_headers[
                    height - start_height
                ].hex()

                if (
                    not isinstance(raw_hex, str)
                    or len(raw_hex) != 160
                ):
                    raise ValueError(
                        f"Invalid header response at {height}"
                    )

                candidate = deserialize_header(
                    bytes.fromhex(raw_hex), height
                )
                candidate_hash = hash_header(candidate)

                kind = classify_header(
                    height,
                    candidate["version"],
                    candidate["nonce"],
                )

                # Check ancestry and median-time-past
                # against the current local historical branch.
                _lcc_owner_here = (
                    _lcc_bhi_owner.get() is _lcc_asyncio.current_task()
                )
                if (
                    _lcc_owner_here
                    and not interface.network.bhi_lock.locked()
                ):
                    raise RuntimeError('BHI ownership inconsistent')
                async with (
                    _LCCAlreadyLockedContext()
                    if _lcc_owner_here
                    else interface.network.bhi_lock
                ):
                    chain = interface.blockchain

                    if chain is not interface.network.blockchain():
                        raise RuntimeError("Selected chain changed")

                    current_height = chain.height()

                    if current_height >= height:
                        if chain.get_hash(height) != candidate_hash:
                            raise RuntimeError(
                                f"Different existing header at {height}"
                            )
                        already_present += 1
                        continue

                    if current_height != height - 1:
                        raise RuntimeError(
                            f"Unexpected chain height {current_height}"
                        )

                    if (
                        candidate["prev_block_hash"]
                        != chain.get_hash(height - 1)
                    ):
                        raise RuntimeError(
                            f"Parent mismatch at {height}"
                        )

                    timestamps = []
                    for h in range(max(0, height - 11), height):
                        previous = chain.read_header(h)

                        if previous is None:
                            raise RuntimeError(
                                f"Missing MTP header {h}"
                            )

                        timestamps.append(previous["timestamp"])

                    median = sorted(timestamps)[len(timestamps) // 2]

                    if candidate["timestamp"] <= median:
                        raise RuntimeError(
                            f"Median-time-past failure at {height}"
                        )

                if kind in ("sha256d", "minotaurx"):
                    _lcc_owner_here = (
                        _lcc_bhi_owner.get() is _lcc_asyncio.current_task()
                    )
                    if (
                        _lcc_owner_here
                        and not interface.network.bhi_lock.locked()
                    ):
                        raise RuntimeError('BHI ownership inconsistent')
                    async with (
                        _LCCAlreadyLockedContext()
                        if _lcc_owner_here
                        else interface.network.bhi_lock
                    ):
                        chain = interface.blockchain

                        if chain is not interface.network.blockchain():
                            raise RuntimeError(
                                "Selected chain changed before PoW"
                            )

                        if chain.height() == height - 1:
                            if not chain.can_connect(candidate):
                                raise RuntimeError(
                                    f"PoW/difficulty verification failed at {height}"
                                )

                            chain.save_header(candidate)
                            accepted_pow += 1

                        elif (
                            chain.height() >= height
                            and chain.get_hash(height) == candidate_hash
                        ):
                            already_present += 1

                        else:
                            raise RuntimeError(
                                f"PoW branch changed at {height}"
                            )

                elif kind == "hive":
                    if prefetch.enabled:
                        full_block = await prefetch.get(height)

                        result = await interface.lcc_collect_hive_candidate(
                            height,
                            peers=prefetch.peers,
                            prefetched_full_block=full_block,
                            prefetched_raw_header=batch_headers[
                                height - start_height
                            ],
                        )
                    else:
                        result = await interface.lcc_collect_hive_candidate(
                            height
                        )

                    verified = result["candidate_header"]

                    if hash_header(verified) != candidate_hash:
                        raise RuntimeError(
                            f"Hive evidence hash mismatch at {height}"
                        )

                    accepted = await accept_first_hive_spv(
                        interface, result
                    )

                    if not accepted:
                        raise RuntimeError(
                            f"Hive acceptance refused at {height}"
                        )

                    accepted_hive += 1

                    interface.logger.warning(
                        "LCC LAB CATCHUP: Hive %d accepted",
                        height,
                    )

                else:
                    raise RuntimeError(
                        f"Unsupported algorithm {kind} at {height}"
                    )

                total = accepted_pow + accepted_hive

                if total <= 5 or total % 10 == 0:
                    interface.logger.warning(
                        "LCC LAB CATCHUP: height=%d "
                        "PoW=%d Hive=%d",
                        height,
                        accepted_pow,
                        accepted_hive,
                    )
        finally:
            await prefetch.close()

    except Exception:
        interface.logger.exception(
            "LCC LAB CATCHUP FAILED at height %d",
            height,
        )
        raise

    interface.logger.warning(
        "LCC LAB CATCHUP FINISHED: height=%d "
        "PoW=%d Hive=%d existing=%d "
        "p2p_retries=%d elapsed=%.2fs",
        interface.blockchain.height(),
        accepted_pow,
        accepted_hive,
        already_present,
        prefetch.retries,
        loop.time() - started_at,
    )

    return {
        "height": interface.blockchain.height(),
        "pow": accepted_pow,
        "hive": accepted_hive,
        "existing": already_present,
    }
