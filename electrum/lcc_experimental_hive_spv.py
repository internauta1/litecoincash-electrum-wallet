
"""Experimental first-Hive SPV acceptance.

Never enabled by default. Not full consensus validation.
"""

import os

from .blockchain import hash_header
from .lcc_header_rules import FIRST_HIVE_BLOCK_HEIGHT


async def accept_first_hive_spv(interface, result):
    if os.environ.get(
        "ELECTRUM_LCC_EXPERIMENTAL_HIVE_SPV"
    ) != "1":
        return False

    if not isinstance(result, dict):
        raise ValueError("Invalid Hive coordinator result")

    candidate = result.get("candidate_header")
    evidence = result.get("evidence")

    if not isinstance(candidate, dict):
        raise ValueError("Missing Hive candidate")

    if not isinstance(evidence, dict):
        raise ValueError("Missing Hive evidence")

    if (
        evidence.get("hive_cryptography_verified") is not True
        or evidence.get("full_block_structure_verified") is not True
    ):
        raise ValueError(
            "Required Hive evidence was not verified"
        )

    # LCC_EXPERIMENTAL_SUBSEQUENT_HIVE_V1
    height = candidate.get('block_height')
    if type(height) is not int or height < FIRST_HIVE_BLOCK_HEIGHT:
        raise ValueError('Invalid Hive candidate height')

    if (
        candidate.get("block_height") != height
        or candidate.get("nonce") != 192
    ):
        raise ValueError("Unexpected Hive candidate")

    candidate_hash = hash_header(candidate)

    # The proof was collected asynchronously. Recheck
    # the selected branch while holding the network lock.
    async with interface.network.bhi_lock:
        chain = interface.blockchain

        if chain is None:
            raise ValueError("No selected blockchain")

        if chain is not interface.network.blockchain():
            raise ValueError(
                "Blockchain changed during Hive verification"
            )

        if "beta2-hive-experimental-" not in str(chain.path()):
            raise ValueError(
                "Experimental acceptance outside isolated directory"
            )

        if chain.height() != height - 1:
            raise ValueError(
                "Chain height changed during Hive verification"
            )

        parent_hash = chain.get_hash(height - 1)

        if candidate.get("prev_block_hash") != parent_hash:
            raise ValueError(
                "Hive candidate no longer extends selected chain"
            )

        receipt = (
            height,
            parent_hash,
            candidate_hash,
        )

        chain._lcc_experimental_hive_receipt = receipt

        try:
            if not chain.can_connect(candidate):
                raise ValueError(
                    "Experimental Hive SPV gate rejected candidate"
                )

            chain.save_header(candidate)

        finally:
            # Never leave reusable acceptance authorization.
            chain._lcc_experimental_hive_receipt = None

        if (
            chain.height() != height
            or chain.get_hash(height) != candidate_hash
        ):
            raise ValueError(
                "Hive header was not stored correctly"
            )

    interface.logger.warning(
        "LCC EXPERIMENTAL SPV: Hive header "
        "stored at height %d, hash=%s; "
        "NOT full consensus validation",
        height,
        candidate_hash,
    )

    return True
