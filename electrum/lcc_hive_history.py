"""Historical evidence coordinator for Litecoin Cash Hive.

No block acceptance or header persistence is performed here.
Only use this with independently validated ancestor headers.
"""

from .blockchain import hash_header
from .transaction import Transaction
from .lcc_bip9 import State, cached_state_for_height
from .lcc_mainnet import mainnet_bip9_deployments
from .lcc_bct import validate_mainnet_bct
from .lcc_bct_proof import fetch_bct_inclusion_evidence
from .lcc_hive_consensus import (
    fetch_hive_coinbase_evidence,
    verify_mainnet_hive_activation_and_difficulty,
)


class HiveHistoryError(Exception):
    pass


def check_branch_anchor(
    *,
    chain,
    candidate_header,
    height,
    parent_hash,
    bct_height=None,
    bct_header_hash=None,
):
    """Verify evidence is still anchored to this historical branch."""
    previous = chain.read_header(height - 1)

    if previous is None:
        raise HiveHistoryError("Missing previous block")

    actual_parent = hash_header(previous)

    if actual_parent != parent_hash:
        raise HiveHistoryError("Chain reorganized during verification")

    if candidate_header.get("prev_block_hash") != actual_parent:
        raise HiveHistoryError("Candidate parent mismatch")

    if bct_height is not None:
        historic = chain.read_header(bct_height)

        if historic is None:
            raise HiveHistoryError("Missing BCT historical header")

        if hash_header(historic) != bct_header_hash:
            raise HiveHistoryError(
                "BCT evidence belongs to another branch"
            )


async def collect_hive_historical_evidence(
    *,
    interface,
    network,
    candidate_header,
    full_block=None,
):
    """Authenticate Hive coinbase and its historical BCT.

    No consensus-valid result is issued:
    - historical reference hashes remain to be integrated
    - Bee Hash and signature checks are not performed here
    - full-block constraints are not established
    """

    if not isinstance(candidate_header, dict):
        raise HiveHistoryError("Invalid candidate header")

    height = candidate_header.get("block_height")

    if type(height) is not int or height <= 0:
        raise HiveHistoryError("Invalid candidate height")

    # Capture the parent on the selected, locally stored branch.
    # LCC_BETA2_HIVE_HISTORY_LOCK_V6
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owner_here = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if (
        _lcc_owner_here
        and not network.bhi_lock.locked()
    ):
        raise RuntimeError(
            'Historical Hive BHI ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owner_here
        else network.bhi_lock
    ):
        chain = network.blockchain()

        parent = chain.read_header(height - 1)

        if parent is None:
            raise HiveHistoryError("Unverified candidate ancestry")

        parent_hash = hash_header(parent)

        check_branch_anchor(
            chain=chain,
            candidate_header=candidate_header,
            height=height,
            parent_hash=parent_hash,
        )

    # Verify official mainnet BIP9 activation and expected Hive bits.
    # This is deliberately not permission to accept the header.
    activation = verify_mainnet_hive_activation_and_difficulty(
        height=height,
        header=candidate_header,
        get_header=chain.read_header,
    )

    # Fetch and verify the actual coinbase commitment.
    coinbase = await fetch_hive_coinbase_evidence(
        interface=interface,
        candidate_header=candidate_header,
        height=height,
        full_block=full_block,
    )

    if coinbase.get("coinbase_commitment_verified") is not True:
        raise HiveHistoryError("Coinbase proof not verified")

    if coinbase.get("candidate_header_hash") != hash_header(
        candidate_header
    ):
        raise HiveHistoryError("Candidate header identity mismatch")

    bct_height = coinbase["bct_height"]
    bct_txid = coinbase["bct_txid"]

    if type(bct_height) is not int or not 0 < bct_height < height:
        raise HiveHistoryError("Invalid historical BCT height")

    # Authenticate the referenced BCT against its original block.
    bct = await fetch_bct_inclusion_evidence(
        interface=interface,
        network=network,
        txid=bct_txid,
        bct_height=bct_height,
    )

    if (
        bct["txid"] != bct_txid.lower()
        or bct["bct_height"] != bct_height
    ):
        raise HiveHistoryError("BCT identity mismatch")

    # Determine the MinotaurX state for the BCT creation context.
    # Core's historic BCT lookup uses IsMinotaurXEnabled()
    # with the BCT block index, hence the following block state.
    deployments = mainnet_bip9_deployments()

    creation_minotaurx_enabled = (
        cached_state_for_height(
            bct_height + 1,
            chain.read_header,
            deployments["minotaurx"],
        ) == State.ACTIVE
    )

    try:
        transaction = Transaction(
            bct["raw_transaction"].hex()
        )

        eligibility = validate_mainnet_bct(
            transaction=transaction,
            block_height=height,
            bct_height=bct_height,
            bee_nonce=coinbase["bee_nonce"],
            expected_honey_hash160=coinbase["honey_hash160"],
            community_contribution=coinbase[
                "community_contribution"
            ],
            minotaurx_enabled_at_creation=(
                creation_minotaurx_enabled
            ),
        )

    except Exception as exc:
        raise HiveHistoryError(
            "Historical BCT validation failed"
        ) from exc

    # Recheck after all network operations and calculations.
    # LCC_BETA2_HIVE_HISTORY_LOCK_V6
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owner_here = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if (
        _lcc_owner_here
        and not network.bhi_lock.locked()
    ):
        raise RuntimeError(
            'Historical Hive BHI ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owner_here
        else network.bhi_lock
    ):
        current_chain = network.blockchain()

        check_branch_anchor(
            chain=current_chain,
            candidate_header=candidate_header,
            height=height,
            parent_hash=parent_hash,
            bct_height=bct_height,
            bct_header_hash=bct["header_hash"],
        )

    return {
        "height": height,
        "candidate_header_hash": hash_header(candidate_header),
        "parent_hash": parent_hash,
        "bct_header_hash": bct["header_hash"],
        "coinbase": coinbase,
        "bct": bct,
        "eligibility": eligibility,
        "activation": activation,
        "historical_evidence_verified": True,
        "hive_cryptography_verified": False,
        "full_block_checked": False,
        "consensus_validated": False,
    }


# LCC_HIVE_REFERENCE_AND_CRYPTO_V1

# Confirmed against the historical Core reference function.
HIVE_REFERENCE_OFFSETS = (0, 13, 173, 471, 1363, 12103)


def hive_reference_hashes(height, get_header):
    """Six Core historical hashes for the candidate Hive block.

    The first reference is the candidate's previous block.
    All headers must belong to one authenticated branch.
    """
    if type(height) is not int or height <= 12103:
        raise HiveHistoryError("Insufficient Hive history")

    previous_height = height - 1
    result = []

    for offset in HIVE_REFERENCE_OFFSETS:
        historical_height = previous_height - offset
        header = get_header(historical_height)

        if header is None:
            raise HiveHistoryError(
                f"Missing reference header {historical_height}"
            )

        if header.get("block_height") != historical_height:
            raise HiveHistoryError(
                "Historical reference height mismatch"
            )

        result.append(hash_header(header))

    return result


async def collect_hive_verified_components(
    *,
    interface,
    network,
    candidate_header,
    full_block=None,
):
    """Verify historical commitments, BCT and Hive cryptography.

    Does not authorize block acceptance. Full-block checks,
    complete ancestry validation and chainwork remain separate.
    """
    from .lcc_hive_consensus import (
        verify_hive_crypto_components,
    )

    evidence = await collect_hive_historical_evidence(
        interface=interface,
        network=network,
        candidate_header=candidate_header,
        full_block=full_block,
    )

    height = evidence["height"]
    coinbase = evidence["coinbase"]

    # LCC_BETA2_HIVE_HISTORY_LOCK_V6
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owner_here = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if (
        _lcc_owner_here
        and not network.bhi_lock.locked()
    ):
        raise RuntimeError(
            'Historical Hive BHI ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owner_here
        else network.bhi_lock
    ):
        chain = network.blockchain()

        check_branch_anchor(
            chain=chain,
            candidate_header=candidate_header,
            height=height,
            parent_hash=evidence["parent_hash"],
            bct_height=coinbase["bct_height"],
            bct_header_hash=evidence["bct_header_hash"],
        )

        references = hive_reference_hashes(
            height,
            chain.read_header,
        )

        # LCC_HIVE_CONSECUTIVE_BLOCK_RULE_V1
        verify_hive_block_sequence(
            height=height,
            get_header=chain.read_header,
            hive11_enabled=evidence["activation"]["hive11_enabled"],
        )

    crypto = verify_hive_crypto_components(
        proof=coinbase["proof_script"],
        previous_hashes=references,
        honey_hash160=coinbase["honey_hash160"],
        expected_bits=evidence["activation"]["expected_bits"],
        hive12_enabled=evidence["activation"]["hive12_enabled"],
    )

    if (
        crypto["bct_txid"] != evidence["bct"]["txid"]
        or crypto["bct_height"] != coinbase["bct_height"]
        or crypto["bee_nonce"] != coinbase["bee_nonce"]
        or crypto["community_contribution"]
        != coinbase["community_contribution"]
    ):
        raise HiveHistoryError(
            "Cryptographic proof differs from historical BCT"
        )

    # Reject evidence if its branch changed during verification.
    # LCC_BETA2_HIVE_HISTORY_LOCK_V6
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owner_here = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if (
        _lcc_owner_here
        and not network.bhi_lock.locked()
    ):
        raise RuntimeError(
            'Historical Hive BHI ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owner_here
        else network.bhi_lock
    ):
        chain = network.blockchain()

        check_branch_anchor(
            chain=chain,
            candidate_header=candidate_header,
            height=height,
            parent_hash=evidence["parent_hash"],
            bct_height=coinbase["bct_height"],
            bct_header_hash=evidence["bct_header_hash"],
        )

        if references != hive_reference_hashes(
            height,
            chain.read_header,
        ):
            raise HiveHistoryError(
                "Historical reference chain changed"
            )

    return {
        **evidence,
        "reference_hashes": tuple(references),
        "cryptography": crypto,
        "hive_cryptography_verified": True,
        "full_block_checked": False,
        "consensus_validated": False,
    }

# LCC_HIVE_P2P_INTEGRATION_V1

async def collect_hive_with_full_block(
    *,
    interface,
    network,
    candidate_header,
    peers=None,
    prefetched_full_block=None,
):
    """Combine historical Hive evidence with a P2P full block.

    Does not bypass any consensus checks.
    """
    from .lcc_p2p_blocks import fetch_verified_hive_block

    # LCC_P2P_COINBASE_V1
    # Obtain and structurally verify the complete block first.
    # LCC_EXPERIMENTAL_HIVE_FULLBLOCK_PREFETCH_V1
    if prefetched_full_block is None:
        full_block = await fetch_verified_hive_block(
            candidate_header=candidate_header,
            peers=peers,
        )
    else:
        # Never trust the prefetch cache without checking identity.
        import hashlib
        from .blockchain import hash_header

        full_block = prefetched_full_block
        raw = (
            full_block.get("raw_block")
            if isinstance(full_block, dict)
            else None
        )

        if not isinstance(raw, bytes) or len(raw) < 81:
            raise HiveHistoryError(
                "Invalid prefetched P2P block"
            )

        actual_hash = hashlib.sha256(
            hashlib.sha256(raw[:80]).digest()
        ).digest()[::-1].hex()

        if actual_hash != hash_header(candidate_header):
            raise HiveHistoryError(
                "Prefetched P2P block identity mismatch"
            )

        structure = full_block.get("structure")

        if (
            not isinstance(structure, dict)
            or not isinstance(
                structure.get("coinbase_txid"), str
            )
        ):
            raise HiveHistoryError(
                "Invalid prefetched block structure"
            )

    evidence = await collect_hive_verified_components(
        interface=interface,
        network=network,
        candidate_header=candidate_header,
        full_block=full_block,
    )

    structure = full_block["structure"]
    coinbase = evidence["coinbase"]

    if structure["coinbase_txid"] != coinbase["coinbase_txid"]:
        raise HiveHistoryError(
            "P2P coinbase differs from ElectrumX evidence"
        )

    # LCC_BETA2_HIVE_HISTORY_LOCK_V6
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owner_here = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if (
        _lcc_owner_here
        and not network.bhi_lock.locked()
    ):
        raise RuntimeError(
            'Historical Hive BHI ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owner_here
        else network.bhi_lock
    ):
        chain = network.blockchain()

        check_branch_anchor(
            chain=chain,
            candidate_header=candidate_header,
            height=evidence["height"],
            parent_hash=evidence["parent_hash"],
            bct_height=coinbase["bct_height"],
            bct_header_hash=evidence["bct_header_hash"],
        )

        if evidence["reference_hashes"] != tuple(
            hive_reference_hashes(
                evidence["height"],
                chain.read_header,
            )
        ):
            raise HiveHistoryError(
                "Hive reference branch changed"
            )

    return {
        **evidence,
        "full_block": full_block,
        "full_block_structure_verified": True,
        "full_consensus_verified": False,
        "consensus_validated": False,
    }


def verify_hive_block_sequence(
    *,
    height,
    get_header,
    hive11_enabled,
):
    """Match Core CheckHiveProof consecutive-Hive rules.

    Before Hive 1.1: Hive must follow PoW.
    From Hive 1.1: no three consecutive Hive blocks.
    """
    if type(height) is not int or height < 2:
        raise HiveHistoryError("Invalid Hive sequence height")

    previous = get_header(height - 1)

    if previous is None:
        raise HiveHistoryError("Missing previous header")

    if previous.get("block_height") != height - 1:
        raise HiveHistoryError("Previous height mismatch")

    if previous.get("nonce") != 192:
        return True

    if not hive11_enabled:
        raise HiveHistoryError(
            "Hive 1.0 block cannot follow another Hive block"
        )

    second_previous = get_header(height - 2)

    if second_previous is None:
        raise HiveHistoryError("Missing second previous header")

    if second_previous.get("block_height") != height - 2:
        raise HiveHistoryError("Second previous height mismatch")

    if second_previous.get("nonce") == 192:
        raise HiveHistoryError(
            "More than two consecutive Hive blocks"
        )

    return True
