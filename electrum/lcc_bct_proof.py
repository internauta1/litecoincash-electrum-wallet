"""Authenticated BCT inclusion verification for Litecoin Cash.

No network calls are performed by this module.

Transaction bytes, merkle branch and block header must be obtained
by the caller. Header authenticity is an external prerequisite.
"""

import hashlib

from .lcc_hive import verify_bct_merkle


class BCTProofError(Exception):
    pass


def verify_bct_inclusion(
    *,
    raw_transaction,
    expected_txid,
    merkle_branch,
    position,
    block_header,
    block_height,
):
    """Verify a BCT transaction against its historical block header.

    The block header must already belong to a consensus-validated
    branch. This function cannot validate the header itself.
    """
    if not isinstance(raw_transaction, bytes) or not raw_transaction:
        raise BCTProofError("Invalid raw transaction")

    if not isinstance(expected_txid, str) or len(expected_txid) != 64:
        raise BCTProofError("Invalid expected TXID")

    if block_header is None:
        raise BCTProofError("Missing historical block header")

    if block_header.get("block_height") != block_height:
        raise BCTProofError("BCT block height mismatch")

    # Use the transaction's non-witness serialization for TXID.
    # Hashing complete SegWit bytes would produce a WTXID instead.
    from .transaction import Transaction

    try:
        actual_txid = Transaction(
            raw_transaction.hex()
        ).txid()
    except Exception as exc:
        raise BCTProofError("Invalid BCT transaction") from exc

    if not isinstance(actual_txid, str):
        raise BCTProofError("Could not calculate BCT TXID")

    if actual_txid != expected_txid.lower():
        raise BCTProofError("BCT transaction hash mismatch")

    root = block_header.get("merkle_root")

    if not isinstance(root, str) or len(root) != 64:
        raise BCTProofError("Missing block merkle root")

    try:
        verify_bct_merkle(
            actual_txid,
            merkle_branch,
            position,
            root,
        )
    except Exception as exc:
        raise BCTProofError("BCT inclusion proof failed") from exc

    return True


# LCC_BCT_NETWORK_EVIDENCE_V1

async def fetch_bct_inclusion_evidence(
    *,
    interface,
    network,
    txid,
    bct_height,
):
    """Obtain BCT data and verify its Merkle inclusion locally.

    IMPORTANT: This verifies inclusion relative to a local header.
    It does NOT establish that the header or its chain satisfies
    Litecoin Cash consensus. It must not authorize block acceptance.
    """
    if (
        not isinstance(txid, str)
        or len(txid) != 64
        or any(c not in "0123456789abcdef" for c in txid.lower())
    ):
        raise BCTProofError("Invalid BCT TXID")

    if type(bct_height) is not int or bct_height < 0:
        raise BCTProofError("Invalid BCT height")

    # LCC_BCT_P2P_FASTPATH_V1
    # Only inside the isolated experimental laboratory.
    import os
    import asyncio

    bootstrap = os.environ.get("LCC_P2P_BOOTSTRAP")

    if (
        os.environ.get("ELECTRUM_LCC_EXPERIMENTAL_HIVE_SPV") == "1"
        and bootstrap
    ):
        from .blockchain import hash_header

        # LCC_BETA2_BCT_LOCK_V7
        import asyncio as _lcc_asyncio
        import os as _lcc_os
        from .lcc_experimental_catchup import (
            _lcc_bhi_owner,
            _LCCAlreadyLockedContext,
        )
        _lcc_owned = (
            _lcc_os.environ.get(
                'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
            ) == '1'
            and _lcc_bhi_owner.get()
                is _lcc_asyncio.current_task()
        )
        if _lcc_owned and not network.bhi_lock.locked():
            raise RuntimeError(
                'BCT BHI lock ownership inconsistent'
            )
        async with (
            _LCCAlreadyLockedContext()
            if _lcc_owned
            else network.bhi_lock
        ):
            selected_chain = network.blockchain()
            isolated = (
                "beta2-hive-experimental-"
                in str(selected_chain.path())
            )
            historical_header = (
                selected_chain.read_header(bct_height)
                if isolated else None
            )
            historical_hash = (
                hash_header(historical_header)
                if historical_header is not None else None
            )

        if isolated and historical_hash is not None:
            from .lcc_p2p_blocks import (
                request_block_from_peer,
                LCCP2PError,
            )
            from .lcc_p2p_bct import extract_bct_from_block

            try:
                host, port_text = bootstrap.rsplit(":", 1)
                raw_block = await request_block_from_peer(
                    host=host,
                    port=int(port_text),
                    block_hash=historical_hash,
                    timeout=5,
                )
            except (OSError, asyncio.TimeoutError, LCCP2PError) as exc:
                interface.logger.warning(
                    "LCC LAB BCT P2P unavailable: %s; "
                    "falling back to ElectrumX",
                    exc,
                )
            else:
                proof = extract_bct_from_block(
                    raw_block=raw_block,
                    candidate_header=historical_header,
                    expected_txid=txid,
                )

                # LCC_BETA2_BCT_LOCK_V7
                import asyncio as _lcc_asyncio
                import os as _lcc_os
                from .lcc_experimental_catchup import (
                    _lcc_bhi_owner,
                    _LCCAlreadyLockedContext,
                )
                _lcc_owned = (
                    _lcc_os.environ.get(
                        'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
                    ) == '1'
                    and _lcc_bhi_owner.get()
                        is _lcc_asyncio.current_task()
                )
                if _lcc_owned and not network.bhi_lock.locked():
                    raise RuntimeError(
                        'BCT BHI lock ownership inconsistent'
                    )
                async with (
                    _LCCAlreadyLockedContext()
                    if _lcc_owned
                    else network.bhi_lock
                ):
                    current = network.blockchain()
                    current_header = current.read_header(bct_height)

                    if (
                        current is not selected_chain
                        or current_header is None
                        or hash_header(current_header) != historical_hash
                    ):
                        raise BCTProofError(
                            "Historical BCT branch changed"
                        )

                    verify_bct_inclusion(
                        raw_transaction=proof["raw_transaction"],
                        expected_txid=txid,
                        merkle_branch=proof["merkle_branch"],
                        position=proof["position"],
                        block_header=current_header,
                        block_height=bct_height,
                    )

                interface.logger.warning(
                    "LCC LAB BCT P2P: height=%d "
                    "txid=%s transactions=%d",
                    bct_height,
                    txid,
                    proof["transaction_count"],
                )

                return {
                    "raw_transaction": proof["raw_transaction"],
                    "txid": txid.lower(),
                    "bct_height": bct_height,
                    "header_hash": historical_hash,
                    "merkle_branch": proof["merkle_branch"],
                    "position": proof["position"],
                    "consensus_validated": False,
                }

    # LCC_PARALLEL_BCT_RPC_V1
    import asyncio

    raw_hex, merkle = await asyncio.gather(
        interface.session.send_request('blockchain.transaction.get', [txid]),
        interface.session.send_request('blockchain.transaction.get_merkle', [txid, bct_height]),
    )

    if not isinstance(raw_hex, str):
        raise BCTProofError("Invalid transaction response")

    if len(raw_hex) > 8_000_000:
        raise BCTProofError("Transaction response too large")

    try:
        raw_transaction = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise BCTProofError("Invalid transaction encoding") from exc

    if not isinstance(merkle, dict):
        raise BCTProofError("Invalid Merkle response")

    if merkle.get("block_height") != bct_height:
        raise BCTProofError("Merkle block height mismatch")

    branch = merkle.get("merkle")
    position = merkle.get("pos")

    if not isinstance(branch, list) or len(branch) > 64:
        raise BCTProofError("Invalid Merkle branch")

    if type(position) is not int or position < 0:
        raise BCTProofError("Invalid Merkle position")

    # Protect the header/branch lookup against concurrent reorgs.
    # LCC_BETA2_BCT_LOCK_V7
    import asyncio as _lcc_asyncio
    import os as _lcc_os
    from .lcc_experimental_catchup import (
        _lcc_bhi_owner,
        _LCCAlreadyLockedContext,
    )
    _lcc_owned = (
        _lcc_os.environ.get(
            'ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC'
        ) == '1'
        and _lcc_bhi_owner.get()
            is _lcc_asyncio.current_task()
    )
    if _lcc_owned and not network.bhi_lock.locked():
        raise RuntimeError(
            'BCT BHI lock ownership inconsistent'
        )
    async with (
        _LCCAlreadyLockedContext()
        if _lcc_owned
        else network.bhi_lock
    ):
        chain = network.blockchain()
        header = chain.read_header(bct_height)

        if header is None:
            raise BCTProofError(
                "BCT historical header unavailable"
            )

        verify_bct_inclusion(
            raw_transaction=raw_transaction,
            expected_txid=txid,
            merkle_branch=branch,
            position=position,
            block_header=header,
            block_height=bct_height,
        )

        # Identify the branch associated with this evidence.
        from .blockchain import hash_header
        historical_header_hash = hash_header(header)

    return {
        "raw_transaction": raw_transaction,
        "txid": txid.lower(),
        "bct_height": bct_height,
        "header_hash": historical_header_hash,
        "merkle_branch": branch,
        "position": position,
        "consensus_validated": False,
    }
