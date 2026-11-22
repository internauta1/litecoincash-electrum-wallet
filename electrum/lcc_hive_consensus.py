"""Litecoin Cash Hive component verification.

Coordinates existing Hive cryptographic and BCT validators.

IMPORTANT:
This is not a complete block-consensus validator.
It must never be used alone to accept a block or advance
the verified header chain.
"""

from .lcc_hive import (
    parse_hive_proof,
    previous_hash_message,
    verify_signature,
    verify_bee_hash,
)

from .lcc_hive12 import verify_hive12_bee_hash
from .lcc_bct import validate_mainnet_bct


class HiveConsensusError(Exception):
    pass


def verify_hive_crypto_components(
    *,
    proof,
    previous_hashes,
    honey_hash160,
    expected_bits,
    hive12_enabled,
):
    """Verify Hive signature and version-dependent Bee Hash.

    All previous hashes and activation states must originate
    from the same authenticated historical branch.
    """

    if type(hive12_enabled) is not bool:
        raise HiveConsensusError("Invalid Hive 1.2 state")

    parsed = parse_hive_proof(proof)

    verify_signature(
        parsed["signature"],
        previous_hashes,
        honey_hash160,
    )

    if hive12_enabled:
        # Core Hive 1.2 hashes the concatenated ASCII text,
        # not Bitcoin's serialized CHashWriter representation.
        if (
            not isinstance(previous_hashes, (list, tuple))
            or len(previous_hashes) != 6
            or any(
                not isinstance(h, str)
                or len(h) != 64
                or any(c not in "0123456789abcdef" for c in h)
                for h in previous_hashes
            )
        ):
            raise HiveConsensusError(
                "Invalid six-block deterministic history"
            )

        deterministic = "".join(previous_hashes)

        verify_hive12_bee_hash(
            deterministic_string=deterministic,
            bct_txid=parsed["bct_txid"],
            bee_nonce=parsed["nonce"],
            expected_bits=expected_bits,
        )

        algorithm = "minotaur-classic"

    else:
        verify_bee_hash(
            parsed["nonce"],
            parsed["bct_txid"],
            previous_hashes,
            expected_bits,
        )

        algorithm = "sha256d"

    return {
        "bct_txid": parsed["bct_txid"],
        "bct_height": parsed["bct_height"],
        "bee_nonce": parsed["nonce"],
        "algorithm": algorithm,
        "community_contribution": parsed["community_contribution"],
        "cryptography_verified": True,
        "consensus_validated": False,
    }


def verify_hive_bct_components(
    *,
    crypto_result,
    transaction,
    block_height,
    honey_hash160,
    community_contribution,
    minotaurx_enabled_at_creation,
):
    """Check a BCT's scripts, amount, age and bee count.

    The caller remains responsible for authenticating the
    transaction, Merkle proof, historical header and branch.
    """

    if not isinstance(crypto_result, dict):
        raise HiveConsensusError("Missing Hive crypto result")

    if crypto_result.get("cryptography_verified") is not True:
        raise HiveConsensusError("Hive cryptography not verified")

    if (
        type(community_contribution) is not bool
        or community_contribution != crypto_result.get(
            "community_contribution"
        )
    ):
        raise HiveConsensusError(
            "Community flag differs from Hive coinbase proof"
        )

    eligibility = validate_mainnet_bct(
        transaction=transaction,
        block_height=block_height,
        bct_height=crypto_result["bct_height"],
        bee_nonce=crypto_result["bee_nonce"],
        expected_honey_hash160=honey_hash160,
        community_contribution=community_contribution,
        minotaurx_enabled_at_creation=(
            minotaurx_enabled_at_creation
        ),
    )

    return {
        "bct_txid": crypto_result["bct_txid"],
        "bct_height": crypto_result["bct_height"],
        "bee_nonce": crypto_result["bee_nonce"],
        "eligibility": eligibility,
        "components_verified": True,
        "consensus_validated": False,
    }

# LCC_HIVE_CONSENSUS_INPUT_FIX_V1


# LCC_HIVE_BIP9_DIFFICULTY_V1

def verify_hive_activation_and_difficulty(
    *,
    height,
    header,
    get_header,
    hive_deployment,
    hive11_deployment,
    minotaurx_deployment,
):
    """Verify Hive activation and expected difficulty on one branch.

    Deployment objects must contain the official mainnet parameters.
    This function does not fetch server data or accept a block.
    """
    from .lcc_bip9 import cached_state_for_height as state_for_height, State
    from .lcc_hive_difficulty import next_hive_bits

    if type(height) is not int or height <= 0:
        raise HiveConsensusError("Invalid Hive block height")

    if not isinstance(header, dict):
        raise HiveConsensusError("Invalid Hive header")

    if header.get("block_height") != height:
        raise HiveConsensusError("Hive header height mismatch")

    previous = get_header(height - 1)

    if previous is None:
        raise HiveConsensusError("Missing previous header")

    hive_state = state_for_height(
        height, get_header, hive_deployment
    )
    hive11_state = state_for_height(
        height, get_header, hive11_deployment
    )
    minotaurx_state = state_for_height(
        height, get_header, minotaurx_deployment
    )

    hive_enabled = hive_state == State.ACTIVE
    hive11_enabled = hive11_state == State.ACTIVE
    minotaurx_enabled = minotaurx_state == State.ACTIVE

    if not hive_enabled:
        raise HiveConsensusError(
            "Hive block before BIP9 activation"
        )

    if minotaurx_enabled and not hive11_enabled:
        raise HiveConsensusError(
            "Inconsistent Hive activation states"
        )

    def is_hive(h):
        historic = get_header(h)

        if historic is None:
            raise HiveConsensusError(
                f"Missing historical header {h}"
            )

        # Mainnet Hive nonce marker.
        return historic["nonce"] == 192

    # LCC_BIP9_PREVIOUS_BLOCK_SEMANTICS_V1
    # Core IsHive11Enabled(pindexPrev) and
    # IsMinotaurXEnabled(pindexPrev) test activation
    # for the block AFTER the supplied previous index.
    def hive11_at(h):
        return (
            state_for_height(
                h + 1, get_header, hive11_deployment
            ) == State.ACTIVE
        )

    def minotaurx_at(h):
        return (
            state_for_height(
                h + 1, get_header, minotaurx_deployment
            ) == State.ACTIVE
        )

    expected_bits = next_hive_bits(
        height - 1,
        get_header,
        is_hive,
        hive11_at,
        minotaurx_at,
    )

    if header.get("bits") != expected_bits:
        raise HiveConsensusError(
            f"Hive difficulty mismatch: "
            f"{header.get('bits')} != {expected_bits}"
        )

    return {
        "height": height,
        "expected_bits": expected_bits,
        "hive_enabled": hive_enabled,
        "hive11_enabled": hive11_enabled,
        "hive12_enabled": minotaurx_enabled,
        "activation_and_difficulty_verified": True,
        "consensus_validated": False,
    }


# LCC_OFFICIAL_DEPLOYMENT_WRAPPER_V1

def verify_mainnet_hive_activation_and_difficulty(
    *,
    height,
    header,
    get_header,
):
    from .lcc_mainnet import mainnet_bip9_deployments

    deployments = mainnet_bip9_deployments()

    return verify_hive_activation_and_difficulty(
        height=height,
        header=header,
        get_header=get_header,
        hive_deployment=deployments["hive"],
        hive11_deployment=deployments["hive11"],
        minotaurx_deployment=deployments["minotaurx"],
    )


# LCC_HIVE_COINBASE_EVIDENCE_V1

def verify_hive_coinbase_commitment(
    *,
    candidate_header,
    height,
    raw_coinbase,
    coinbase_txid,
    merkle_branch,
):
    """Verify Hive coinbase inclusion in a candidate header.

    This establishes transaction commitment, not full block
    consensus validity. Candidate header and ancestors still
    need independent validation.
    """
    from .blockchain import hash_header
    from .transaction import Transaction
    from .lcc_hive import parse_hive_proof, verify_bct_merkle

    if type(height) is not int or height <= 0:
        raise HiveConsensusError("Invalid Hive block height")

    if (
        not isinstance(candidate_header, dict)
        or candidate_header.get("block_height") != height
    ):
        raise HiveConsensusError("Candidate header height mismatch")

    if (
        not isinstance(raw_coinbase, bytes)
        or not 44 <= len(raw_coinbase) <= 4_000_000
    ):
        raise HiveConsensusError("Invalid coinbase bytes")

    if (
        not isinstance(coinbase_txid, str)
        or len(coinbase_txid) != 64
        or any(c not in "0123456789abcdef"
               for c in coinbase_txid)
    ):
        raise HiveConsensusError("Invalid coinbase TXID")

    if (
        not isinstance(merkle_branch, list)
        or len(merkle_branch) > 64
        or any(
            not isinstance(h, str)
            or len(h) != 64
            or any(c not in "0123456789abcdef" for c in h)
            for h in merkle_branch
        )
    ):
        raise HiveConsensusError("Invalid coinbase Merkle branch")

    root = candidate_header.get("merkle_root")

    if (
        not isinstance(root, str)
        or len(root) != 64
        or any(c not in "0123456789abcdef" for c in root)
    ):
        raise HiveConsensusError("Invalid candidate Merkle root")

    # Check the coinbase prevout without assuming that the
    # transaction necessarily uses legacy serialization.
    offset = 4

    if raw_coinbase[4] == 0 and raw_coinbase[5] != 0:
        offset = 6

    first = raw_coinbase[offset]
    offset += 1

    if first < 253:
        input_count = first
    elif first == 253:
        input_count = int.from_bytes(
            raw_coinbase[offset:offset + 2], "little"
        )
        offset += 2
    elif first == 254:
        input_count = int.from_bytes(
            raw_coinbase[offset:offset + 4], "little"
        )
        offset += 4
    else:
        input_count = int.from_bytes(
            raw_coinbase[offset:offset + 8], "little"
        )
        offset += 8

    if input_count != 1:
        raise HiveConsensusError("Invalid coinbase input count")

    if (
        raw_coinbase[offset:offset + 32] != bytes(32)
        or raw_coinbase[offset + 32:offset + 36]
        != bytes.fromhex("ffffffff")
    ):
        raise HiveConsensusError("Transaction is not coinbase")

    try:
        tx = Transaction(raw_coinbase.hex())
        actual_txid = tx.txid()
        outputs = tx.outputs()
    except Exception as exc:
        raise HiveConsensusError(
            "Could not deserialize Hive coinbase"
        ) from exc

    if actual_txid != coinbase_txid:
        raise HiveConsensusError("Coinbase TXID mismatch")

    if len(outputs) not in (2, 3):
        raise HiveConsensusError(
            "Invalid Hive coinbase output count"
        )

    proof_script = bytes(outputs[0].scriptpubkey)
    honey_script = bytes(outputs[1].scriptpubkey)

    if len(proof_script) < 144:
        raise HiveConsensusError("Missing Hive proof")

    parsed = parse_hive_proof(proof_script)

    if (
        len(honey_script) != 25
        or honey_script[:3] != bytes.fromhex("76a914")
        or honey_script[23:] != bytes.fromhex("88ac")
    ):
        raise HiveConsensusError(
            "Hive honey output must be P2PKH"
        )

    verify_bct_merkle(
        coinbase_txid,
        merkle_branch,
        0,
        root,
    )

    return {
        "height": height,
        "candidate_header_hash": hash_header(
            candidate_header
        ),
        "coinbase_txid": coinbase_txid,
        "proof_script": proof_script,
        "honey_hash160": honey_script[3:23],
        "bct_txid": parsed["bct_txid"],
        "bct_height": parsed["bct_height"],
        "bee_nonce": parsed["nonce"],
        "community_contribution": parsed[
            "community_contribution"
        ],
        "coinbase_commitment_verified": True,
        "full_block_checked": False,
        "consensus_validated": False,
    }


async def fetch_hive_coinbase_evidence(
    *,
    interface,
    candidate_header,
    height,
    full_block=None,
):
    """Fetch coinbase at position zero using ElectrumX.

    Verification is against the supplied candidate header,
    which may not yet be in the local header database.
    """
    if (
        not isinstance(candidate_header, dict)
        or candidate_header.get("block_height") != height
    ):
        raise HiveConsensusError(
            "Invalid candidate header"
        )

    # LCC_P2P_COINBASE_V1
    # Fast path ONLY for structurally verified one-transaction blocks.
    # The existing cryptographic verifier checks the transaction,
    # its TXID and its Merkle commitment against the candidate header.
    if full_block is not None:
        from .blockchain import hash_header

        if not isinstance(full_block, dict):
            raise HiveConsensusError("Invalid P2P block evidence")

        raw_block = full_block.get("raw_block")
        structure = full_block.get("structure")
        expected_hash = hash_header(candidate_header)

        if (
            not isinstance(raw_block, (bytes, bytearray))
            or len(raw_block) < 82
            or not isinstance(structure, dict)
            or full_block.get("block_hash") != expected_hash
            or structure.get("candidate_header_hash") != expected_hash
        ):
            raise HiveConsensusError(
                "P2P block identity or structure mismatch"
            )

        # At offset 80, CompactSize value 0x01 means exactly
        # one transaction. No Merkle siblings are needed.
        # The full-block structural verifier has already checked
        # transaction count, serialization and block Merkle root.
        if raw_block[80] == 1:
            coinbase_txid = structure.get("coinbase_txid")

            if (
                not isinstance(coinbase_txid, str)
                or len(coinbase_txid) != 64
            ):
                raise HiveConsensusError(
                    "Invalid P2P coinbase TXID"
                )

            evidence = verify_hive_coinbase_commitment(
                candidate_header=candidate_header,
                height=height,
                raw_coinbase=bytes(raw_block[81:]),
                coinbase_txid=coinbase_txid,
                merkle_branch=[],
            )

            interface.logger.warning(
                "LCC LAB P2P COINBASE: height=%d "
                "verified without ElectrumX coinbase RPC",
                height,
            )

            return evidence

        # Multi-transaction blocks retain the existing
        # ElectrumX proof path until local Merkle-branch
        # construction has been implemented.
        interface.logger.info(
            "LCC P2P coinbase: multi-transaction block %d; "
            "using ElectrumX proof",
            height,
        )

    response = await interface.session.send_request(
        "blockchain.transaction.id_from_pos",
        [height, 0, True],
    )

    if not isinstance(response, dict):
        raise HiveConsensusError(
            "Invalid coinbase position response"
        )

    txid = response.get("tx_hash")
    branch = response.get("merkle")

    if (
        not isinstance(txid, str)
        or len(txid) != 64
        or any(c not in "0123456789abcdef" for c in txid)
    ):
        raise HiveConsensusError("Invalid coinbase TXID")

    if not isinstance(branch, list):
        raise HiveConsensusError("Missing coinbase Merkle proof")

    raw_hex = await interface.session.send_request(
        "blockchain.transaction.get",
        [txid],
    )

    if (
        not isinstance(raw_hex, str)
        or len(raw_hex) > 8_000_000
    ):
        raise HiveConsensusError("Invalid coinbase response")

    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise HiveConsensusError(
            "Invalid coinbase encoding"
        ) from exc

    return verify_hive_coinbase_commitment(
        candidate_header=candidate_header,
        height=height,
        raw_coinbase=raw,
        coinbase_txid=txid,
        merkle_branch=branch,
    )
