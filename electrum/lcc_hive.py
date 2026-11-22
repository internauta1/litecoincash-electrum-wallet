"""Litecoin Cash Hive cryptographic proof components.

These checks are necessary but NOT sufficient for block consensus.
Historical BCT eligibility and other block rules must be checked
before a Hive block can be accepted.
"""

import hashlib

import electrum_ecc as ecc

from .crypto import hash_160
from .lcc_chainwork import bits_to_target


class HiveProofError(Exception):
    pass


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(n):
    if not 0 <= n <= 0xFFFFFFFF:
        raise HiveProofError("Invalid serialization length")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def serialize_string(value):
    if not isinstance(value, str):
        raise HiveProofError("Expected ASCII string")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HiveProofError("Non-ASCII value") from exc
    return compact_size(len(raw)) + raw


def previous_hash_message(previous_hashes):
    """Serialize the six historical reference hashes."""
    if len(previous_hashes) != 6:
        raise HiveProofError("Expected six previous hashes")

    for item in previous_hashes:
        if not isinstance(item, str) or len(item) != 64:
            raise HiveProofError("Invalid reference hash")
        try:
            bytes.fromhex(item)
        except ValueError as exc:
            raise HiveProofError("Invalid reference hash") from exc

    return serialize_string("".join(previous_hashes))


def parse_hive_proof(proof):
    """Parse the known Hive 1.0 coinbase proof format."""
    if not isinstance(proof, bytes) or len(proof) < 144:
        raise HiveProofError("Incomplete Hive proof")

    if proof[:2] != bytes.fromhex("6abe"):
        raise HiveProofError("Invalid Hive proof marker")

    nonce = int.from_bytes(proof[3:7], "little")
    bct_height = int.from_bytes(proof[8:12], "little")

    try:
        bct_txid = proof[14:78].decode("ascii")
        if len(bct_txid) != 64:
            raise ValueError("Incorrect TXID length")
        bytes.fromhex(bct_txid)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HiveProofError("Invalid BCT TXID") from exc

    return {
        "nonce": nonce,
        "bct_height": bct_height,
        "bct_txid": bct_txid,
        "signature": proof[79:144],
        "community_contribution": proof[12] == 0x51,
    }


def verify_signature(signature, previous_hashes, expected_hash160):
    if len(signature) != 65 or len(expected_hash160) != 20:
        raise HiveProofError("Invalid signature or reward address")

    if not 31 <= signature[0] <= 34:
        raise HiveProofError("Invalid signature recovery byte")

    digest = sha256d(previous_hash_message(previous_hashes))

    try:
        sig64 = signature[1:]

        pubkey = ecc.ECPubkey.from_ecdsa_sig64(
            sig64, signature[0] - 31, digest
        )

        if not pubkey.ecdsa_verify(sig64, digest):
            raise HiveProofError("Invalid Hive ECDSA signature")

        recovered_hash160 = hash_160(
            pubkey.get_public_key_bytes(compressed=True)
        )

    except HiveProofError:
        raise
    except Exception as exc:
        raise HiveProofError("Hive public key recovery failed") from exc

    if recovered_hash160 != expected_hash160:
        raise HiveProofError("Hive reward address mismatch")

    return True


def verify_bee_hash(nonce, bct_txid, previous_hashes, bits):
    if not isinstance(nonce, int) or not 0 <= nonce <= 0xFFFFFFFF:
        raise HiveProofError("Invalid bee nonce")

    payload = (
        previous_hash_message(previous_hashes)
        + serialize_string(bct_txid)
        + nonce.to_bytes(4, "little")
    )

    target = bits_to_target(bits)
    result = sha256d(payload)

    if int.from_bytes(result, "little") >= target:
        raise HiveProofError("Bee Hash exceeds target")

    return result


def verify_bct_merkle(txid, branch, position, expected_root):
    """Verify BCT inclusion against an independently verified header.

    The caller must establish the authenticity of expected_root.
    This check does not prove BCT eligibility or unspent status.
    """
    from .verifier import SPV

    try:
        actual_root = SPV.hash_merkle_root(
            branch, txid, position
        )
    except Exception as exc:
        raise HiveProofError("Invalid BCT Merkle proof") from exc

    if actual_root != expected_root:
        raise HiveProofError("BCT Merkle root mismatch")

    return True


def verify_hive_cryptography(
    proof, previous_hashes, expected_hash160, bits
):
    """Verify Hive signature and Bee Hash.

    Does not establish complete Hive consensus validity.
    """
    parsed = parse_hive_proof(proof)

    verify_signature(
        parsed["signature"],
        previous_hashes,
        expected_hash160,
    )

    bee_digest = verify_bee_hash(
        parsed["nonce"],
        parsed["bct_txid"],
        previous_hashes,
        bits,
    )

    return {
        "bct_txid": parsed["bct_txid"],
        "bct_height": parsed["bct_height"],
        "bee_nonce": parsed["nonce"],
        "bee_hash": bee_digest,
    }
