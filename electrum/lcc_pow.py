"""Litecoin Cash SHA256d / MinotaurX PoW verification.

This module verifies the proof-of-work hash against a supplied
target. It does NOT establish that the target is the correct
consensus difficulty, nor does it validate Hive proofs.
"""

import hashlib
from .lcc_minotaurx import minotaurx_hash
from .lcc_chainwork import bits_to_target


class LCCPoWError(Exception):
    pass


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def block_hash(header_bytes):
    """Block identifier hash, in displayed hexadecimal order."""
    if len(header_bytes) != 80:
        raise LCCPoWError("Expected 80-byte header")

    return sha256d(header_bytes)[::-1].hex()


def pow_hash(header_bytes, algorithm):
    """Return consensus PoW hash bytes in internal byte order.

    Supported algorithms: sha256d, minotaurx.
    Scrypt and Hive require separate verification paths.
    """
    if not isinstance(header_bytes, bytes) or len(header_bytes) != 80:
        raise LCCPoWError("Expected exactly 80 header bytes")

    if algorithm == "sha256d":
        return sha256d(header_bytes)

    if algorithm == "minotaurx":
        return minotaurx_hash(header_bytes)

    raise LCCPoWError(
        f"Unsupported PoW algorithm: {algorithm}"
    )


def verify_pow(header_bytes, algorithm, expected_bits):
    """Check selected PoW against independently calculated bits.

    The caller must first validate the applicable consensus
    deployment, block classification and expected difficulty.
    """
    if not isinstance(header_bytes, bytes) or len(header_bytes) != 80:
        raise LCCPoWError("Expected exactly 80 header bytes")

    header_bits = int.from_bytes(
        header_bytes[72:76], "little"
    )

    if header_bits != expected_bits:
        raise LCCPoWError(
            f"Incorrect difficulty bits: "
            f"{header_bits:08x} != {expected_bits:08x}"
        )

    target = bits_to_target(expected_bits)
    result = pow_hash(header_bytes, algorithm)

    if int.from_bytes(result, "little") > target:
        raise LCCPoWError(
            f"Invalid {algorithm} proof of work"
        )

    return True
