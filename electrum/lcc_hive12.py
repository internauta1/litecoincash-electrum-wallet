"""Litecoin Cash Hive 1.2 classical Minotaur Bee Hash.

This module checks the Bee Hash against a supplied target.
It does not independently authenticate the previous-block hashes,
BCT, difficulty, or BIP9 activation state.
"""

from .lcc_minotaurx import minotaur_hash


class Hive12Error(Exception):
    pass


def compact_target(bits: int) -> int:
    """Decode Bitcoin-style compact difficulty with overflow checks."""
    if type(bits) is not int or not 0 <= bits <= 0xffffffff:
        raise Hive12Error("Invalid compact difficulty")

    size = bits >> 24
    word = bits & 0x007fffff
    negative = bool(bits & 0x00800000)

    overflow = (
        word != 0
        and (
            size > 34
            or (word > 0xff and size > 33)
            or (word > 0xffff and size > 32)
        )
    )

    if negative or overflow or word == 0:
        raise Hive12Error("Invalid difficulty target")

    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))

    if not 0 < target < (1 << 256):
        raise Hive12Error("Difficulty target out of range")

    return target


def hive12_bee_hash(
    deterministic_string: str,
    bct_txid: str,
    bee_nonce: int,
) -> bytes:
    """Calculate classical Minotaur Bee Hash.

    Input representation matches Core's string concatenation:
    deterministic_string + bct_txid + std::to_string(beeNonce).

    Returns the 32-byte result in native Core byte order.
    """
    if not isinstance(deterministic_string, str):
        raise Hive12Error("Invalid deterministic string")

    if not deterministic_string or not deterministic_string.isascii():
        raise Hive12Error("Invalid deterministic string encoding")

    if not isinstance(bct_txid, str) or len(bct_txid) != 64:
        raise Hive12Error("Invalid BCT TXID")

    if any(c not in "0123456789abcdef" for c in bct_txid):
        raise Hive12Error("BCT TXID must be lowercase hexadecimal")

    if type(bee_nonce) is not int or not 0 <= bee_nonce <= 0xffffffff:
        raise Hive12Error("Invalid Bee nonce")

    message = (
        deterministic_string
        + bct_txid
        + str(bee_nonce)
    ).encode("ascii")

    return minotaur_hash(message)


def verify_hive12_bee_hash(
    *,
    deterministic_string: str,
    bct_txid: str,
    bee_nonce: int,
    expected_bits: int,
) -> bool:
    """Check Hive 1.2 Bee Hash.

    Core rejects a Bee Hash greater than or EQUAL to its target.
    The caller must independently verify expected_bits.
    """
    target = compact_target(expected_bits)

    digest = hive12_bee_hash(
        deterministic_string,
        bct_txid,
        bee_nonce,
    )

    if not isinstance(digest, bytes) or len(digest) != 32:
        raise Hive12Error("Invalid Minotaur hash result")

    value = int.from_bytes(digest, byteorder="little")

    if value >= target:
        raise Hive12Error("Bee Hash does not satisfy difficulty")

    return True
