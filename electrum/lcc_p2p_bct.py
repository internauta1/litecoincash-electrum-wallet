
"""Historical LCC BCT extraction with locally verified Merkle inclusion."""

import hashlib

from .blockchain import hash_header


class P2PBCTError(ValueError):
    pass


def _hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _take(data, pos, length):
    if (
        type(length) is not int
        or length < 0
        or pos < 0
        or pos + length > len(data)
    ):
        raise P2PBCTError("Truncated transaction or block")
    return pos + length


def _compact(data, pos):
    pos = _take(data, pos, 1)
    prefix = data[pos - 1]

    if prefix < 253:
        return prefix, pos

    size = {253: 2, 254: 4, 255: 8}[prefix]
    end = _take(data, pos, size)
    value = int.from_bytes(data[pos:end], "little")

    minimum = {253: 253, 254: 65536, 255: 4294967296}[prefix]

    if value < minimum:
        raise P2PBCTError("Non-canonical CompactSize")

    return value, end


def _transaction(data, pos):
    start = pos
    pos = _take(data, pos, 4)
    base_start = pos

    inputs, pos = _compact(data, pos)
    has_witness = False

    if inputs == 0:
        flag_end = _take(data, pos, 1)
        flag = data[pos]
        pos = flag_end

        if flag != 1:
            raise P2PBCTError("Unsupported transaction flag")

        has_witness = True
        base_start = pos
        inputs, pos = _compact(data, pos)

    if not 0 < inputs <= 100000:
        raise P2PBCTError("Invalid input count")

    for _ in range(inputs):
        pos = _take(data, pos, 36)
        script_len, pos = _compact(data, pos)
        pos = _take(data, pos, script_len)
        pos = _take(data, pos, 4)

    outputs, pos = _compact(data, pos)

    if not 0 < outputs <= 100000:
        raise P2PBCTError("Invalid output count")

    for _ in range(outputs):
        pos = _take(data, pos, 8)
        script_len, pos = _compact(data, pos)
        pos = _take(data, pos, script_len)

    base_end = pos

    if has_witness:
        for _ in range(inputs):
            item_count, pos = _compact(data, pos)

            if item_count > 100000:
                raise P2PBCTError("Too many witness items")

            for _ in range(item_count):
                item_len, pos = _compact(data, pos)
                pos = _take(data, pos, item_len)

    end = _take(data, pos, 4)

    if has_witness:
        # TXID excludes marker, flag and witness stacks.
        legacy = (
            data[start:start + 4]
            + data[base_start:base_end]
            + data[pos:end]
        )
    else:
        legacy = data[start:end]

    return end, _hash256(legacy), data[start:end]


def extract_bct_from_block(
    *,
    raw_block,
    candidate_header,
    expected_txid,
):
    if (
        not isinstance(raw_block, bytes)
        or not 81 <= len(raw_block) <= 8_000_000
        or not isinstance(candidate_header, dict)
        or not isinstance(expected_txid, str)
        or len(expected_txid) != 64
    ):
        raise P2PBCTError("Invalid block or BCT request")

    # Historical pre-MinotaurX block identity.
    block_hash = _hash256(raw_block[:80])[::-1].hex()

    if block_hash != hash_header(candidate_header):
        raise P2PBCTError("Historical block hash mismatch")

    count, pos = _compact(raw_block, 80)

    if not 0 < count <= 100000:
        raise P2PBCTError("Invalid block transaction count")

    hashes = []
    matches = []

    expected = expected_txid.lower()

    for index in range(count):
        pos, tx_hash, raw_tx = _transaction(raw_block, pos)
        hashes.append(tx_hash)

        if tx_hash[::-1].hex() == expected:
            matches.append((index, raw_tx))

    if pos != len(raw_block):
        raise P2PBCTError("Trailing bytes after transactions")

    if len(matches) != 1:
        raise P2PBCTError(
            "Expected BCT not uniquely present in historical block"
        )

    position, raw_transaction = matches[0]

    # Build Merkle proof and independently recompute the root.
    level = hashes
    index = position
    branch = []

    while len(level) > 1:
        sibling = index ^ 1

        if sibling >= len(level):
            sibling = index

        branch.append(level[sibling][::-1].hex())

        next_level = []

        for j in range(0, len(level), 2):
            left = level[j]
            right = (
                level[j + 1]
                if j + 1 < len(level)
                else left
            )

            # Reject the classic duplicated-transaction mutation.
            if j + 1 < len(level) and left == right:
                raise P2PBCTError("Mutated Merkle tree")

            next_level.append(_hash256(left + right))

        level = next_level
        index //= 2

    root = level[0][::-1].hex()

    if root != candidate_header.get("merkle_root", "").lower():
        raise P2PBCTError("Historical Merkle root mismatch")

    return {
        "raw_transaction": raw_transaction,
        "merkle_branch": branch,
        "position": position,
        "transaction_count": count,
        "merkle_root_verified": True,
    }
