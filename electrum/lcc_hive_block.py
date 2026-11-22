"""Litecoin Cash Hive full-block structural verification.

Checks block serialization, transaction Merkle commitment,
coinbase position and prohibition of BCTs in Hive blocks.

Not a complete consensus validator.
"""

import hashlib

from .blockchain import hash_header
from .lcc_hive import parse_hive_proof
from .lcc_mainnet import bee_creation_script


class HiveBlockError(Exception):
    pass


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, size):
        if (
            type(size) is not int
            or size < 0
            or self.pos + size > len(self.data)
        ):
            raise HiveBlockError("Truncated serialized block")

        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def compact(self):
        prefix = self.read(1)[0]

        if prefix < 253:
            return prefix

        size = {253: 2, 254: 4, 255: 8}[prefix]
        value = int.from_bytes(self.read(size), "little")

        if (
            prefix == 253 and value < 253
            or prefix == 254 and value <= 0xffff
            or prefix == 255 and value <= 0xffffffff
        ):
            raise HiveBlockError("Noncanonical CompactSize")

        return value


def parse_transaction(reader):
    start = reader.pos
    version = reader.read(4)

    segwit = False

    if (
        len(reader.data) - reader.pos >= 2
        and reader.data[reader.pos] == 0
        and reader.data[reader.pos + 1] != 0
    ):
        flag = reader.read(2)

        if flag != b"\x00\x01":
            raise HiveBlockError("Unsupported witness flag")

        segwit = True

    stripped_start = reader.pos
    input_count = reader.compact()

    if not 1 <= input_count <= 100_000:
        raise HiveBlockError("Invalid input count")

    is_coinbase = False

    for index in range(input_count):
        outpoint = reader.read(36)
        reader.read(reader.compact())
        reader.read(4)

        if index == 0 and input_count == 1:
            is_coinbase = (
                outpoint == bytes(32) + b"\xff" * 4
            )

    output_count = reader.compact()

    if not 1 <= output_count <= 100_000:
        raise HiveBlockError("Invalid output count")

    scripts = []

    for _ in range(output_count):
        reader.read(8)
        scripts.append(reader.read(reader.compact()))

    witness_start = reader.pos

    if segwit:
        has_witness = False

        for _ in range(input_count):
            stack_count = reader.compact()

            if stack_count > 100_000:
                raise HiveBlockError("Excessive witness items")

            if stack_count:
                has_witness = True

            for _ in range(stack_count):
                reader.read(reader.compact())

        if not has_witness:
            raise HiveBlockError("Superfluous witness marker")

    locktime = reader.read(4)

    if segwit:
        stripped = (
            version
            + reader.data[stripped_start:witness_start]
            + locktime
        )
    else:
        stripped = reader.data[start:reader.pos]

    return {
        "txid_raw": sha256d(stripped),
        "coinbase": is_coinbase,
        "scripts": scripts,
        "serialized": reader.data[start:reader.pos],
    }


def calculate_merkle_root(txids):
    level = list(txids)

    if not level:
        raise HiveBlockError("Empty block")

    while len(level) > 1:
        for i in range(0, len(level) - 1, 2):
            if level[i] == level[i + 1]:
                raise HiveBlockError("Mutated Merkle tree")

        if len(level) % 2:
            level.append(level[-1])

        level = [
            sha256d(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]

    return level[0]


def verify_hive_full_block_structure(
    *,
    raw_block,
    candidate_header,
):
    """Verify Hive block structural commitments.

    The raw block must be obtained independently.
    This function does not validate all transaction scripts,
    witness commitments, fees or full consensus rules.
    """
    if (
        not isinstance(raw_block, bytes)
        or not 81 <= len(raw_block) <= 8_000_000
    ):
        raise HiveBlockError("Invalid raw block")

    if not isinstance(candidate_header, dict):
        raise HiveBlockError("Invalid candidate header")

    raw_header = raw_block[:80]
    block_hash = sha256d(raw_header)[::-1].hex()

    if block_hash != hash_header(candidate_header):
        raise HiveBlockError("Candidate header hash mismatch")

    nonce = int.from_bytes(raw_header[76:80], "little")

    if nonce != 192:
        raise HiveBlockError("Not a Hive block")

    reader = Reader(raw_block)
    reader.read(80)

    count = reader.compact()

    if not 1 <= count <= 100_000:
        raise HiveBlockError("Invalid transaction count")

    creation_prefix = bee_creation_script()
    txids = []
    coinbase = None

    for index in range(count):
        tx = parse_transaction(reader)
        txids.append(tx["txid_raw"])

        if index == 0:
            if not tx["coinbase"]:
                raise HiveBlockError("Missing coinbase")

            if len(tx["scripts"]) not in (2, 3):
                raise HiveBlockError("Invalid Hive coinbase outputs")

            if len(tx["scripts"][0]) < 144:
                raise HiveBlockError("Missing Hive proof")

            parse_hive_proof(tx["scripts"][0])
            coinbase = tx

        else:
            if tx["coinbase"]:
                raise HiveBlockError("Additional coinbase")

            # Core CTransaction::IsBCT checks vout[0].
            script = tx["scripts"][0]

            if (
                len(script) == 52
                and script[:25] == creation_prefix
                and script[25:27] == bytes.fromhex("6abe")
            ):
                raise HiveBlockError(
                    "Hive block contains Bee Creation Transaction"
                )

    if reader.pos != len(raw_block):
        raise HiveBlockError("Trailing block data")

    if calculate_merkle_root(txids) != raw_header[36:68]:
        raise HiveBlockError("Block Merkle root mismatch")

    return {
        "candidate_header_hash": block_hash,
        "coinbase_txid": coinbase["txid_raw"][::-1].hex(),
        "coinbase_raw": coinbase["serialized"],
        "transaction_count": count,
        "block_merkle_verified": True,
        "no_bct_inside_hive_verified": True,
        "consensus_validated": False,
    }
