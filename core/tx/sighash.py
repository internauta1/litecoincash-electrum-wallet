import hashlib


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(
        hashlib.sha256(data).digest()
    ).digest()


#
# BIP143-like sighash (SegWit style)
#
def sighash_p2wpkh(
    tx,
    input_index,
    script_code,
    value,
    sighash_type=1
):

    version = tx["version"]
    locktime = tx["locktime"]

    hash_prevouts = double_sha256(
        b"".join([
            bytes.fromhex(i["tx_hash"])[::-1] +
            i["tx_pos"].to_bytes(4, "little")
            for i in tx["inputs"]
        ])
    )

    hash_sequence = double_sha256(
        b"".join([
            i.get("sequence", 0xffffffff).to_bytes(4, "little")
            for i in tx["inputs"]
        ])
    )

    hash_outputs = double_sha256(
        b"".join([
            int(o["value"]).to_bytes(8, "little") +
            o["script"]
            for o in tx["outputs"]
        ])
    )

    inp = tx["inputs"][input_index]

    preimage = (
        version.to_bytes(4, "little") +
        hash_prevouts +
        hash_sequence +
        bytes.fromhex(inp["tx_hash"])[::-1] +
        inp["tx_pos"].to_bytes(4, "little") +
        script_code +
        value.to_bytes(8, "little") +
        inp.get("sequence", 0xffffffff).to_bytes(4, "little") +
        hash_outputs +
        locktime.to_bytes(4, "little") +
        sighash_type.to_bytes(4, "little")
    )

    return double_sha256(preimage)
