from electrum.blockchain import (
    deserialize_header,
    hash_header,
    pow_hash_header,
)

RAW = bytes.fromhex(
    "00000020759a2e5043c5328973d56125ea0dcfe3"
    "6a70d23bc52b68a22a9b7c3cd007fae157788a1"
    "db01e5e7854080c3ee9a35680320d44fae6216b3"
    "e9ef44cc5ca1772390be0895affff001d095c8db7"
)

EXPECTED = (
    "00000000de1e4e93317241177b5f1d72"
    "fc151c6e76815e9b0be4961dfd309d60"
)

assert len(RAW) == 80

header = deserialize_header(RAW, 1371112)

assert hash_header(header) == EXPECTED
assert pow_hash_header(header) == EXPECTED

print("OK: bloco 1371112 SHA256d")

for name, height, version, nonce in [
    ("Hive", 1766016, 536870912, 192),
    ("MinotaurX", 2540194, 65536, 3993042944),
]:
    modified = dict(
        header,
        block_height=height,
        version=version,
        nonce=nonce,
    )

    try:
        pow_hash_header(modified)
    except NotImplementedError:
        print(f"OK: {name} ainda nao e aceite")
    else:
        raise AssertionError(f"{name} aceite sem verificacao")

print("LCC POW DISPATCH TEST OK")
