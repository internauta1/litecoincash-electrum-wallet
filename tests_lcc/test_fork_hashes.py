import hashlib

FIXTURES = [
    (
        1371111,
        "e1fa07d03c7c9b2aa2682bc53bd2706ae3cf0dea2561d5738932c543502e9a75",
        "0000002053048b2d7f536fcbcda6fb48bb18c0b3b32a7fefe2aa59baec54c10aa8ad4dc5a6b808946f668f698775979b7dcebe15b6144e2b3e0598698b4ab69751496db904d5895a296c031a0ccbfa73",
        "scrypt",
    ),
    (
        1371112,
        "00000000de1e4e93317241177b5f1d72fc151c6e76815e9b0be4961dfd309d60",
        "00000020759a2e5043c5328973d56125ea0dcfe36a70d23bc52b68a22a9b7c3cd007fae157788a1db01e5e7854080c3ee9a35680320d44fae6216b3e9ef44cc5ca1772390be0895affff001d095c8db7",
        "sha256d",
    ),
]


def sha256d(raw):
    return hashlib.sha256(
        hashlib.sha256(raw).digest()
    ).digest()[::-1].hex()


def scrypt_hash(raw):
    return hashlib.scrypt(
        raw, salt=raw, n=1024, r=1, p=1, dklen=32
    )[::-1].hex()


def bits_target(raw):
    bits = int.from_bytes(raw[72:76], "little")
    exponent = bits >> 24
    mantissa = bits & 0x007fffff
    assert mantissa > 0
    assert exponent >= 3
    return mantissa << (8 * (exponent - 3))


for height, expected_hash, raw_hex, algorithm in FIXTURES:
    raw = bytes.fromhex(raw_hex)
    assert len(raw) == 80

    block_hash = sha256d(raw)
    assert block_hash == expected_hash

    pow_hash = (
        scrypt_hash(raw)
        if algorithm == "scrypt"
        else block_hash
    )

    assert int(pow_hash, 16) <= bits_target(raw)
    print(f"OK: block {height} | ID SHA256d | PoW {algorithm}")

print("LCC FORK HASH TESTS OK")
