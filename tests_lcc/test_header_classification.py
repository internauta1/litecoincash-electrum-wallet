from electrum.lcc_header_rules import classify_header

# Observed LCC mainnet headers from ElectrumX.
# These are classification vectors, not PoW validation vectors.
VECTORS = [
    (1371111, 536870912, 1945815820, "scrypt"),
    (1371112, 536870912, 3079494665, "sha256d"),
    (1564415, 536871040, 904833353, "sha256d"),
    (1564416, 536870912, 2271873817, "sha256d"),
    (1766015, 536871424, 192, "hive"),
    (1766016, 536870912, 192, "hive"),
    (2540159, 536871040, 192, "hive"),
    (2540160, 0, 192, "hive"),
    (2540194, 65536, 3993042944, "minotaurx"),
    (2540195, 0, 192, "hive"),
]

for height, version, nonce, expected in VECTORS:
    result = classify_header(height, version, nonce)
    assert result == expected, (
        f"Block {height}: expected {expected}, got {result}"
    )
    print(f"OK: {height} -> {result}")

try:
    classify_header(2540194, 2 << 16, 3993042944)
except ValueError:
    print("OK: unknown PoW type rejected")
else:
    raise AssertionError("Unknown PoW type was accepted")

print("\nLCC HEADER CLASSIFICATION TEST OK")
