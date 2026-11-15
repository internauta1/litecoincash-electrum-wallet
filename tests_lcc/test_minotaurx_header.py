import hashlib

HEIGHT = 2540194
EXPECTED_HASH = (
    "5d53a580ecea580791602a3cbfd90cab"
    "1fc1d3a97f68c608af85f3751f6055d9"
)

HEADER_HEX = (
    "00000100861674f2956624f1f923a94222e13600af29ee48bfd3d1c45c9a4cd7b601173"
    "1e0f0b58e93c90ab6d6d56690ec01278ed16861afbd1dd6f6932297ed4495d67590e05"
    "a61ffff0f1f000001ee"
)

raw = bytes.fromhex(HEADER_HEX)
assert len(raw) == 80

version = int.from_bytes(raw[0:4], "little")
timestamp = int.from_bytes(raw[68:72], "little")
bits = int.from_bytes(raw[72:76], "little")
nonce = int.from_bytes(raw[76:80], "little")

block_hash = hashlib.sha256(
    hashlib.sha256(raw).digest()
).digest()[::-1].hex()

assert block_hash == EXPECTED_HASH
print(f"OK: block {HEIGHT} - SHA256d block ID")

pow_type = (version >> 16) & 0xFF
assert pow_type == 1
assert version == 65536
assert nonce != 192
assert timestamp == 1633345680
print("OK: PoW type = MinotaurX")

assert bits == 0x1F0FFFFF
exponent = bits >> 24
mantissa = bits & 0x007FFFFF
target = mantissa << (8 * (exponent - 3))

assert int(block_hash, 16) > target
print("OK: SHA256d does not satisfy MinotaurX target")

print("LCC MINOTAURX HEADER TESTS OK")
