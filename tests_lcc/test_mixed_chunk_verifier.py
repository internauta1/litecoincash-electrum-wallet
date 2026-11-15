import hashlib
from pathlib import Path

from electrum.blockchain import (
    Blockchain,
    InvalidHeader,
    MissingHeader,
    deserialize_header,
    pow_hash_header,
)

START = 1370880
FORK = 1371112
COUNT = 2016
INDEX = START // 2016

EXPECTED_SHA256 = (
    "2121bf2c292e184688c489bcb86f35a"
    "478bcabd6e17b853ca4173cafd10b1894"
)

fixture = (
    Path(__file__).parent
    / "fixtures/lcc_chunk_680.hex"
)

data = bytes.fromhex(fixture.read_text().strip())

assert len(data) == COUNT * 80
assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256

first_header = deserialize_header(data[:80], START)


class OfflineChain(Blockchain):
    def __init__(self):
        # No real blockchain database is used.
        pass

    def get_hash(self, height):
        if height == START - 1:
            return first_header["prev_block_hash"]
        raise MissingHeader()

    def get_target(self, index):
        assert index == INDEX - 1
        return self.bits_to_target(first_header["bits"])

    def read_header(self, height):
        return None


def check_rejected(name, payload):
    try:
        OfflineChain().verify_chunk(INDEX, payload)
    except InvalidHeader:
        print("OK: rejeitado", name)
    else:
        raise AssertionError(
            f"ERRO: lote adulterado aceite: {name}"
        )


print("=== VERIFY_CHUNK REAL ===")

OfflineChain().verify_chunk(INDEX, data)
print("OK: lote 680 completo aceite")
print("OK: 232 blocos Scrypt")
print("OK: 1784 blocos SHA256d com DGW")

print("\n=== TESTES NEGATIVOS ===")

height = 1371150
offset = (height - START) * 80

bad_bits = bytearray(data)
bad_bits[offset + 72] ^= 1
check_rejected("dificuldade adulterada", bytes(bad_bits))

bad_prev = bytearray(data)
bad_prev[offset + 4] ^= 1
check_rejected("hash anterior adulterado", bytes(bad_prev))

original = deserialize_header(
    data[offset:offset + 80], height
)
target = Blockchain.bits_to_target(original["bits"])

bad_nonce = None

for step in range(1, 33):
    candidate = dict(original)
    candidate["nonce"] = (
        original["nonce"] + step
    ) % (2**32)

    if int(pow_hash_header(candidate), 16) > target:
        bad_nonce = candidate["nonce"]
        break

assert bad_nonce is not None

bad_pow = bytearray(data)
bad_pow[offset + 76:offset + 80] = (
    bad_nonce.to_bytes(4, "little")
)

check_rejected("prova de trabalho insuficiente", bytes(bad_pow))

check_rejected("lote incompleto", data[:-1])

print("\nLCC MIXED CHUNK VERIFIER OK")
