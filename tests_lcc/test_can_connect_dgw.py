from pathlib import Path

from electrum.blockchain import (
    Blockchain,
    MissingHeader,
    deserialize_header,
    hash_header,
    pow_hash_header,
)

START = 1370880
FORK = 1371112
COUNT = 2016

fixture = (
    Path(__file__).parent
    / "fixtures/lcc_chunk_680.hex"
)

data = bytes.fromhex(fixture.read_text().strip())
assert len(data) == COUNT * 80

headers = {
    START + i: deserialize_header(
        data[i * 80:(i + 1) * 80],
        START + i,
    )
    for i in range(COUNT)
}


class OfflineChain(Blockchain):
    def __init__(self, tip_height, missing=None):
        self.tip_height = tip_height
        self.missing = missing

    def height(self):
        return self.tip_height

    def get_hash(self, height):
        if height not in headers:
            raise MissingHeader()
        return hash_header(headers[height])

    def read_header(self, height):
        if height == self.missing:
            return None
        return headers.get(height)

    def get_target(self, index):
        # O caminho SHA256d deve usar DGW.
        # Nunca deve depender do retarget Litecoin.
        raise MissingHeader()


print("=== CAN_CONNECT SHA256D ===")

heights = [
    FORK,
    FORK + 1,
    1371136,
    1371150,
    1371200,
    START + COUNT - 1,
]

for height in heights:
    chain = OfflineChain(height - 1)
    result = chain.can_connect(headers[height])
    print(f"Bloco {height}: can_connect={result}")

    assert result, (
        f"Cabecalho LCC valido recusado: {height}"
    )

print("OK: cabecalhos SHA256d aceites")

print("\n=== TESTES NEGATIVOS ===")

height = 1371150
original = headers[height]
chain = OfflineChain(height - 1)

bad_bits = dict(original)
bad_bits["bits"] ^= 1
assert not chain.can_connect(bad_bits)
print("OK: dificuldade adulterada rejeitada")

bad_prev = dict(original)
bad_prev["prev_block_hash"] = "00" * 32
assert not chain.can_connect(bad_prev)
print("OK: hash anterior adulterado rejeitado")

target = Blockchain.bits_to_target(original["bits"])
bad_pow = None

for step in range(1, 33):
    candidate = dict(original)
    candidate["nonce"] = (
        original["nonce"] + step
    ) % (2**32)

    if int(pow_hash_header(candidate), 16) > target:
        bad_pow = candidate
        break

assert bad_pow is not None
assert not chain.can_connect(bad_pow)
print("OK: PoW insuficiente rejeitado")

missing_history = OfflineChain(
    height - 1,
    missing=height - 10,
)

assert not missing_history.can_connect(original)
print("OK: historico DGW incompleto rejeitado")

print("\nLCC CAN_CONNECT DGW TEST OK")
