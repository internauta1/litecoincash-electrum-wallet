from pathlib import Path

from electrum.blockchain import (
    Blockchain,
    InvalidHeader,
    deserialize_header,
    hash_header,
    pow_hash_header,
)

START = 1371112
COUNT = 100

fixture = (
    Path(__file__).parent
    / "fixtures/dgw_1371112_100.hex"
)

data = bytes.fromhex(fixture.read_text().strip())
assert len(data) == COUNT * 80

headers = {
    START + i: deserialize_header(
        data[i*80:(i+1)*80], START+i
    )
    for i in range(COUNT)
}

print("=== VALIDACAO ORIGINAL ELECTRUM ===")

for height in range(START, START + COUNT):
    header = headers[height]

    prev_hash = (
        "e1fa07d03c7c9b2aa2682bc53bd2706"
        "ae3cf0dea2561d5738932c543502e9a75"
        if height == START
        else hash_header(headers[height-1])
    )

    bits = Blockchain.dgw_next_bits_early(
        height, headers
    )
    target = Blockchain.bits_to_target(bits)

    Blockchain.verify_header(
        header, prev_hash, target
    )

print("OK: 100 cabecalhos aceites pela verificacao Electrum")

print("\n=== TESTES NEGATIVOS ===")

original = headers[1371150]
expected_prev = original["prev_block_hash"]

bits = Blockchain.dgw_next_bits_early(
    1371150, headers
)
target = Blockchain.bits_to_target(bits)

def must_reject(name, header):
    try:
        Blockchain.verify_header(
            header, expected_prev, target
        )
    except InvalidHeader:
        print("OK: rejeitado", name)
    else:
        raise AssertionError(
            f"ERRO: {name} foi aceite"
        )

bad_bits = dict(original)
bad_bits["bits"] ^= 1
must_reject("dificuldade adulterada", bad_bits)

bad_prev = dict(original)
bad_prev["prev_block_hash"] = "00" * 32
must_reject("hash anterior adulterado", bad_prev)

bad_pow = None
for offset in range(1, 33):
    candidate = dict(original)
    candidate["nonce"] = (
        original["nonce"] + offset
    ) % (2**32)

    if int(pow_hash_header(candidate), 16) > target:
        bad_pow = candidate
        break

assert bad_pow is not None
must_reject("prova de trabalho insuficiente", bad_pow)

print("\nLCC DGW HEADER VALIDATION OK")
