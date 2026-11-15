import hashlib
from pathlib import Path

from electrum.blockchain import (
    Blockchain,
    deserialize_header,
    hash_header,
    pow_hash_header,
)
from electrum.lcc_header_rules import classify_header

START = 1370880
COUNT = 2016
FORK = 1371112

EXPECTED_SHA256 = (
    "2121bf2c292e184688c489bcb86f35a"
    "478bcabd6e17b853ca4173cafd10b1894"
)

REFERENCES = {
    1371111: (
        "e1fa07d03c7c9b2aa2682bc53bd2706"
        "ae3cf0dea2561d5738932c543502e9a75"
    ),
    1371112: (
        "00000000de1e4e93317241177b5f1d72"
        "fc151c6e76815e9b0be4961dfd309d60"
    ),
}

fixture_dir = Path(__file__).parent / "fixtures"

data = bytes.fromhex(
    (fixture_dir / "lcc_chunk_680.hex").read_text().strip()
)

assert len(data) == COUNT * 80
assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256

headers = {
    START + i: deserialize_header(
        data[i * 80:(i + 1) * 80],
        START + i,
    )
    for i in range(COUNT)
}

print("=== VERIFICAR REFERENCIAS ===")

for height, expected in REFERENCES.items():
    assert hash_header(headers[height]) == expected
    print("OK: bloco", height)

# Confirmar que os 100 blocos previamente testados
# coincidem exatamente com esta nova referencia.
reference_100 = bytes.fromhex(
    (fixture_dir / "dgw_1371112_100.hex")
    .read_text().strip()
)

offset = (FORK - START) * 80

assert data[offset:offset + len(reference_100)] == reference_100
print("OK: 100 cabecalhos DGW anteriores coincidem")

print("\n=== VERIFICAR LIGACOES ===")

for height in range(START + 1, START + COUNT):
    actual = headers[height]["prev_block_hash"]
    expected = hash_header(headers[height - 1])

    assert actual == expected, (
        f"Ligacao incorreta no bloco {height}"
    )

print("OK: 2015 ligacoes entre blocos")

print("\n=== VALIDAR SCRYPT ===")

scrypt_bits = headers[START]["bits"]
scrypt_target = Blockchain.bits_to_target(scrypt_bits)

for height in range(START, FORK):
    header = headers[height]

    assert classify_header(
        height,
        header["version"],
        header["nonce"],
    ) == "scrypt"

    assert header["bits"] == scrypt_bits, (
        f"Dificuldade Scrypt mudou no bloco {height}"
    )

    pow_value = int(pow_hash_header(header), 16)

    assert pow_value <= scrypt_target, (
        f"PoW Scrypt insuficiente: {height}"
    )

print("OK: 232 provas Scrypt e bits constantes")
print("NOTA: retarget Scrypt anterior nao validado aqui")

print("\n=== VALIDAR SHA256D COM DGW ===")

for height in range(FORK, START + COUNT):
    header = headers[height]

    assert classify_header(
        height,
        header["version"],
        header["nonce"],
    ) == "sha256d"

    expected_bits = Blockchain.dgw_next_bits_early(
        height, headers
    )

    assert header["bits"] == expected_bits, (
        f"DGW incorreto no bloco {height}: "
        f"real={header['bits']:08x}, "
        f"esperado={expected_bits:08x}"
    )

    target = Blockchain.bits_to_target(expected_bits)

    Blockchain.verify_header(
        header,
        hash_header(headers[height - 1]),
        target,
    )

print("OK: 1784 dificuldades DGW")
print("OK: 1784 verificacoes SHA256d")

print("\nLCC MIXED CHUNK TEST OK")
