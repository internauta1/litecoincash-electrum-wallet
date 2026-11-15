import hashlib
from pathlib import Path

from electrum.blockchain import (
    Blockchain,
    deserialize_header,
    hash_header,
    pow_hash_header,
)

START = 1371112
COUNT = 100
LAST_SCRYPT = 1371111
WINDOW = 24
SPACING = 150

POW_LIMIT = int("00000000" + "ff" * 28, 16)

FIXTURE_SHA256 = (
    "556bb297b74ed308a6a075cec2e6fdbc"
    "4b98b5cd5a79fa7db36d606ed66a1b93"
)

PREVIOUS_HASH = (
    "e1fa07d03c7c9b2aa2682bc53bd2706a"
    "e3cf0dea2561d5738932c543502e9a75"
)

CORE_HASHES = {
    1371112: "00000000de1e4e93317241177b5f1d72fc151c6e76815e9b0be4961dfd309d60",
    1371135: "000000000001c79d0de9292626b6a4b9acd15b27d7d8675d656ea55132343c2f",
    1371136: "00000000000352da8082c332901d2fa4bec08756c3f15f029bbe2684fc9ecb4f",
    1371150: "00000000000128485e2f530add429da575d33872545fdc1037305576710e3679",
    1371200: "000000000000d64fbc0e0aadb3b33cd07d582b2129553d8981856522b76f453c",
}

def expected_bits(height, headers):
    if height - 1 - LAST_SCRYPT < WINDOW:
        return Blockchain.target_to_bits(POW_LIMIT)

    average = 0

    for n in range(1, WINDOW + 1):
        previous = headers[height - n]
        target = Blockchain.bits_to_target(previous["bits"])

        if n == 1:
            average = target
        else:
            average = (average * n + target) // (n + 1)

    first = headers[height - WINDOW]
    last = headers[height - 1]

    actual = last["timestamp"] - first["timestamp"]
    expected = WINDOW * SPACING

    actual = max(expected // 3, actual)
    actual = min(expected * 3, actual)

    target = min(average * actual // expected, POW_LIMIT)

    return Blockchain.target_to_bits(target)


def test_dgw_reference():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "dgw_1371112_100.hex"
    )

    data = bytes.fromhex(fixture.read_text().strip())

    assert len(data) == COUNT * 80
    assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256

    headers = {
        START + i: deserialize_header(
            data[i * 80:(i + 1) * 80],
            START + i,
        )
        for i in range(COUNT)
    }

    for height, expected_hash in CORE_HASHES.items():
        assert hash_header(headers[height]) == expected_hash
    print("OK: fixture e cinco hashes do Core")

    previous_hash = PREVIOUS_HASH

    for height in range(START, START + COUNT):
        header = headers[height]

        assert header["prev_block_hash"] == previous_hash, (
            f"Ligacao de blocos invalida: {height}"
        )
        previous_hash = hash_header(header)

        calculated = expected_bits(height, headers)
        actual = header["bits"]

        assert calculated == actual, (
            f"DGW {height}: "
            f"calculado={calculated:08x}, "
            f"real={actual:08x}"
        )

        pow_hash = pow_hash_header(header)
        target = Blockchain.bits_to_target(actual)

        assert int(pow_hash, 16) <= target, (
            f"PoW insuficiente no bloco {height}"
        )

    print(f"OK: {COUNT} dificuldades DGW")
    print(f"OK: {COUNT} ligacoes entre blocos")
    print(f"OK: {COUNT} hashes PoW SHA256d")
    print("LCC DGW OFFLINE TEST OK")


if __name__ == "__main__":
    test_dgw_reference()
