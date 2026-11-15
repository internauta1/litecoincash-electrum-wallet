import asyncio

from electrum.interface import (
    Interface,
    TxBroadcastHashMismatch,
)

TXID = "ab" * 32
RAW_TX = "01000000"


class FakeTransaction:
    def txid(self):
        return TXID

    def serialize(self):
        return RAW_TX

    def outputs(self):
        return []


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def send_request(self, method, params, timeout=None):
        self.calls.append((method, params, timeout))
        return self.response


class FakeLogger:
    def info(self, message):
        pass


class FakeInterface:
    def __init__(self, response):
        self.session = FakeSession(response)
        self._rawtx_cache = {}
        self.logger = FakeLogger()


async def run_tests():
    tx = FakeTransaction()

    print("=== TRANSMISSAO ELECTRUMX ===")
    interface = FakeInterface(TXID)

    await Interface.broadcast_transaction(
        interface, tx, timeout=7
    )

    assert interface.session.calls == [
        (
            "blockchain.transaction.broadcast",
            [RAW_TX],
            7,
        )
    ]

    assert interface._rawtx_cache[TXID] == bytes.fromhex(
        RAW_TX
    )

    print("OK: utiliza blockchain.transaction.broadcast")
    print("OK: TXID correto aceite")
    print("OK: transacao guardada na cache")

    print("\n=== TESTES NEGATIVOS ===")

    for name, response in [
        ("TXID diferente", "cd" * 32),
        ("resposta invalida", None),
    ]:
        interface = FakeInterface(response)

        try:
            await Interface.broadcast_transaction(
                interface, tx, timeout=7
            )
        except TxBroadcastHashMismatch:
            print("OK: rejeitada", name)
        else:
            raise AssertionError(
                f"ERRO: resposta aceite: {name}"
            )

        assert not interface._rawtx_cache

    print("\nLCC BROADCAST OFFLINE TEST OK")


if __name__ == "__main__":
    asyncio.run(run_tests())
