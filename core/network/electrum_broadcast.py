from core.network.electrum_client import ElectrumClient


class ElectrumBroadcast:

    def __init__(self, host="127.0.0.1", port=50001):

        self.client = ElectrumClient(
            host=host,
            port=port
        )

    # ---------------------------------
    # BROADCAST RAW TX
    # ---------------------------------
    def broadcast(self, rawtx):

        return self.client.call(
            "blockchain.transaction.broadcast",
            [rawtx]
        )
