import hashlib

from core.network.electrum_client import ElectrumClient
from core.bech32 import decode_segwit_address


class ElectrumUTXO:

    def __init__(self, host="127.0.0.1", port=50001):

        self.client = ElectrumClient(
            host=host,
            port=port
        )

    # -----------------------------------
    # HASH160
    # -----------------------------------
    def address_to_h160(self, address):

        if address.startswith("lcc1"):
            return decode_segwit_address(address)

        raise Exception(
            "Only lcc1 supported currently"
        )

    # -----------------------------------
    # SCRIPT HASH
    # -----------------------------------
    def address_to_scripthash(self, address):

        h160 = self.address_to_h160(address)

        script = b"\x00\x14" + h160

        digest = hashlib.sha256(script).digest()

        return digest[::-1].hex()

    # -----------------------------------
    # GET UTXOS
    # -----------------------------------
    def get_utxos(self, address):

        sh = self.address_to_scripthash(address)

        result = self.client.call(
            "blockchain.scripthash.listunspent",
            [sh]
        )

        return result
