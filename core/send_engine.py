from core.network import LCCNetwork
from core.txbuilder import TransactionBuilder


class SendEngine:

    def __init__(self, wallet, signer):

        self.wallet = wallet

        self.signer = signer

        self.builder = TransactionBuilder(wallet)

        self.net = LCCNetwork(
            "electrumx.litecoincash.com.br:50002"
        )

    #
    # GET ALL WALLET UTXOS
    #
    def collect_utxos(self, max_addresses=20):

        all_utxos = []

        for i in range(max_addresses):

            addr = self.wallet.get_address(i)

            utxos = self.net.get_utxos(addr)

            #
            # attach address/index
            #
            for u in utxos:

                u["address"] = addr
                u["index"] = i

            all_utxos.extend(utxos)

        return all_utxos

    #
    # SEND
    #
    def send(
        self,
        to_address,
        amount,
        fee=1000
    ):

        #
        # GET UTXOS
        #
        utxos = self.collect_utxos()

        if not utxos:
            raise Exception("No funds")

        #
        # CHANGE ADDRESS
        #
        change_address = self.wallet.get_address(1)

        #
        # BUILD TX
        #
        tx = self.builder.build_transaction(
            utxos=utxos,
            to_address=to_address,
            amount=amount,
            fee=fee,
            change_address=change_address
        )

        print("\n===== TX BUILT =====")
        print(tx)

        #
        # SIGN
        #
        signed = self.signer.sign(tx)

        print("\n===== TX SIGNED =====")
        print(signed)

        #
        # RAW
        #
        raw = self.signer.serialize(signed)

        raw_hex = raw.hex()

        print("\n===== RAW HEX =====")
        print(raw_hex)

        #
        # BROADCAST
        #
        txid = self.net.broadcast(raw_hex)

        print("\n===== TXID =====")
        print(txid)

        return txid
