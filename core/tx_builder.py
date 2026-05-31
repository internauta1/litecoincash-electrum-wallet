from core.sighash import Sighash
from core.signer import Signer


class TXBuilder:

    def __init__(self, network, wallet):
        self.net = network
        self.wallet = wallet

    # -------------------------
    # BUILD TX
    # -------------------------
    def build(self, utxos, to_address, amount, fee=1000):

        selected = []
        total = 0

        # -------------------------
        # SELECT UTXOS
        # -------------------------
        for u in utxos:

            tx_data = self.net.get_tx(u["tx_hash"])
            vout_index = u["tx_pos"]

            script_hex = (
                tx_data["result"]["vout"][vout_index]
                ["scriptPubKey"]["hex"]
            )

            u["scriptPubKey"] = bytes.fromhex(script_hex)

            selected.append(u)
            total += u["value"]

            if total >= amount + fee:
                break

        if total < amount + fee:
            raise Exception("Insufficient funds")

        change = total - amount - fee

        # -------------------------
        # OUTPUTS
        # -------------------------
        outputs = [
            {
                "address": to_address,
                "value": amount
            }
        ]

        if change > 0:
            outputs.append({
                "address": self.wallet.get_address(0),
                "value": change
            })

        # -------------------------
        # INPUTS
        # -------------------------
        inputs = []

        for u in selected:
            inputs.append({
                "txid": u["tx_hash"],
                "vout": u["tx_pos"],
                "value": u["value"],
                "scriptPubKey": u["scriptPubKey"]
            })

        # -------------------------
        # CHANGE H160
        # -------------------------
        change_h160 = self.wallet.address_to_pubkeyhash(
            self.wallet.get_address(0)
        ).hex()

        # -------------------------
        # FINAL TX
        # -------------------------
        return {
            "inputs": inputs,
            "outputs": outputs,
            "fee": fee,
            "version": 1,
            "locktime": 0,
            "change_h160": change_h160
        }

    # -------------------------
    # SIGN TX
    # -------------------------
    def sign(self, tx, private_key_hex):

        signer = Signer(private_key_hex)
        sighash_engine = Sighash()

        signed_inputs = []

        for i, inp in enumerate(tx["inputs"]):

            sighash = sighash_engine.create_sighash(
                tx,
                i,
                inp["scriptPubKey"],
                inp["value"]
            )

            sig = signer.sign(sighash)
            pub = signer.get_public_key()

            signed_inputs.append({
                "signature": sig.hex(),
                "pubkey": pub.hex()
            })

        tx["signed_inputs"] = signed_inputs

        return tx
