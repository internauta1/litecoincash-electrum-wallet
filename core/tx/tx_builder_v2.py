class TXBuilderV2:

    def __init__(self, wallet, fee_per_byte=2):

        self.wallet = wallet
        self.fee_per_byte = fee_per_byte

    # -------------------------
    # SIZE ESTIMATION (simplificado)
    # -------------------------
    def estimate_size(self, inputs, outputs):

        # segwit tx base aprox
        return 10 + inputs * 68 + outputs * 31

    # -------------------------
    # SELECT UTXOS (FIFO simples)
    # -------------------------
    def select_utxos(self, utxos, amount_needed):

        selected = []
        total = 0

        for u in utxos:

            selected.append(u)
            total += u["value"]

            if total >= amount_needed:
                break

        if total < amount_needed:
            raise Exception("Insufficient funds")

        return selected, total

    # -------------------------
    # BUILD TX
    # -------------------------
    def build(self, to_address, amount, utxos, change_index=0):

        selected, total = self.select_utxos(
            utxos,
            amount
        )

        inputs = []

        for u in selected:

            inputs.append({
                "tx_hash": u["tx_hash"],
                "tx_pos": u["tx_pos"],
                "sequence": 0xffffffff,
                "key_index": u.get("key_index", 0)
            })

        outputs = []

        # -------------------------
        # OUTPUT DESTINO
        # -------------------------
        outputs.append({
            "address": to_address,
            "value": amount
        })

        # -------------------------
        # ESTIMAR FEE
        # -------------------------
        size = self.estimate_size(
            len(inputs),
            2  # assume change
        )

        fee = size * self.fee_per_byte

        change = total - amount - fee

        if change < 0:
            raise Exception("Fee too high / insufficient funds")

        # -------------------------
        # CHANGE OUTPUT
        # -------------------------
        if change > 546:  # dust filter

            change_address = self.wallet.get_lcc1_address(
                change_index
            )

            outputs.append({
                "address": change_address,
                "value": change
            })

        tx = {
            "version": 1,
            "inputs": inputs,
            "outputs": outputs,
            "locktime": 0
        }

        return {
            "tx": tx,
            "utxos": selected,
            "fee": fee,
            "change": change
        }
