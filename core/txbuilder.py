from core.coinselect import CoinSelector


class TransactionBuilder:

    def __init__(self, wallet):

        self.wallet = wallet

        self.selector = CoinSelector()

    #
    # BUILD
    #
    def build_transaction(
        self,
        utxos,
        to_address,
        amount,
        fee,
        change_address
    ):

        #
        # SELECT COINS
        #
        selected = self.selector.select(
            utxos,
            amount,
            fee
        )

        inputs = selected["inputs"]

        change = selected["change"]

        #
        # OUTPUTS
        #
        outputs = []

        #
        # MAIN OUTPUT
        #
        outputs.append({
            "address": to_address,
            "value": amount
        })

        #
        # CHANGE
        #
        if change > 0:

            outputs.append({
                "address": change_address,
                "value": change
            })

        return {
            "inputs": inputs,
            "outputs": outputs,
            "fee": fee
        }
