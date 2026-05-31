class CoinSelector:

    def select(self, utxos, amount, fee):

        selected = []

        total = 0

        needed = amount + fee

        #
        # menor -> maior
        #
        utxos = sorted(
            utxos,
            key=lambda x: x["value"]
        )

        for utxo in utxos:

            selected.append(utxo)

            total += utxo["value"]

            if total >= needed:
                break

        if total < needed:
            raise Exception(
                "Insufficient funds"
            )

        change = total - needed

        return {
            "inputs": selected,
            "change": change,
            "total": total
        }
