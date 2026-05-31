import time


class BroadcastEngine:

    def __init__(self, network):

        self.net = network

    # -------------------------
    # BROADCAST TX
    # -------------------------
    def broadcast(self, raw_hex):

        print("\n=== BROADCASTING TX ===\n")

        try:

            txid = self.net.broadcast(raw_hex)

            print("TX SENT OK")
            print("TXID:", txid)

            return txid

        except Exception as e:

            print("BROADCAST FAILED")
            print(str(e))

            raise

    # -------------------------
    # MEMPOOL CHECK
    # -------------------------
    def wait_confirmation(
        self,
        txid,
        timeout=300,
        interval=10
    ):

        print("\n=== TRACKING TX ===\n")

        start = time.time()

        while True:

            try:

                tx = self.net.rpc(
                    "blockchain.transaction.get",
                    [txid, True]
                )

                confirmations = tx.get(
                    "confirmations",
                    0
                )

                print(
                    f"Confirmations: {confirmations}"
                )

                if confirmations > 0:
                    return tx

            except Exception as e:

                print("Track error:", e)

            if time.time() - start > timeout:
                raise Exception(
                    "Confirmation timeout"
                )

            time.sleep(interval)

    # -------------------------
    # SIMPLE FEE ESTIMATOR
    # -------------------------
    def estimate_fee(
        self,
        inputs,
        outputs,
        sat_per_byte=2
    ):

        #
        # rough segwit estimate
        #
        size = (
            inputs * 68 +
            outputs * 31 +
            10
        )

        fee = size * sat_per_byte

        return {
            "size": size,
            "fee": fee,
            "sat_per_byte": sat_per_byte
        }

    # -------------------------
    # RBF ENABLE
    # -------------------------
    def enable_rbf(self, tx):

        for inp in tx["inputs"]:

            #
            # RBF sequence
            #
            inp["sequence"] = 0xfffffffd

        return tx
