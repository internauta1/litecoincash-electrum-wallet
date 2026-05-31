import hashlib


class TXValidator:

    def validate_basic(self, tx):

        # -------------------------
        # 1. INPUTS EXIST
        # -------------------------
        if not tx.get("inputs"):
            raise Exception("No inputs in transaction")

        # -------------------------
        # 2. OUTPUTS EXIST
        # -------------------------
        if not tx.get("outputs"):
            raise Exception("No outputs in transaction")

        # -------------------------
        # 3. VALUE CHECK
        # -------------------------
        total_in = sum(i["value"] for i in tx["inputs"])
        total_out = sum(o["value"] for o in tx["outputs"])
        fee = tx.get("fee", 0)

        if total_out + fee > total_in:
            raise Exception("Invalid balance (overspend)")

        # -------------------------
        # 4. ADDRESS CHECK (basic sanity)
        # -------------------------
        for o in tx["outputs"]:
            if not isinstance(o["address"], str):
                raise Exception("Invalid address format")

            if len(o["address"]) < 20:
                raise Exception("Address too short")

        return True

    def tx_size_estimate(self, tx):

        # very simple estimation (good enough for fee check)
        inputs = len(tx["inputs"])
        outputs = len(tx["outputs"])

        return inputs * 180 + outputs * 34 + 10
