import hashlib


class TXValidator:

    # -----------------------------
    # DOUBLE SHA256
    # -----------------------------
    def hash256(self, b: bytes):
        return hashlib.sha256(
            hashlib.sha256(b).digest()
        ).digest()

    # -----------------------------
    # BASIC STRUCTURE CHECK
    # -----------------------------
    def validate_structure(self, tx: dict):

        if "inputs" not in tx or len(tx["inputs"]) == 0:
            raise Exception("TX invalid: no inputs")

        if "outputs" not in tx or len(tx["outputs"]) == 0:
            raise Exception("TX invalid: no outputs")

        for inp in tx["inputs"]:
            if "tx_hash" not in inp:
                raise Exception("TX invalid: missing tx_hash")
            if "tx_pos" not in inp:
                raise Exception("TX invalid: missing tx_pos")

        for out in tx["outputs"]:
            if "value" not in out:
                raise Exception("TX invalid: missing output value")
            if "address" not in out:
                raise Exception("TX invalid: missing output address")

        return True

    # -----------------------------
    # FEE CHECK
    # -----------------------------
    def validate_fee(self, tx: dict, utxos: list, fee: int):

        total_in = sum(u["value"] for u in utxos)
        total_out = sum(o["value"] for o in tx["outputs"])

        expected_fee = total_in - total_out

        if fee != expected_fee:
            raise Exception(
                f"Fee mismatch: expected {expected_fee}, got {fee}"
            )

        return True

    # -----------------------------
    # BASIC SIGN CHECK (WITNESS EXISTS)
    # -----------------------------
    def validate_witness(self, witness: list):

        if not witness:
            raise Exception("Missing witness data")

        for w in witness:
            if "items" not in w:
                raise Exception("Invalid witness format")

            if len(w["items"]) < 2:
                raise Exception("Witness too small (invalid signature)")

        return True

    # -----------------------------
    # FULL VALIDATION
    # -----------------------------
    def validate(self, tx: dict, utxos: list, fee: int, witness: list):

        self.validate_structure(tx)
        self.validate_fee(tx, utxos, fee)
        self.validate_witness(witness)

        return {
            "ok": True,
            "inputs": len(tx["inputs"]),
            "outputs": len(tx["outputs"]),
            "fee": fee
        }
