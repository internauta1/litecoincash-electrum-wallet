import hashlib
import base58


class BIP143:

    # -----------------------------
    # DOUBLE SHA256
    # -----------------------------
    def hash256(self, b):

        return hashlib.sha256(
            hashlib.sha256(b).digest()
        ).digest()

    # -----------------------------
    # VARINT
    # -----------------------------
    def varint(self, i):

        if i < 0xfd:
            return bytes([i])

        elif i <= 0xffff:
            return b"\xfd" + i.to_bytes(2, "little")

        elif i <= 0xffffffff:
            return b"\xfe" + i.to_bytes(4, "little")

        else:
            return b"\xff" + i.to_bytes(8, "little")

    # -----------------------------
    # ADDRESS -> HASH160
    # -----------------------------
    def address_to_h160(self, address):

        # ---------------------------------
        # SEGWIT (lcc1...)
        # ---------------------------------
        if address.startswith("lcc1"):

            from core.bech32 import decode_segwit_address

            return decode_segwit_address(address)

        # ---------------------------------
        # LEGACY BASE58
        # ---------------------------------
        decoded = base58.b58decode(address)

        return decoded[1:-4]

    # -----------------------------
    # REAL SCRIPTCODE
    # -----------------------------
    def scriptcode(self, address):

        h160 = self.address_to_h160(address)

        # ---------------------------------
        # Native SegWit (P2WPKH)
        # BIP143 scriptCode
        # ---------------------------------
        if address.startswith("lcc1"):

            return (
                b"\x19"
                +
                b"\x76\xa9\x14"
                +
                h160
                +
                b"\x88\xac"
            )

        # ---------------------------------
        # Legacy P2PKH
        # ---------------------------------
        return (
            b"\x76\xa9\x14"
            +
            h160
            +
            b"\x88\xac"
        )

    # -----------------------------
    # HASH PREVOUTS
    # -----------------------------
    def hash_prevouts(self, tx):

        data = b""

        for inp in tx["inputs"]:

            data += bytes.fromhex(
                inp["tx_hash"]
            )[::-1]

            data += inp["tx_pos"].to_bytes(
                4,
                "little"
            )

        return self.hash256(data)

    # -----------------------------
    # HASH SEQUENCE
    # -----------------------------
    def hash_sequence(self, tx):

        data = b""

        for inp in tx["inputs"]:

            seq = inp.get(
                "sequence",
                0xffffffff
            )

            data += seq.to_bytes(
                4,
                "little"
            )

        return self.hash256(data)

    # -----------------------------
    # HASH OUTPUTS
    # -----------------------------
    def hash_outputs(self, tx):

        data = b""

        for out in tx["outputs"]:

            script = self.scriptcode(
                out["address"]
            )

            data += int(
                out["value"]
            ).to_bytes(8, "little")

            data += self.varint(
                len(script)
            )

            data += script

        return self.hash256(data)

    # -----------------------------
    # BUILD SIGHASH
    # -----------------------------
    def sighash(
        self,
        tx,
        input_index,
        utxo
    ):

        version = tx.get(
            "version",
            1
        ).to_bytes(4, "little")

        hash_prevouts = self.hash_prevouts(tx)

        hash_sequence = self.hash_sequence(tx)

        inp = tx["inputs"][input_index]

        outpoint = (
            bytes.fromhex(
                inp["tx_hash"]
            )[::-1]
            +
            inp["tx_pos"].to_bytes(
                4,
                "little"
            )
        )

        script = self.scriptcode(
            utxo["address"]
        )

        scriptcode = (
            self.varint(len(script))
            +
            script
        )

        amount = int(
            utxo["value"]
        ).to_bytes(8, "little")

        sequence = inp.get(
            "sequence",
            0xffffffff
        ).to_bytes(4, "little")

        hash_outputs = self.hash_outputs(tx)

        locktime = tx.get(
            "locktime",
            0
        ).to_bytes(4, "little")

        sighash_type = (
            0x01 |
            0x40
        ).to_bytes(4, "little")

        preimage = (
            version +
            hash_prevouts +
            hash_sequence +
            outpoint +
            scriptcode +
            amount +
            sequence +
            hash_outputs +
            locktime +
            sighash_type
        )

        return self.hash256(preimage)
