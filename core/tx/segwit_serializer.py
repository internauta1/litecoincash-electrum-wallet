import base58

from core.bech32 import decode_segwit_address


class SegWitSerializer:

    # --------------------------------
    # VARINT
    # --------------------------------
    def encode_varint(self, i):

        if i < 0xfd:
            return bytes([i])

        elif i <= 0xffff:
            return b"\xfd" + i.to_bytes(2, "little")

        elif i <= 0xffffffff:
            return b"\xfe" + i.to_bytes(4, "little")

        return b"\xff" + i.to_bytes(8, "little")

    # --------------------------------
    # SERIALIZE SEGWIT TX
    # --------------------------------
    def serialize(self, tx, witnesses=None):

        if witnesses is None:
            witnesses = []

        version = tx["version"].to_bytes(
            4,
            "little"
        )

        marker_flag = b"\x00\x01"

        # --------------------------------
        # INPUTS
        # --------------------------------
        vin = self.encode_varint(
            len(tx["inputs"])
        )

        for inp in tx["inputs"]:

            vin += bytes.fromhex(
                inp["tx_hash"]
            )[::-1]

            vin += inp["tx_pos"].to_bytes(
                4,
                "little"
            )

            # empty scriptsig
            vin += b"\x00"

            vin += inp.get(
                "sequence",
                0xffffffff
            ).to_bytes(4, "little")

        # --------------------------------
        # OUTPUTS
        # --------------------------------
        vout = self.encode_varint(
            len(tx["outputs"])
        )

        for out in tx["outputs"]:

            value = int(
                out["value"]
            ).to_bytes(8, "little")

            addr = out["address"]

            # native segwit
            if addr.startswith("lcc1"):

                script = self.p2wpkh_script(
                    addr
                )

            # legacy
            else:

                script = self.p2pkh_script(
                    addr
                )

            vout += value
            vout += self.encode_varint(
                len(script)
            )
            vout += script

        # --------------------------------
        # WITNESS
        # --------------------------------
        wit = b""

        for w in witnesses:

            wit += self.encode_varint(
                len(w["items"])
            )

            for item in w["items"]:

                wit += self.encode_varint(
                    len(item)
                )

                wit += item

        locktime = tx.get(
            "locktime",
            0
        ).to_bytes(4, "little")

        return (
            version +
            marker_flag +
            vin +
            vout +
            wit +
            locktime
        )

    # --------------------------------
    # LEGACY SCRIPT
    # --------------------------------
    def p2pkh_script(self, address):

        decoded = base58.b58decode(
            address
        )

        h160 = decoded[1:-4]

        return (
            b"\x76\xa9\x14" +
            h160 +
            b"\x88\xac"
        )

    # --------------------------------
    # NATIVE SEGWIT SCRIPT
    # --------------------------------
    def p2wpkh_script(self, address):

        h160 = decode_segwit_address(
            address
        )

        return b"\x00\x14" + h160
