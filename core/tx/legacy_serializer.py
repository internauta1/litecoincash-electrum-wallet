import base58
import hashlib


class LegacySerializer:

    # -------------------------
    # VARINT
    # -------------------------
    def encode_varint(self, i):

        if i < 0xfd:
            return bytes([i])

        elif i <= 0xffff:
            return b"\xfd" + i.to_bytes(2, "little")

        elif i <= 0xffffffff:
            return b"\xfe" + i.to_bytes(4, "little")

        else:
            return b"\xff" + i.to_bytes(8, "little")

    # -------------------------
    # ADDRESS -> HASH160
    # -------------------------
    def address_to_h160(self, address):

        decoded = base58.b58decode(address)

        return decoded[1:-4]

    # -------------------------
    # P2PKH SCRIPT
    # -------------------------
    def p2pkh_script(self, address):

        h160 = self.address_to_h160(address)

        return (
            b"\x76\xa9\x14" +
            h160 +
            b"\x88\xac"
        )

    # -------------------------
    # SERIALIZE
    # -------------------------
    def serialize(self, tx):

        raw = b""

        #
        # VERSION
        #
        raw += tx["version"].to_bytes(4, "little")

        #
        # INPUT COUNT
        #
        raw += self.encode_varint(
            len(tx["inputs"])
        )

        #
        # INPUTS
        #
        for inp in tx["inputs"]:

            raw += bytes.fromhex(
                inp["tx_hash"]
            )[::-1]

            raw += inp["tx_pos"].to_bytes(
                4,
                "little"
            )

            script_sig = inp.get(
                "scriptSig",
                b""
            )

            raw += self.encode_varint(
                len(script_sig)
            )

            raw += script_sig

            raw += inp.get(
                "sequence",
                0xffffffff
            ).to_bytes(4, "little")

        #
        # OUTPUT COUNT
        #
        raw += self.encode_varint(
            len(tx["outputs"])
        )

        #
        # OUTPUTS
        #
        for out in tx["outputs"]:

            raw += int(
                out["value"]
            ).to_bytes(8, "little")

            script = self.p2pkh_script(
                out["address"]
            )

            raw += self.encode_varint(
                len(script)
            )

            raw += script

        #
        # LOCKTIME
        #
        raw += tx.get(
            "locktime",
            0
        ).to_bytes(4, "little")

        return raw
