import hashlib
import base58


class RawSerializer:

    # -------------------------
    # BASE58 DECODE
    # -------------------------
    def b58decode(self, addr):

        raw = base58.b58decode(addr)

        return raw

    # -------------------------
    # ADDRESS -> HASH160
    # -------------------------
    def address_to_h160(self, address):

        decoded = self.b58decode(address)

        # remove prefix + checksum
        return decoded[1:-4]

    # -------------------------
    # SERIALIZE TX
    # -------------------------
    def serialize(self, tx):

        raw = b""

        # version
        raw += (1).to_bytes(4, "little")

        # input count
        raw += len(tx["inputs"]).to_bytes(1, "little")

        # inputs
        for i, inp in enumerate(tx["inputs"]):

            signed = tx["signed_inputs"][i]

            raw += bytes.fromhex(inp["txid"])[::-1]

            raw += inp["vout"].to_bytes(4, "little")

            sig = bytes.fromhex(
                signed["signature"]
            )

            pub = bytes.fromhex(
                signed["pubkey"]
            )

            script_sig = (
                len(sig).to_bytes(1, "little") +
                sig +
                len(pub).to_bytes(1, "little") +
                pub
            )

            raw += len(script_sig).to_bytes(1, "little")

            raw += script_sig

            raw += bytes.fromhex("ffffffff")

        # outputs
        raw += len(tx["outputs"]).to_bytes(1, "little")

        for out in tx["outputs"]:

            raw += out["value"].to_bytes(8, "little")

            h160 = self.address_to_h160(
                out["address"]
            )

            script_pubkey = (
                b"\x76\xa9\x14" +
                h160 +
                b"\x88\xac"
            )

            raw += len(script_pubkey).to_bytes(1, "little")

            raw += script_pubkey

        # locktime
        raw += (0).to_bytes(4, "little")

        return raw.hex()
