import struct
import hashlib


class RawTX:

    def serialize(self, tx):

        version = struct.pack("<I", tx.get("version", 1))

        inputs = tx["inputs"]
        outputs = tx["outputs"]

        vin = self.varint(len(inputs))
        vout = self.varint(len(outputs))

        raw_inputs = b""

        # -------------------
        # INPUTS
        # -------------------
        for i, inp in enumerate(inputs):

            txid = bytes.fromhex(inp["txid"])[::-1]
            vout_index = struct.pack("<I", inp["vout"])

            sig = bytes.fromhex(tx["signed_inputs"][i]["signature"])
            pub = bytes.fromhex(tx["signed_inputs"][i]["pubkey"])

            # 🔥 FIX PRINCIPAL: scriptSig correto (NÃO double push)
            script = self.push(sig) + self.push(pub)

            script_len = self.varint(len(script))

            raw_inputs += (
                txid +
                vout_index +
                script_len +
                script +
                b"\xff\xff\xff\xff"
            )

        # -------------------
        # OUTPUTS
        # -------------------
        raw_outputs = b""

        for o in outputs:

            value = struct.pack("<Q", o["value"])

            h160 = self.address_to_hash160(o["address"])

            script = (
                b"\x76\xa9\x14" +
                h160 +
                b"\x88\xac"
            )

            raw_outputs += value + self.push(script)

        locktime = struct.pack("<I", 0)

        return version + vin + raw_inputs + vout + raw_outputs + locktime

    # -------------------------
    def push(self, data):

        if isinstance(data, str):
            data = data.encode()

        if len(data) < 75:
            return bytes([len(data)]) + data

        raise Exception("Push size não suportado neste builder simples")

    # -------------------------
    def varint(self, n):

        if n < 253:
            return bytes([n])

        raise Exception("Varint não implementado para TX grande")

    # -------------------------
    def address_to_hash160(self, address):

        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        n = 0
        for c in address:
            n = n * 58 + alphabet.index(c)

        full = n.to_bytes(25, "big")

        return full[1:21]
