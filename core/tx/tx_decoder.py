import hashlib


class TXDecoder:

    # -------------------------
    # TXID
    # -------------------------
    def txid(self, raw_hex):

        raw = bytes.fromhex(raw_hex)

        h = hashlib.sha256(raw).digest()
        h = hashlib.sha256(h).digest()

        return h[::-1].hex()

    # -------------------------
    # BASIC INFO
    # -------------------------
    def inspect(self, raw_hex):

        raw = bytes.fromhex(raw_hex)

        print("\n=== TX INSPECT ===\n")

        print("SIZE:", len(raw), "bytes")

        if raw[4:6] == b"\x00\x01":
            print("SEGWIT: YES")
        else:
            print("SEGWIT: NO")

        print("TXID:")
        print(self.txid(raw_hex))

        print("\nFIRST 80 BYTES:")
        print(raw_hex[:160])

        print("\nLAST 40 BYTES:")
        print(raw_hex[-80:])

        return {
            "size": len(raw),
            "segwit": raw[4:6] == b"\x00\x01",
            "txid": self.txid(raw_hex)
        }
