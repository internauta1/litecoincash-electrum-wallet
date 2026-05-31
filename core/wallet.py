from core.chain import LCCChain
import hashlib
import ecdsa
import base58


class LCCWallet:

    def __init__(self):

        # FIXED SEED (deterministic wallet)
        self.seed = b"lcc-test-wallet-fixed-seed"

        self.chain = LCCChain()

        # 🔥 PRIVATE KEY (RAW BYTES SHA256)
        self._privkey = hashlib.sha256(self.seed).digest()

    # -------------------------
    # PRIVATE KEY
    # -------------------------
    def get_private_key(self):
        return self._privkey.hex()

    # -------------------------
    # PUBLIC KEY (ECDSA SECP256K1)
    # -------------------------
    def get_public_key(self):

        sk = ecdsa.SigningKey.from_string(
            self._privkey,
            curve=ecdsa.SECP256k1
        )

        vk = sk.verifying_key

        return b"\x04" + vk.to_string()

    # -------------------------
    # ADDRESS (P2PKH STANDARD)
    # -------------------------
    def get_address(self, index=0):

        pub = self.get_public_key()

        h160 = hashlib.new(
            "ripemd160",
            hashlib.sha256(pub).digest()
        ).digest()

        payload = bytes([self.chain.PUBKEY_PREFIX]) + h160

        checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        addr_bytes = payload + checksum

        return self.base58(addr_bytes)

    # -------------------------
    # BASE58 ENCODE
    # -------------------------
    def base58(self, b):

        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        n = int.from_bytes(b, "big")
        res = ""

        while n > 0:
            n, r = divmod(n, 58)
            res = alphabet[r] + res

        pad = 0
        for byte in b:
            if byte == 0:
                pad += 1
            else:
                break

        return "1" * pad + res

    # -------------------------
    # ADDRESS -> SCRIPTHASH (ELECTRUM FORMAT)
    # -------------------------
    def address_to_scripthash(self, address):

        n = 0
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        for c in address:
            n = n * 58 + alphabet.index(c)

        full = n.to_bytes(25, "big")

        h160 = full[1:21]

        script = b"\x76\xa9\x14" + h160 + b"\x88\xac"

        return hashlib.sha256(script).digest()[::-1].hex()

    # -------------------------
    # SCRIPTHASH
    # -------------------------
    def get_scripthash(self, index=0):

        return self.address_to_scripthash(
            self.get_address(index)
        )

    # -------------------------
    # PUBKEY HASH (FIXED)
    # -------------------------
    def address_to_pubkeyhash(self, address):

        decoded = base58.b58decode(address)

        return decoded[1:-4]
