import os
import hashlib
import hmac

import ecdsa
import base58

from mnemonic import Mnemonic
from bip32utils import BIP32Key


# -------------------------
# HD WALLET V2 (BIP39 + BIP32)
# -------------------------
class HDWalletV2:

    def __init__(self, mnemonic=None, passphrase=""):

        self.mnemo = Mnemonic("english")

        # -------------------------
        # LOAD OR GENERATE MNEMONIC
        # -------------------------
        if mnemonic:
            self.mnemonic = mnemonic

        elif os.path.exists("wallet_secure/seed.txt"):
            with open("wallet_secure/seed.txt", "r") as f:
                self.mnemonic = f.read().strip()

        else:
            self.mnemonic = self.mnemo.generate(strength=256)

            os.makedirs("wallet_secure", exist_ok=True)

            with open("wallet_secure/seed.txt", "w") as f:
                f.write(self.mnemonic)

        # -------------------------
        # BIP39 → SEED
        # -------------------------
        self.seed = self.mnemo.to_seed(self.mnemonic, passphrase=passphrase)

        # -------------------------
        # BIP32 MASTER KEY
        # -------------------------
        self.master = BIP32Key.fromEntropy(self.seed)

    # -------------------------
    # DERIVATION PATH HELPERS
    # -------------------------
    def _derive_path(self, path: str):

        key = self.master

        for part in path.split("/")[1:]:

            hardened = "'" in part

            index = int(part.replace("'", ""))

            if hardened:
                index += 0x80000000

            key = key.ChildKey(index)

        return key

    # -------------------------
    # PRIVATE KEY
    # -------------------------
    def get_private_key(self, index=0):

        path = f"m/84'/192'/0'/0/{index}"

        key = self._derive_path(path)

        return key.WalletImportFormat()

    # -------------------------
    # PUBLIC KEY (compressed)
    # -------------------------
    def get_public_key(self, index=0):

        path = f"m/84'/192'/0'/0/{index}"

        key = self._derive_path(path)

        return key.PublicKey()

    # -------------------------
    # LEGACY ADDRESS (BASE58)
    # -------------------------
    def get_address(self, index=0):

        pubkey = self.get_public_key(index)

        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new("ripemd160", sha).digest()

        payload = b"\x30" + ripe  # LCC prefix (same como teu chain)

        checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        return base58.b58encode(payload + checksum).decode()

    # -------------------------
    # SEGWIT ADDRESS (BECH32 SIMPLE)
    # -------------------------
    def get_lcc1_address(self, index=0):

        pubkey = self.get_public_key(index)

        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new("ripemd160", sha).digest()

        # simples conversion (igual ao teu modelo atual)
        data = [0] + list(self._convertbits(ripe, 8, 5))

        return self._bech32_encode("lcc", data)

    # -------------------------
    # HELPERS BECH32
    # -------------------------
    def _convertbits(self, data, frombits, tobits, pad=True):

        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1

        for value in data:
            acc = (acc << frombits) | value
            bits += frombits

            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)

        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)

        return ret

    def _bech32_encode(self, hrp, data):

        CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def polymod(values):
            GEN = [0x3b6a57b2,
                   0x26508e6d,
                   0x1ea119fa,
                   0x3d4233dd,
                   0x2a1462b3]

            chk = 1

            for v in values:
                b = chk >> 25
                chk = ((chk & 0x1ffffff) << 5) ^ v

                for i in range(5):
                    if ((b >> i) & 1):
                        chk ^= GEN[i]

            return chk

        def hrp_expand(hrp):
            return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

        values = hrp_expand(hrp) + data

        polymod_val = polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1

        checksum = [(polymod_val >> 5 * (5 - i)) & 31 for i in range(6)]

        combined = data + checksum

        return hrp + "1" + "".join([CHARSET[d] for d in combined])
