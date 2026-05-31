import os
import hashlib
import hmac
import ecdsa
import base58

from mnemonic import Mnemonic
from core.chain import LCCChain


# -------------------------
# BECH32 (minimal LCC1)
# -------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
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


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
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

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)

    return ret


# -------------------------
# WALLET
# -------------------------
class HDWallet:

    def __init__(self, mnemonic=None):

        self.chain = LCCChain()

        if mnemonic:
            self.mnemonic = mnemonic

        elif os.path.exists("wallet_data/mnemonic.txt"):
            with open("wallet_data/mnemonic.txt", "r") as f:
                self.mnemonic = f.read().strip()

        else:
            self.mnemonic = Mnemonic("english").generate(128)

            os.makedirs("wallet_data", exist_ok=True)

            with open("wallet_data/mnemonic.txt", "w") as f:
                f.write(self.mnemonic)

        self.seed = Mnemonic.to_seed(self.mnemonic, passphrase="")

    # -------------------------
    # DERIVATION
    # -------------------------
    def derive_key(self, index):

        data = b"LCC-HD-" + index.to_bytes(4, "big")

        return hmac.new(
            self.seed,
            data,
            hashlib.sha256
        ).digest()

    def get_private_key(self, index=0):
        return self.derive_key(index).hex()

    # -------------------------
    # PUBLIC KEY
    # -------------------------
    def get_public_key(self, index=0):

        privkey = self.derive_key(index)

        sk = ecdsa.SigningKey.from_string(
            privkey,
            curve=ecdsa.SECP256k1
        )

        vk = sk.verifying_key

        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()

        prefix = b"\x02" if y % 2 == 0 else b"\x03"

        return prefix + x.to_bytes(32, "big")

    # -------------------------
    # LEGACY ADDRESS (C...)
    # -------------------------
    def get_address(self, index=0):

        pub = self.get_public_key(index)

        sha = hashlib.sha256(pub).digest()
        ripe = hashlib.new("ripemd160", sha).digest()

        payload = bytes([self.chain.PUBKEY_PREFIX]) + ripe

        checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        return base58.b58encode(payload + checksum).decode()

    # -------------------------
    # LCC1 ADDRESS (NATIVE SEGWIT)
    # -------------------------
    def get_lcc1_address(self, index=0):

        pub = self.get_public_key(index)

        sha = hashlib.sha256(pub).digest()
        ripe = hashlib.new("ripemd160", sha).digest()

        # witness version 0 + hash160
        data = [0] + list(convertbits(ripe, 8, 5))

        return bech32_encode("lcc", data)

    # -------------------------
    # ADDRESS TO PUBKEYHASH
    # -------------------------
    def address_to_pubkeyhash(self, address):

        decoded = base58.b58decode(address)
        return decoded[1:-4]
