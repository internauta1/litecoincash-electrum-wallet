import hmac
import hashlib
import struct

from ecdsa import SigningKey, SECP256k1
from mnemonic import Mnemonic

from core.wallet_core_v1.lcc_network import (
    LCC_P2PKH_PREFIX,
    LCC_DEFAULT_DERIVATION_PATH
)


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_ORDER = SECP256k1.order


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    res = ""

    while n > 0:
        n, r = divmod(n, 58)
        res = B58_ALPHABET[r] + res

    pad = 0

    for b in data:
        if b == 0:
            pad += 1
        else:
            break

    return "1" * pad + res


def base58check_encode(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = sha256(sha256(data))[:4]

    return base58_encode(data + checksum)


def private_key_to_public_key_compressed(privkey: bytes) -> bytes:
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.verifying_key

    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()

    prefix = b"\x02" if y % 2 == 0 else b"\x03"

    return prefix + x.to_bytes(32, "big")


def mnemonic_to_seed(mnemonic_words: str, passphrase: str = "") -> bytes:
    mnemo = Mnemonic("english")

    return mnemo.to_seed(
        mnemonic_words,
        passphrase=passphrase
    )


def master_key_from_seed(seed: bytes):
    digest = hmac.new(
        b"Bitcoin seed",
        seed,
        hashlib.sha512
    ).digest()

    private_key = digest[:32]
    chain_code = digest[32:]

    return private_key, chain_code


def ckd_priv(
    parent_private_key: bytes,
    parent_chain_code: bytes,
    index: int
):
    if index >= 0x80000000:
        data = (
            b"\x00" +
            parent_private_key +
            struct.pack(">L", index)
        )
    else:
        parent_public_key = private_key_to_public_key_compressed(
            parent_private_key
        )

        data = parent_public_key + struct.pack(">L", index)

    digest = hmac.new(
        parent_chain_code,
        data,
        hashlib.sha512
    ).digest()

    il = digest[:32]
    ir = digest[32:]

    il_int = int.from_bytes(il, "big")
    pk_int = int.from_bytes(parent_private_key, "big")

    child_int = (il_int + pk_int) % SECP256K1_ORDER

    if child_int == 0:
        raise ValueError("Invalid child private key")

    child_private_key = child_int.to_bytes(32, "big")
    child_chain_code = ir

    return child_private_key, child_chain_code


def parse_path(path: str):
    if not path.startswith("m/"):
        raise ValueError("Invalid derivation path")

    parts = path.split("/")[1:]
    indexes = []

    for part in parts:
        hardened = part.endswith("'")

        if hardened:
            part = part[:-1]

        index = int(part)

        if index < 0:
            raise ValueError("Invalid negative index")

        if hardened:
            index += 0x80000000

        indexes.append(index)

    return indexes


def derive_private_key(seed: bytes, path: str):
    private_key, chain_code = master_key_from_seed(seed)

    for index in parse_path(path):
        private_key, chain_code = ckd_priv(
            private_key,
            chain_code,
            index
        )

    return private_key


def bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1

    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value

        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]

    return chk


def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1

    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list):
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    combined = data + bech32_create_checksum(hrp, data)

    return hrp + "1" + "".join([charset[d] for d in combined])


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True):
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


def lcc_segwit_address_from_pubkey(public_key: bytes) -> str:
    witness_program = hash160(public_key)
    data = [0] + list(convertbits(witness_program, 8, 5))

    return bech32_encode("lcc", data)


def lcc_address_from_mnemonic(
    mnemonic_words: str,
    path: str = LCC_DEFAULT_DERIVATION_PATH
) -> dict:
    seed = mnemonic_to_seed(mnemonic_words)
    private_key = derive_private_key(seed, path)

    public_key = private_key_to_public_key_compressed(private_key)

    address = base58check_encode(
        LCC_P2PKH_PREFIX,
        hash160(public_key)
    )

    segwit_address = lcc_segwit_address_from_pubkey(public_key)

    return {
        "address": address,
        "segwit_address": segwit_address,
        "public_key": public_key.hex(),
        "derivation": path,
        "warning": "Endereço derivado com sucesso."
    }


def lcc_address_at_index(
    mnemonic_words: str,
    index: int = 0,
    account: int = 0,
    change: int = 0
) -> dict:
    path = f"m/44'/2'/{account}'/{change}/{index}"

    return lcc_address_from_mnemonic(
        mnemonic_words=mnemonic_words,
        path=path
    )


def lcc_addresses_from_mnemonic(
    mnemonic_words: str,
    count: int = 5,
    account: int = 0,
    change: int = 0
) -> list:
    addresses = []

    for i in range(count):
        info = lcc_address_at_index(
            mnemonic_words=mnemonic_words,
            index=i,
            account=account,
            change=change
        )

        addresses.append({
            "index": i,
            "path": info["derivation"],
            "address": info["address"],
            "segwit_address": info.get("segwit_address"),
            "public_key": info["public_key"]
        })

    return addresses


def private_key_for_address(
    mnemonic_words: str,
    target_address: str,
    count: int = 100
):
    seed = mnemonic_to_seed(mnemonic_words)

    for i in range(count):
        path = f"m/44'/2'/0'/0/{i}"

        private_key = derive_private_key(seed, path)
        public_key = private_key_to_public_key_compressed(private_key)

        address = base58check_encode(
            LCC_P2PKH_PREFIX,
            hash160(public_key)
        )

        segwit_address = lcc_segwit_address_from_pubkey(public_key)

        if address == target_address or segwit_address == target_address:
            return {
                "ok": True,
                "index": i,
                "path": path,
                "address": address,
                "segwit_address": segwit_address,
                "matched_address": target_address,
                "private_key": private_key.hex(),
                "public_key": public_key.hex()
            }

    return {
        "ok": False,
        "error": "ADDRESS_PRIVATE_KEY_NOT_FOUND"
    }
