import hashlib
import base58


def b58decode_check(addr):
    raw = base58.b58decode_check(addr)
    return raw


def address_to_scripthash(address):

    decoded = b58decode_check(address)

    pubkey_hash = decoded[1:]

    script = (
        b"\x76"
        + b"\xa9"
        + b"\x14"
        + pubkey_hash
        + b"\x88"
        + b"\xac"
    )

    sha = hashlib.sha256(script).digest()

    scripthash = sha[::-1].hex()

    return scripthash
