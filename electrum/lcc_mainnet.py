"""Verified Litecoin Cash mainnet consensus parameters.

Sources:
  Litecoin Cash Core src/chainparams.cpp
  Litecoin Cash Core src/amount.h

This module contains mainnet constants only.
"""

import hashlib


COIN = 10_000_000
COIN_SCALE = 10

HALVING_INTERVAL = 840_000
LAST_SCRYPT_BLOCK = 1_371_111
SLOW_START_BLOCKS = 2_000
PREMINE_AMOUNT = 550_000
TOTAL_MONEY_SUPPLY_HEIGHT = 6_215_968

MIN_BEE_COST = 10_000
BEE_COST_FACTOR = 2_500

BEE_GESTATION = 1_152
BEE_LIFESPAN = 16_128
COMMUNITY_FACTOR = 10

BEE_CREATION_ADDRESS = "CReateLitecoinCashWorkerBeeXYs19YQ"
HIVE_COMMUNITY_ADDRESS = "CashCFfv8CmdWo6wyMGQWtmQnaToyhgsWr"


class LCCMainnetError(Exception):
    pass


def _sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def decode_base58check(address):
    """Decode a Base58Check address, verifying its checksum."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    if not isinstance(address, str) or not address:
        raise LCCMainnetError("Invalid address")

    value = 0
    for character in address:
        if character not in alphabet:
            raise LCCMainnetError("Invalid Base58 character")
        value = value * 58 + alphabet.index(character)

    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    leading = len(address) - len(address.lstrip("1"))
    raw = b"\x00" * leading + raw

    if len(raw) != 25:
        raise LCCMainnetError("Invalid address length")

    payload, checksum = raw[:-4], raw[-4:]

    if _sha256d(payload)[:4] != checksum:
        raise LCCMainnetError("Invalid address checksum")

    return payload[0], payload[1:]


def p2pkh_script(address):
    """Return the canonical P2PKH script for a mainnet address."""
    version, hash160 = decode_base58check(address)

    if version != 0x1c:
        raise LCCMainnetError("Unexpected mainnet P2PKH version")

    if len(hash160) != 20:
        raise LCCMainnetError("Invalid public key hash")

    return bytes.fromhex("76a914") + hash160 + bytes.fromhex("88ac")


def bee_creation_script():
    return p2pkh_script(BEE_CREATION_ADDRESS)


def community_script():
    return p2pkh_script(HIVE_COMMUNITY_ADDRESS)


# LCC_MAINNET_BIP9_DEPLOYMENTS_V1
# Official Litecoin Cash mainnet deployments.

BIP9_WINDOW = 8064
BIP9_THRESHOLD = 6048
POW_FORK_TIME = 1518982404

def mainnet_bip9_deployments():
    from .lcc_bip9 import Deployment

    return {
        "hive": Deployment(
            bit=7,
            start=1545782400,
            timeout=1577318400,
        ),
        "hive11": Deployment(
            bit=9,
            start=1568937600,
            timeout=1600560000,
        ),
        "minotaurx": Deployment(
            bit=7,
            start=1631793600,
            timeout=1663329600,
        ),
    }
