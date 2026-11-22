"""LCC DarkGravityWave across Hive 1.1.

Port of Litecoin Cash Core src/pow.cpp DarkGravityWave().
The history provider must expose a previously validated chain.
This module never authorizes header storage by itself.
"""

from .lcc_chainwork import bits_to_target
from .lcc_hive_difficulty import target_to_bits
from .lcc_header_rules import classify_header

MASK = (1 << 256) - 1
POW_LIMIT_SHA = int("00000000" + "f" * 56, 16)
LAST_SCRYPT_BLOCK = 1371111
WINDOW = 24
SPACING = 150


class DGWHive11Error(ValueError):
    pass


def next_dgw_bits(*, height, get_header, hive11_active):
    if type(height) is not int or height <= LAST_SCRYPT_BLOCK:
        raise DGWHive11Error("Invalid DGW height")

    if type(hive11_active) is not bool:
        raise DGWHive11Error("Invalid Hive 1.1 activation state")

    def read(h):
        item = get_header(h)
        if not isinstance(item, dict) or item.get("block_height") != h:
            raise DGWHive11Error(f"Missing historical header {h}")
        return item

    def kind(h):
        item = read(h)
        return classify_header(
            h, item["version"], item["nonce"]
        )

    cursor = height - 1
    steps = 0

    # Core skips Hive blocks at the tip only after Hive 1.1.
    if hive11_active:
        while kind(cursor) == "hive":
            cursor -= 1
            steps += 1
            if steps > 512:
                raise DGWHive11Error("Excessive Hive scan")

    last_pow_height = cursor

    if last_pow_height - LAST_SCRYPT_BLOCK < WINDOW:
        return target_to_bits(POW_LIMIT_SHA)

    average = 0
    oldest = None

    for count in range(1, WINDOW + 1):
        while kind(cursor) == "hive":
            cursor -= 1
            steps += 1
            if steps > 512:
                raise DGWHive11Error("Excessive Hive scan")

        previous = read(cursor)

        if kind(cursor) != "sha256d":
            raise DGWHive11Error("Unexpected historical PoW type")

        target = bits_to_target(previous["bits"])

        if not 0 < target <= POW_LIMIT_SHA:
            raise DGWHive11Error("Invalid historical PoW target")

        if count == 1:
            average = target
        else:
            # Match Core's iterative integer calculation.
            average = (
                ((average * count) & MASK) + target
            ) & MASK
            average //= count + 1

        oldest = previous

        if count != WINDOW:
            cursor -= 1
            steps += 1
            if steps > 512:
                raise DGWHive11Error("Excessive DGW scan")

    newest = read(last_pow_height)

    timespan = newest["timestamp"] - oldest["timestamp"]

    target_timespan = WINDOW * SPACING
    timespan = max(target_timespan // 3, timespan)
    timespan = min(target_timespan * 3, timespan)

    result = ((average * timespan) & MASK) // target_timespan
    result = min(result, POW_LIMIT_SHA)

    return target_to_bits(result)
