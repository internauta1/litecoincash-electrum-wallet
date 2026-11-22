"""Litecoin Cash per-block chainwork rules.

Mirrors the structure of Core's GetBlockProof().
Inputs must come from a verified chain and consensus validators.
"""

import math

MAX_UINT256 = (1 << 256) - 1

MIN_K = 2
MAX_K = 16
MAX_HIVE_DIFF = 0.006
MAX_K_POW = 5
POW_SPLIT_1 = 0.005
POW_SPLIT_2 = 0.0025


class ChainworkError(Exception):
    pass


def bits_to_target(bits):
    if not isinstance(bits, int) or not 0 <= bits <= 0xffffffff:
        raise ChainworkError("Invalid compact bits")

    size = bits >> 24
    word = bits & 0x007fffff

    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))

    negative = bool(word and bits & 0x00800000)
    overflow = bool(
        word and (
            size > 34
            or (word > 0xff and size > 33)
            or (word > 0xffff and size > 32)
        )
    )

    if negative or overflow or target == 0 or target > MAX_UINT256:
        raise ChainworkError("Invalid target")

    return target


def base_work(bits):
    target = bits_to_target(bits)
    return ((MAX_UINT256 - target) // (target + 1)) + 1


def hive_multiplier(difficulty):
    """Hive 1.1 bonus multiplier, matching Core's double arithmetic."""
    difficulty = float(difficulty)

    if not math.isfinite(difficulty) or difficulty < 0:
        raise ChainworkError("Invalid Hive difficulty")

    return math.floor(
        min(difficulty / MAX_HIVE_DIFF, 1.0)
        * (MAX_K - MIN_K) + MIN_K
    )


def pow_multiplier(blocks_since_hive, last_hive_difficulty):
    """PoW multiplier used by GetBlockProof() after Hive 1.1."""
    if not 0 <= blocks_since_hive <= MAX_K_POW:
        raise ChainworkError("Invalid distance from Hive")

    difficulty = float(last_hive_difficulty)
    if not math.isfinite(difficulty) or difficulty < 0:
        raise ChainworkError("Invalid Hive difficulty")

    k = MAX_K_POW - blocks_since_hive

    if difficulty < POW_SPLIT_1:
        k >>= 1
    if difficulty < POW_SPLIT_2:
        k >>= 1

    return max(k, 1)


def block_work(
    height,
    get_header,
    is_hive,
    hive11_enabled,
    hive_difficulty,
):
    """Calculate consensus work for one block.

    All callbacks must describe the same validated historical branch:
      get_header(height) -> header dict or None
      is_hive(height) -> bool
      hive11_enabled(height) -> bool
      hive_difficulty(height) -> float
    """
    header = get_header(height)
    if header is None:
        raise ChainworkError(f"Missing header {height}")

    work = base_work(int(header["bits"]))

    if is_hive(height):
        if height == 0:
            raise ChainworkError("Hive at genesis")

        previous = height - 1

        while previous >= 0 and is_hive(previous):
            previous -= 1

        if previous < 0:
            raise ChainworkError("No preceding PoW block")

        pow_header = get_header(previous)
        if pow_header is None:
            raise ChainworkError(f"Missing PoW header {previous}")

        work += base_work(int(pow_header["bits"]))
        work &= MAX_UINT256

        if hive11_enabled(height):
            work *= hive_multiplier(core_difficulty_from_bits(int(header["bits"])))

    elif hive11_enabled(height):
        previous_hive = None

        for distance in range(MAX_K_POW):
            candidate = height - 1 - distance

            if candidate < 0:
                break

            if is_hive(candidate):
                previous_hive = (candidate, distance)
                break

        if previous_hive is None:
            multiplier = pow_multiplier(MAX_K_POW, 0.0)
        else:
            hive_height, distance = previous_hive
            multiplier = pow_multiplier(
                distance,
                core_difficulty_from_bits(
                    int(get_header(hive_height)["bits"])
                ),
            )

        work *= multiplier

    if work > MAX_UINT256:
        work &= MAX_UINT256

    return work


def accumulate_chainwork(start_height, end_height, previous_work, **callbacks):
    """Accumulate work on a validated branch, allowing checkpointed totals."""
    if start_height < 0 or end_height < start_height:
        raise ChainworkError("Invalid height interval")
    if not 0 <= previous_work <= MAX_UINT256:
        raise ChainworkError("Invalid previous chainwork")

    total = previous_work

    for height in range(start_height, end_height + 1):
        total += block_work(height, **callbacks)
        total &= MAX_UINT256

    return total


def difficulty_from_bits(bits):
    """Reproduce Litecoin Cash Core GetDifficulty() numeric formula."""
    bits_to_target(bits)  # Reject invalid compact targets.

    shift = (bits >> 24) & 0xff
    mantissa = bits & 0x00ffffff

    if mantissa == 0:
        raise ChainworkError("Zero difficulty mantissa")

    difficulty = float(0x0000ffff) / float(mantissa)

    while shift < 29:
        difficulty *= 256.0
        shift += 1

    while shift > 29:
        difficulty /= 256.0
        shift -= 1

    return difficulty


def hive_difficulty_at(
    height,
    get_header,
    is_hive,
    *,
    min_hive_check_block=1537566,
):
    """GetDifficulty(block, true) for a historical LCC branch.

    Header data and Hive classification must already be validated.
    """
    if height < 0:
        raise ChainworkError("Negative block height")

    cursor = height

    while cursor >= min_hive_check_block:
        header = get_header(cursor)

        if header is None:
            raise ChainworkError(f"Missing header {cursor}")

        if is_hive(cursor):
            return difficulty_from_bits(int(header["bits"]))

        cursor -= 1

    return 1.0


# LCC_CORE_DIFFICULTY_CHAINWORK_V1

def core_difficulty_from_bits(bits: int) -> float:
    """Reproduce Litecoin Cash Core GetDifficulty() arithmetic.

    Source: src/rpc/blockchain.cpp, GetDifficulty().
    """
    if type(bits) is not int or not 0 <= bits <= 0xffffffff:
        raise ChainworkError("Invalid difficulty bits")

    # Reject invalid compact targets before floating-point conversion.
    bits_to_target(bits)

    shift = (bits >> 24) & 0xff
    mantissa = bits & 0x00ffffff

    if mantissa == 0:
        raise ChainworkError("Zero difficulty mantissa")

    difficulty = float(0x0000ffff) / float(mantissa)

    while shift < 29:
        difficulty *= 256.0
        shift += 1

    while shift > 29:
        difficulty /= 256.0
        shift -= 1

    if not math.isfinite(difficulty) or difficulty <= 0:
        raise ChainworkError("Invalid Core difficulty")

    return difficulty
