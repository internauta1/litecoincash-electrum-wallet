"""Litecoin Cash historical Hive difficulty rules.

Implements the target-adjustment arithmetic from Core's pow.cpp.

IMPORTANT:
- Historical headers and activation states must be validated separately.
- This module does not validate Hive proofs or BCT eligibility.
"""

from .lcc_chainwork import bits_to_target, ChainworkError

UINT256_MASK = (1 << 256) - 1

HIVE_LIMIT = int("0" + "f" * 63, 16)
HIVE_WINDOW = 36
HIVE_SPACING = 2
HIVE_AGGRESSION = 30
MIN_HIVE_CHECK_BLOCK = 1537566


class HiveDifficultyError(Exception):
    pass


def target_to_bits(target):
    """Bitcoin Core arith_uint256::GetCompact."""
    if not isinstance(target, int) or not 0 <= target <= UINT256_MASK:
        raise HiveDifficultyError("Invalid target")

    if target == 0:
        return 0

    size = (target.bit_length() + 7) // 8

    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))

    if compact & 0x00800000:
        compact >>= 8
        size += 1

    return (size << 24) | (compact & 0x007fffff)


def required_header(height, get_header):
    header = get_header(height)
    if header is None:
        raise HiveDifficultyError(f"Missing historical header {height}")
    return header


def hive10_next_bits(prev_height, get_header, is_hive):
    """Core GetNextHiveWorkRequired(), Hive 1.0 branch."""
    height = prev_height
    num_pow_blocks = 0

    while True:
        if height <= MIN_HIVE_CHECK_BLOCK:
            return target_to_bits(HIVE_LIMIT)

        current = required_header(height, get_header)

        if is_hive(height):
            target = bits_to_target(int(current["bits"]))
            break

        height -= 1
        num_pow_blocks += 1

    if num_pow_blocks == 0:
        return 0

    interval = HIVE_AGGRESSION // HIVE_SPACING

    numerator = (
        (interval - 1) * HIVE_SPACING
        + num_pow_blocks * 2
    )
    denominator = (interval + 1) * HIVE_SPACING

    # Match arith_uint256 arithmetic and integer division.
    target = (target * numerator) & UINT256_MASK
    target //= denominator

    return target_to_bits(min(target, HIVE_LIMIT))


def hive_sma_next_bits(
    prev_height,
    get_header,
    is_hive,
    *,
    hive12=False,
    minotaurx_enabled=None,
):
    """Core Hive 1.1 / Hive 1.2 SMA difficulty."""
    height = prev_height
    total_blocks = 0
    hive_blocks = 0
    target_sum = 0

    while hive_blocks < HIVE_WINDOW and height > 0:
        if hive12:
            if minotaurx_enabled is None:
                raise HiveDifficultyError(
                    "MinotaurX activation callback required"
                )
            if not minotaurx_enabled(height):
                break
        elif height < MIN_HIVE_CHECK_BLOCK:
            break

        header = required_header(height, get_header)

        if is_hive(height):
            target_sum = (
                target_sum
                + bits_to_target(int(header["bits"]))
            ) & UINT256_MASK
            hive_blocks += 1

        total_blocks += 1
        height -= 1

    if hive12:
        if hive_blocks < HIVE_WINDOW:
            return target_to_bits(HIVE_LIMIT)
    elif hive_blocks == 0:
        return target_to_bits(HIVE_LIMIT)

    target = target_sum // hive_blocks

    expected = hive_blocks * HIVE_SPACING
    target = (target * total_blocks) & UINT256_MASK
    target //= expected

    return target_to_bits(min(target, HIVE_LIMIT))


def next_hive_bits(
    prev_height,
    get_header,
    is_hive,
    hive11_enabled,
    minotaurx_enabled,
):
    """Select Hive difficulty rule using the previous block state.

    All callbacks must refer to the same independently verified branch.
    """
    required_header(prev_height, get_header)

    if minotaurx_enabled(prev_height):
        return hive_sma_next_bits(
            prev_height,
            get_header,
            is_hive,
            hive12=True,
            minotaurx_enabled=minotaurx_enabled,
        )

    if hive11_enabled(prev_height):
        return hive_sma_next_bits(
            prev_height,
            get_header,
            is_hive,
        )

    return hive10_next_bits(
        prev_height,
        get_header,
        is_hive,
    )
