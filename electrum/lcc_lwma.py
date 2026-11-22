"""Litecoin Cash LWMA difficulty adjustment.

Port of GetNextWorkRequiredLWMA() from LCC Core.
Mainnet calculations; no testnet minimum-difficulty exception.

The supplied headers, activation state and PoW types must be
independently validated by the caller.
"""

from .lcc_chainwork import bits_to_target
from .lcc_hive_difficulty import target_to_bits

UINT256_MASK = (1 << 256) - 1
LWMA_WINDOW = 90
TARGET_SPACING = 150
ALGORITHM_SPACING = TARGET_SPACING * 2


class LWMAError(Exception):
    pass


def next_lwma_bits(
    prev_height,
    pow_type,
    pow_limit,
    get_header,
    is_hive,
    get_pow_type,
):
    """Calculate next nBits for one PoW algorithm.

    pow_type identifies SHA256d or MinotaurX.
    pow_limit is the consensus target limit for that algorithm.

    get_header(height) returns a historical header dict.
    is_hive(height) identifies Hive blocks.
    get_pow_type(height) identifies the PoW algorithm.

    Call only after MinotaurX activation has been validated.
    """
    N = LWMA_WINDOW
    T = ALGORITHM_SPACING
    k = N * (N + 1) * T // 2

    if prev_height < 0:
        raise LWMAError("Invalid previous height")

    if not 0 < pow_limit <= UINT256_MASK:
        raise LWMAError("Invalid PoW limit")

    limit_bits = target_to_bits(pow_limit)

    if prev_height < N:
        return limit_bits

    cursor = prev_height
    wanted = []

    while len(wanted) < N:
        if cursor < 0:
            raise LWMAError("Insufficient block history")

        header = get_header(cursor)

        if header is None:
            raise LWMAError(f"Missing header {cursor}")

        # Matches the Core fork-boundary check.
        if int(header["version"]) >= 0x20000000:
            return limit_bits

        if (
            is_hive(cursor)
            or get_pow_type(cursor) != pow_type
        ):
            cursor -= 1
            continue

        wanted.append((cursor, header))
        cursor -= 1

    # The oldest selected block provides the initial timestamp.
    previous_timestamp = int(wanted[-1][1]["timestamp"])

    weighted_solvetimes = 0
    average_target = 0

    for j, (_, header) in enumerate(reversed(wanted), start=1):
        timestamp = int(header["timestamp"])

        # Reproduce the Core's handling of non-increasing times.
        if timestamp > previous_timestamp:
            adjusted_timestamp = timestamp
        else:
            adjusted_timestamp = previous_timestamp + 1

        solvetime = min(
            6 * T,
            adjusted_timestamp - previous_timestamp,
        )

        previous_timestamp = adjusted_timestamp
        weighted_solvetimes += solvetime * j

        target = bits_to_target(int(header["bits"]))

        # C++ integer divisions are performed sequentially.
        contribution = (target // N) // k
        average_target = (
            average_target + contribution
        ) & UINT256_MASK

    # arith_uint256 arithmetic wraps at 256 bits.
    next_target = (
        average_target * weighted_solvetimes
    ) & UINT256_MASK

    if next_target > pow_limit:
        return limit_bits

    return target_to_bits(next_target)
