"""Litecoin Cash BIP9 activation state calculation.

Pure header-based logic. Does not authenticate supplied headers.
"""

from dataclasses import dataclass
from enum import Enum


WINDOW = 8064
THRESHOLD = 6048
POW_FORK_TIME = 1518982404

TOP_MASK = 0xE0000000
TOP_BITS = 0x20000000


class State(str, Enum):
    DEFINED = "defined"
    STARTED = "started"
    LOCKED_IN = "locked_in"
    ACTIVE = "active"
    FAILED = "failed"


@dataclass(frozen=True)
class Deployment:
    bit: int
    start: int
    timeout: int


HIVE = Deployment(7, 1545782400, 1577318400)
HIVE_1_1 = Deployment(9, 1568937600, 1600560000)
MINOTAURX = Deployment(7, 1631793600, 1663329600)


def median_time_past(height, get_header):
    """Median timestamp of this block and up to ten ancestors."""
    if height < 0:
        raise ValueError("negative height")

    timestamps = []
    for h in range(max(0, height - 10), height + 1):
        header = get_header(h)
        if header is None:
            raise ValueError(f"missing header {h}")
        timestamps.append(int(header["timestamp"]))

    timestamps.sort()
    return timestamps[len(timestamps) // 2]


def signals(header, bit, fork_time=POW_FORK_TIME):
    version = int(header["version"])
    timestamp = int(header["timestamp"])
    mask = 1 << bit

    if timestamp > fork_time:
        return bool(version & mask)

    return (
        (version & TOP_MASK) == TOP_BITS
        and bool(version & mask)
    )


def state_for_height(
    height,
    get_header,
    deployment,
    *,
    period=WINDOW,
    threshold=THRESHOLD,
    fork_time=POW_FORK_TIME,
):
    """BIP9 state applicable to block at 'height'.

    get_header must supply the correct historical branch.
    """
    if height < 0:
        raise ValueError("negative height")
    if period <= 0 or not 0 < threshold <= period:
        raise ValueError("invalid period or threshold")

    state = State.DEFINED

    # State transitions only occur at period boundaries.
    for period_start in range(period, height + 1, period):
        previous_end = period_start - 1
        mtp = median_time_past(previous_end, get_header)

        if state == State.DEFINED:
            if mtp >= deployment.timeout:
                state = State.FAILED
            elif mtp >= deployment.start:
                state = State.STARTED

        elif state == State.STARTED:
            if mtp >= deployment.timeout:
                state = State.FAILED
            else:
                count = 0
                for h in range(period_start - period, period_start):
                    header = get_header(h)
                    if header is None:
                        raise ValueError(f"missing header {h}")
                    if signals(header, deployment.bit, fork_time):
                        count += 1

                if count >= threshold:
                    state = State.LOCKED_IN

        elif state == State.LOCKED_IN:
            state = State.ACTIVE

    return state


# LCC_BRANCH_AWARE_BIP9_CACHE_V1

_BIP9_STATE_CACHE = {}


def cached_state_for_height(
    height,
    get_header,
    deployment,
    *,
    period=WINDOW,
    threshold=THRESHOLD,
    fork_time=POW_FORK_TIME,
):
    """BIP9 with branch-specific, period-boundary caching.

    Uses the hash of the previous period's final header as
    the branch identity. Missing headers fail closed.

    This returns the state applicable to the candidate block
    at 'height', not the state for its predecessor.
    """
    from .blockchain import hash_header

    if type(height) is not int or height < 0:
        raise ValueError("invalid BIP9 height")

    if period <= 0 or not 0 < threshold <= period:
        raise ValueError("invalid BIP9 period or threshold")

    def state_at_boundary(start):
        if start == 0:
            return State.DEFINED

        previous_end = start - 1
        header = get_header(previous_end)

        if header is None:
            raise ValueError(
                f"missing BIP9 boundary header {previous_end}"
            )

        boundary_hash = hash_header(header)

        key = (
            deployment.bit,
            deployment.start,
            deployment.timeout,
            period,
            threshold,
            fork_time,
            boundary_hash,
        )

        cached = _BIP9_STATE_CACHE.get(key)

        if cached is not None:
            return cached

        prior = state_at_boundary(start - period)
        mtp = median_time_past(previous_end, get_header)

        if prior == State.DEFINED:
            if mtp >= deployment.timeout:
                state = State.FAILED
            elif mtp >= deployment.start:
                state = State.STARTED
            else:
                state = State.DEFINED

        elif prior == State.STARTED:
            if mtp >= deployment.timeout:
                state = State.FAILED
            else:
                count = 0

                for h in range(start - period, start):
                    voting_header = get_header(h)

                    if voting_header is None:
                        raise ValueError(
                            f"missing BIP9 voting header {h}"
                        )

                    if signals(
                        voting_header,
                        deployment.bit,
                        fork_time,
                    ):
                        count += 1

                state = (
                    State.LOCKED_IN
                    if count >= threshold
                    else State.STARTED
                )

        elif prior == State.LOCKED_IN:
            state = State.ACTIVE

        else:
            state = prior

        # Bound memory usage without sacrificing branch safety.
        if len(_BIP9_STATE_CACHE) >= 4096:
            _BIP9_STATE_CACHE.clear()

        _BIP9_STATE_CACHE[key] = state
        return state

    boundary = (height // period) * period
    return state_at_boundary(boundary)
