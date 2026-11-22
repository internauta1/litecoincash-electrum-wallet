
"""Mainnet post-MinotaurX PoW verification.

Standalone consensus component. Does not authorize storing
a header, reorganizing a chain, or enabling wallet sync.
"""

from .lcc_bip9 import State, cached_state_for_height
from .lcc_chainwork import bits_to_target
from .lcc_header_rules import classify_header
from .lcc_lwma import next_lwma_bits
from .lcc_mainnet import mainnet_bip9_deployments


MINOTAURX_ACTIVATION_HEIGHT = 2540160

POW_LIMITS = {
    "sha256d": int("00000000" + "f" * 56, 16),
    "minotaurx": int("000" + "f" * 61, 16),
}


class PostForkPoWError(ValueError):
    pass


def verify_postfork_pow_header(
    *,
    candidate_header,
    get_header,
):
    """Check BIP9, ancestry, LWMA nBits and actual PoW.

    get_header must read from the selected, previously
    validated chain. The caller is responsible for
    establishing that history's validity.
    """
    from . import constants
    from .blockchain import Blockchain, hash_header

    if constants.net.TESTNET:
        raise PostForkPoWError("Mainnet only")

    if not isinstance(candidate_header, dict):
        raise PostForkPoWError("Invalid candidate header")

    if not callable(get_header):
        raise PostForkPoWError("Invalid history provider")

    fields = (
        "block_height",
        "version",
        "nonce",
        "bits",
        "timestamp",
    )

    if any(
        type(candidate_header.get(key)) is not int
        for key in fields
    ):
        raise PostForkPoWError("Invalid candidate fields")

    height = candidate_header["block_height"]

    if height < MINOTAURX_ACTIVATION_HEIGHT:
        raise PostForkPoWError("Before MinotaurX activation")

    previous = get_header(height - 1)

    if (
        not isinstance(previous, dict)
        or previous.get("block_height") != height - 1
    ):
        raise PostForkPoWError("Missing previous header")

    previous_hash = hash_header(previous)

    if candidate_header.get("prev_block_hash") != previous_hash:
        raise PostForkPoWError("Previous block hash mismatch")

    deployments = mainnet_bip9_deployments()

    state = cached_state_for_height(
        height,
        get_header,
        deployments["minotaurx"],
    )

    if state != State.ACTIVE:
        raise PostForkPoWError(
            "MinotaurX BIP9 is not ACTIVE"
        )

    algorithm = classify_header(
        height,
        candidate_header["version"],
        candidate_header["nonce"],
    )

    if algorithm not in POW_LIMITS:
        raise PostForkPoWError(
            f"Unsupported PoW type: {algorithm}"
        )

    def get_pow_type(h):
        item = get_header(h)

        if not isinstance(item, dict):
            raise PostForkPoWError(
                f"Missing historical header {h}"
            )

        return classify_header(
            h,
            item["version"],
            item["nonce"],
        )

    def is_hive(h):
        return get_pow_type(h) == "hive"

    expected_bits = next_lwma_bits(
        prev_height=height - 1,
        pow_type=algorithm,
        pow_limit=POW_LIMITS[algorithm],
        get_header=get_header,
        is_hive=is_hive,
        get_pow_type=get_pow_type,
    )

    if candidate_header["bits"] != expected_bits:
        raise PostForkPoWError(
            "LWMA difficulty mismatch"
        )

    # This existing method independently checks:
    # parent hash, nBits and the real algorithm's PoW.
    Blockchain.verify_header(
        candidate_header,
        previous_hash,
        bits_to_target(expected_bits),
    )

    return {
        "height": height,
        "algorithm": algorithm,
        "expected_bits": expected_bits,
        "bip9_active": True,
        "pow_verified": True,
        "consensus_validated": False,
    }
