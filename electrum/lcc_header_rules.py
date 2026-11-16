"""Litecoin Cash mainnet header classification.

Classification only: this module does NOT verify proof of work,
Hive proofs, difficulty, or consensus validity.
"""

LAST_SCRYPT_BLOCK = 1_371_111
HIVE_ACTIVATION_HEIGHT = 1_564_416
FIRST_HIVE_BLOCK_HEIGHT = 1_565_612
MINOTAURX_ACTIVATION_HEIGHT = 2_540_160

HIVE_NONCE_MARKER = 192
OLD_VERSION_THRESHOLD = 0x20000000

POW_SHA256D = 0
POW_MINOTAURX = 1


def classify_header(height: int, version: int, nonce: int) -> str:
    """Identify the expected header category on historical LCC mainnet."""

    if not (0 <= height and 0 <= version < 2**32
            and 0 <= nonce < 2**32):
        raise ValueError("Invalid header fields")

    if height <= LAST_SCRYPT_BLOCK:
        return "scrypt"

    if height >= HIVE_ACTIVATION_HEIGHT and nonce == HIVE_NONCE_MARKER:
        return "hive"

    if height < MINOTAURX_ACTIVATION_HEIGHT:
        return "sha256d"

    # LCC Core retains a SHA256d path for old-style versions.
    if version >= OLD_VERSION_THRESHOLD:
        return "sha256d"

    pow_type = (version >> 16) & 0xff

    if pow_type == POW_SHA256D:
        return "sha256d"

    if pow_type == POW_MINOTAURX:
        return "minotaurx"

    raise ValueError(f"Unrecognised LCC PoW type: {pow_type}")
