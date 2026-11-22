"""Litecoin Cash BCT historical eligibility rules.

Port of the financial and age checks in Core CheckHiveProof().

This module does NOT prove:
- BCT transaction inclusion in an authenticated block;
- validity of the BCT creation script;
- correct extraction of the honey destination;
- authenticity of the historical activation state;
- validity of the surrounding Hive block.

Those checks are mandatory before consensus acceptance.
"""

from dataclasses import dataclass

BEE_GESTATION = 1152
BEE_LIFESPAN = 16128
MIN_BEE_COST = 10000
COMMUNITY_FACTOR = 10
MAX_AMOUNT = (1 << 63) - 1


class BCTError(Exception):
    pass


@dataclass(frozen=True)
class BCTEligibility:
    bct_height: int
    block_height: int
    age: int
    bee_cost: int
    bee_count: int
    total_paid: int
    community_contribution: int


def _amount(value, name):
    if type(value) is not int or not 0 <= value <= MAX_AMOUNT:
        raise BCTError(f"Invalid {name}")
    return value


def expected_community_contribution(
    creation_value,
    donation_value,
    *,
    minotaurx_enabled_at_creation=False,
):
    """Reproduce the Core's historical community amount formula."""
    creation_value = _amount(creation_value, "creation value")
    donation_value = _amount(donation_value, "donation value")

    if type(minotaurx_enabled_at_creation) is not bool:
        raise BCTError("Invalid MinotaurX activation state")

    total = creation_value + donation_value
    if total > MAX_AMOUNT:
        raise BCTError("BCT amount overflow")

    expected = total // COMMUNITY_FACTOR

    if minotaurx_enabled_at_creation:
        expected += expected >> 1

    return expected


def validate_bct_eligibility(
    *,
    block_height,
    bct_height,
    bee_nonce,
    creation_value,
    bee_cost,
    community_contribution=False,
    donation_value=0,
    minotaurx_enabled_at_creation=False,
):
    """Validate BCT age, cost, community amount and bee nonce.

    All arguments must originate from authenticated historical
    consensus data. In particular, bee_cost must be calculated
    independently using Core's GetBeeCost() rules.

    A successful result is NOT sufficient to accept a Hive block.
    """
    for name, value in (
        ("block height", block_height),
        ("BCT height", bct_height),
        ("bee nonce", bee_nonce),
    ):
        if type(value) is not int or value < 0:
            raise BCTError(f"Invalid {name}")

    if bee_nonce > 0xFFFFFFFF:
        raise BCTError("Bee nonce outside uint32")

    if type(community_contribution) is not bool:
        raise BCTError("Invalid community flag")

    if type(minotaurx_enabled_at_creation) is not bool:
        raise BCTError("Invalid activation state")

    creation_value = _amount(creation_value, "creation value")
    donation_value = _amount(donation_value, "donation value")
    bee_cost = _amount(bee_cost, "bee cost")

    if bee_cost < MIN_BEE_COST:
        raise BCTError("Bee cost below consensus minimum")

    age = block_height - bct_height

    if age < BEE_GESTATION:
        raise BCTError("BCT has not matured")

    if age > BEE_GESTATION + BEE_LIFESPAN:
        raise BCTError("BCT has expired")

    if community_contribution:
        expected = expected_community_contribution(
            creation_value,
            donation_value,
            minotaurx_enabled_at_creation=(
                minotaurx_enabled_at_creation
            ),
        )

        if donation_value != expected:
            raise BCTError(
                "Incorrect community contribution: "
                f"{donation_value} != {expected}"
            )

        total_paid = creation_value + donation_value
    else:
        if donation_value != 0:
            raise BCTError(
                "Unexpected donation without community flag"
            )
        total_paid = creation_value

    if total_paid > MAX_AMOUNT:
        raise BCTError("BCT amount overflow")

    if total_paid < MIN_BEE_COST:
        raise BCTError("BCT below minimum bee cost")

    if total_paid < bee_cost:
        raise BCTError("BCT cannot purchase one bee")

    bee_count = total_paid // bee_cost

    if bee_nonce >= bee_count:
        raise BCTError("Bee nonce exceeds BCT bee count")

    return BCTEligibility(
        bct_height=bct_height,
        block_height=block_height,
        age=age,
        bee_cost=bee_cost,
        bee_count=bee_count,
        total_paid=total_paid,
        community_contribution=(
            donation_value if community_contribution else 0
        ),
    )


# LCC_BCT_CORE_SUBSIDY_AND_SCRIPTS_V1
# Mainnet rules from Litecoin Cash Core validation.cpp
# and script/script.h.

COIN = 10_000_000
COIN_SCALE = 10
HALVING_INTERVAL = 840_000
LAST_SCRYPT_BLOCK = 1_371_111
SLOW_START_BLOCKS = 2_000
PREMINE_AMOUNT = 550_000
TOTAL_MONEY_SUPPLY_HEIGHT = 6_215_968
BEE_COST_FACTOR = 2_500


def block_subsidy(height):
    """Reproduce mainnet Core GetBlockSubsidy()."""
    if type(height) is not int or height < 0:
        raise BCTError("Invalid block height")

    if height == LAST_SCRYPT_BLOCK + 1:
        return PREMINE_AMOUNT * COIN * COIN_SCALE

    halvings = height // HALVING_INTERVAL

    if halvings >= 64 or height >= TOTAL_MONEY_SUPPLY_HEIGHT:
        return 0

    subsidy = 50 * COIN * COIN_SCALE
    subsidy >>= halvings

    since_fork = height - LAST_SCRYPT_BLOCK

    if 0 < since_fork < SLOW_START_BLOCKS:
        increment = subsidy // SLOW_START_BLOCKS
        subsidy = since_fork * increment

    return subsidy


def bee_cost_at_height(height):
    """Reproduce mainnet Core GetBeeCost()."""
    if type(height) is not int or height < 0:
        raise BCTError("Invalid BCT height")

    if height >= TOTAL_MONEY_SUPPLY_HEIGHT:
        return MIN_BEE_COST

    cost = block_subsidy(height) // BEE_COST_FACTOR
    return max(cost, MIN_BEE_COST)


def extract_bct_honey_hash160(script, bee_creation_prefix):
    """Validate Core IsBCTScript layout and P2PKH honey destination.

    bee_creation_prefix must be the verified 25-byte
    scriptPubKey of the mainnet bee creation address.

    Returns the 20-byte honey public-key hash.

    This checks script structure, not historical inclusion.
    """
    if not isinstance(script, bytes):
        raise BCTError("Invalid BCT script type")

    if (not isinstance(bee_creation_prefix, bytes)
            or len(bee_creation_prefix) != 25):
        raise BCTError("Invalid bee creation prefix")

    if len(script) != 52:
        raise BCTError("Invalid BCT script length")

    if script[:25] != bee_creation_prefix:
        raise BCTError("Incorrect bee creation destination")

    # OP_RETURN, OP_BEE
    if script[25:27] != bytes.fromhex("6abe"):
        raise BCTError("Missing BCT delimiter")

    honey_script = script[27:52]

    # Legacy P2PKH: DUP HASH160 PUSH20 <hash> EQUALVERIFY CHECKSIG
    if (honey_script[:3] != bytes.fromhex("76a914")
            or honey_script[23:25] != bytes.fromhex("88ac")):
        raise BCTError("Invalid honey P2PKH script")

    return honey_script[3:23]


def verify_bct_honey(
    script,
    bee_creation_prefix,
    expected_honey_hash160,
):
    """Check that the BCT and Hive reward address agree."""
    if (not isinstance(expected_honey_hash160, bytes)
            or len(expected_honey_hash160) != 20):
        raise BCTError("Invalid expected honey hash160")

    actual = extract_bct_honey_hash160(
        script, bee_creation_prefix
    )

    if actual != expected_honey_hash160:
        raise BCTError("BCT honey address mismatch")

    return True


# LCC_BCT_TRANSACTION_VALIDATION_V1

def validate_bct_transaction(
    *,
    transaction,
    block_height,
    bct_height,
    bee_nonce,
    expected_honey_hash160,
    bee_creation_prefix,
    community_script,
    community_contribution,
    minotaurx_enabled_at_creation,
):
    """Validate BCT outputs and eligibility.

    The transaction's identity, inclusion proof, block height
    and historical branch MUST already be authenticated.

    This function does not authenticate transaction inclusion.
    """
    outputs = transaction.outputs()

    if not outputs:
        raise BCTError("BCT has no outputs")

    creation = outputs[0]
    creation_script = bytes(creation.scriptpubkey)

    verify_bct_honey(
        creation_script,
        bee_creation_prefix,
        expected_honey_hash160,
    )

    donation_value = 0

    if community_contribution:
        if len(outputs) < 2:
            raise BCTError("Missing community output")

        donation = outputs[1]

        if bytes(donation.scriptpubkey) != community_script:
            raise BCTError("Incorrect community destination")

        donation_value = donation.value

    return validate_bct_eligibility(
        block_height=block_height,
        bct_height=bct_height,
        bee_nonce=bee_nonce,
        creation_value=creation.value,
        bee_cost=bee_cost_at_height(bct_height),
        community_contribution=community_contribution,
        donation_value=donation_value,
        minotaurx_enabled_at_creation=(
            minotaurx_enabled_at_creation
        ),
    )


# LCC_BCT_MAINNET_INTEGRATION_V1

def validate_mainnet_bct(
    *,
    transaction,
    block_height,
    bct_height,
    bee_nonce,
    expected_honey_hash160,
    community_contribution,
    minotaurx_enabled_at_creation,
):
    """Apply mainnet BCT consensus parameters.

    The caller must separately authenticate:
      - transaction TXID and historical Merkle inclusion
      - the header's consensus-valid chain
      - BIP9 activation state at BCT creation
      - the claimed Hive block and its proof

    No server-supplied consensus parameters are accepted.
    """
    from .lcc_mainnet import (
        bee_creation_script,
        community_script,
    )

    return validate_bct_transaction(
        transaction=transaction,
        block_height=block_height,
        bct_height=bct_height,
        bee_nonce=bee_nonce,
        expected_honey_hash160=expected_honey_hash160,
        bee_creation_prefix=bee_creation_script(),
        community_script=community_script(),
        community_contribution=community_contribution,
        minotaurx_enabled_at_creation=(
            minotaurx_enabled_at_creation
        ),
    )
