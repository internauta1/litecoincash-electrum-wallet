from electrum import bitcoin, constants, keystore
from electrum.bip32 import BIP32Node

# BIP39 public test vector. NEVER use with real funds.
MNEMONIC = " ".join(["abandon"] * 11 + ["about"])

VECTORS = [
    (
        "Legacy LCC",
        "m/44'/192'/0'/0/0",
        False,
        "CWFGGU3TpgFkexS46YKSofrTFaUvVJNCvz",
        "29f15f3f42e9bc0851d32cb5fcf550d97a7396b2c22c6255cb0a0cf9e3011e49",
    ),
    (
        "Native SegWit LCC",
        "m/84'/192'/0'/0/0",
        True,
        "lcc1ql8wctcvye87ln80q4gnf5x0z2fl94r0nfz77d7",
        "2402fcb08ffed722934e83bcf34b88e2fa8953177fac2c01031b8e4705ddfc32",
    ),
    (
        "Legacy LCC old derivation",
        "m/44'/2'/0'/0/0",
        False,
        "CRkKuePHqcmHktexeEK5UjKCECcyqZJcKt",
        "3b4211b90e22eda2a6463189ddc79af7e4857462816db0b926d135a4f82f65b7",
    ),
]

assert constants.net.BIP44_COIN_TYPE == 192

seed = keystore.bip39_to_seed(MNEMONIC, passphrase="")
root = BIP32Node.from_rootseed(seed, xtype="standard")

for name, path, is_segwit, expected_addr, expected_hash in VECTORS:
    node = root.subkey_at_private_derivation(path)
    pubkey = node.eckey.get_public_key_bytes(compressed=True)

    address = (
        bitcoin.public_key_to_p2wpkh(pubkey)
        if is_segwit
        else bitcoin.public_key_to_p2pkh(pubkey)
    )

    assert address == expected_addr, name
    assert bitcoin.is_address(address), name
    assert bitcoin.address_to_scripthash(address) == expected_hash, name

    print(f"OK: {name}")

print("LCC ADDRESS COMPATIBILITY TESTS OK")
