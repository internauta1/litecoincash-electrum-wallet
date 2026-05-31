def p2wpkh_script_code(pubkey_hash: bytes):

    return (
        b"\x76\xa9\x14" +
        pubkey_hash +
        b"\x88\xac"
    )
