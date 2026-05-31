from core.signer import Signer
from core.sighash import Sighash


def sign_transaction(tx, wallet):

    signer = Signer(wallet.get_private_key())
    engine = Sighash()

    signed_inputs = []

    for i, inp in enumerate(tx["inputs"]):

        script_pubkey = b""  # simplificação P2PKH (já OK para teste)

        sighash = engine.create_sighash(
            tx,
            i,
            script_pubkey,
            inp["value"]   # 🔥 FIX IMPORTANTE
        )

        sig = signer.sign(sighash)
        pub = signer.vk.to_string("compressed")

        signed_inputs.append({
            "signature": sig.hex(),
            "pubkey": pub.hex()
        })

    tx["signed_inputs"] = signed_inputs

    return tx
