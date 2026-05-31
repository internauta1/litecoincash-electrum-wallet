from core.signer import Signer
from core.tx.bip143 import BIP143


class SigningEngineV2:

    def __init__(self, wallet):

        self.wallet = wallet

        self.bip143 = BIP143()

    #
    # SIGN TX
    #
    def sign_transaction(
        self,
        tx,
        utxos
    ):

        witnesses = []

        for i in range(len(tx["inputs"])):

            inp = tx["inputs"][i]

            utxo = utxos[i]

            key_index = utxo.get(
                "key_index",
                0
            )

            #
            # PRIVATE KEY
            #
            privkey = self.wallet.get_private_key(
                key_index
            )

            signer = Signer(privkey)

            #
            # REAL BIP143 HASH
            #
            sighash = self.bip143.sighash(
                tx,
                i,
                utxo
            )

            #
            # SIGNATURE
            #
            signature = signer.sign(
                sighash
            )

            #
            # PUBLIC KEY
            #
            pubkey = signer.get_public_key()

            #
            # WITNESS STACK
            #
            witnesses.append({
                "items": [
                    signature,
                    pubkey
                ]
            })

        return witnesses
