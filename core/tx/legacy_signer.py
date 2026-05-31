import hashlib
from core.signer import Signer
from core.tx.signing_engine_v2 import SigningEngineV2



class LegacySigner:

    def __init__(self, wallet):

        self.wallet = wallet

        self.serializer = LegacySerializer()

    # -------------------------
    # DOUBLE SHA256
    # -------------------------
    def dsha256(self, b):

        return hashlib.sha256(
            hashlib.sha256(b).digest()
        ).digest()

    # -------------------------
    # BUILD SIGHASH TX
    # -------------------------
    def build_sighash_tx(
        self,
        tx,
        input_index,
        script_pubkey
    ):

        tmp_tx = {
            "version": tx["version"],
            "inputs": [],
            "outputs": tx["outputs"],
            "locktime": tx.get("locktime", 0)
        }

        #
        # INPUTS
        #
        for i, inp in enumerate(tx["inputs"]):

            new_inp = dict(inp)

            #
            # only current input gets scriptPubKey
            #
            if i == input_index:
                new_inp["scriptSig"] = script_pubkey
            else:
                new_inp["scriptSig"] = b""

            tmp_tx["inputs"].append(
                new_inp
            )

        raw = self.serializer.serialize(
            tmp_tx
        )

        #
        # SIGHASH_ALL
        #
        raw += (1).to_bytes(4, "little")

        return raw

    # -------------------------
    # SIGN TX
    # -------------------------
    def sign_transaction(
        self,
        tx
    ):

        #
        # sign every input
        #
        for i, inp in enumerate(tx["inputs"]):

            #
            # derive key index
            #
            key_index = inp.get(
                "key_index",
                0
            )

            #
            # private key
            #
            priv = self.wallet.get_private_key(
                key_index
            )

            signer = Signer(priv)

            #
            # pubkey
            #
            pubkey = signer.get_public_key()

            #
            # scriptPubKey
            #
            addr = self.wallet.get_address(
                key_index
            )

            script_pubkey = (
                self.serializer.p2pkh_script(
                    addr
                )
            )

            #
            # sighash tx
            #
            sighash_tx = self.build_sighash_tx(
                tx,
                i,
                script_pubkey
            )

            #
            # hash
            #
            sighash = self.dsha256(
                sighash_tx
            )

            #
            # signature
            #
            sig = signer.sign_input(
                sighash
            )

            #
            # scriptSig
            #
            script_sig = b""

            #
            # signature push
            #
            script_sig += bytes([
                len(sig)
            ]) + sig

            #
            # pubkey push
            #
            script_sig += bytes([
                len(pubkey)
            ]) + pubkey

            #
            # attach
            #
            inp["scriptSig"] = script_sig

        return tx
