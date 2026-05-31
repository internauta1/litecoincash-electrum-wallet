import ecdsa
import ecdsa.util


class Signer:

    def __init__(self, private_key_hex):

        self.private_key = bytes.fromhex(
            private_key_hex
        )

        self.sk = ecdsa.SigningKey.from_string(
            self.private_key,
            curve=ecdsa.SECP256k1
        )

        self.vk = self.sk.verifying_key

    # -------------------------
    # SIGN INPUT
    # -------------------------
    def sign_input(self, sighash):

        if isinstance(sighash, str):
            sighash = bytes.fromhex(
                sighash
            )

        signature = self.sk.sign_digest(
            sighash,
            sigencode=ecdsa.util.sigencode_der_canonize
        )

        #
        # SIGHASH_ALL
        #
        signature += b"\x01"

        return signature

    # -------------------------
    # BACKWARD COMPATIBILITY
    # -------------------------
    def sign(self, sighash):

        return self.sign_input(
            sighash
        )

    # -------------------------
    # PUBLIC KEY
    # -------------------------
    def get_public_key(self):

        return (
            b"\x04" +
            self.vk.to_string()
        )
