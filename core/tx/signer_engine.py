import hashlib
from core.signer import Signer


SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40


class SigningEngine:

    def __init__(self, wallet):
        self.wallet = wallet

    # -------------------------
    # HASH160 HELP
    # -------------------------
    def hash160(self, data):
        return hashlib.new(
            "ripemd160",
            hashlib.sha256(data).digest()
        ).digest()

    # -------------------------
    # BIP143 HASH (simplificado LCC/BCH style)
    # -------------------------
    def sighash(self, tx, input_index, utxos):

        txin = tx["inputs"][input_index]
        utxo = utxos[input_index]

        # scriptPubKey
        h160 = self.wallet.address_to_pubkeyhash(
            tx["outputs"][0]["address"]
        )

        script_code = (
            b"\x76\xa9\x14" +
            h160 +
            b"\x88\xac"
        )

        # hashPrevouts
        prevouts = b""
        for i in tx["inputs"]:
            prevouts += bytes.fromhex(i["tx_hash"])[::-1]
            prevouts += i["tx_pos"].to_bytes(4, "little")

        hash_prevouts = hashlib.sha256(
            hashlib.sha256(prevouts).digest()
        ).digest()

        # hashSequence
        seq = b""
        for i in tx["inputs"]:
            seq += i.get("sequence", 0xffffffff).to_bytes(4, "little")

        hash_sequence = hashlib.sha256(
            hashlib.sha256(seq).digest()
        ).digest()

        # hashOutputs
        outputs = b""
        for o in tx["outputs"]:
            outputs += int(o["value"]).to_bytes(8, "little")
            outputs += script_code

        hash_outputs = hashlib.sha256(
            hashlib.sha256(outputs).digest()
        ).digest()

        # build sighash preimage
        preimage = b""
        preimage += tx["version"].to_bytes(4, "little")
        preimage += hash_prevouts
        preimage += hash_sequence

        preimage += bytes.fromhex(txin["tx_hash"])[::-1]
        preimage += txin["tx_pos"].to_bytes(4, "little")

        preimage += len(script_code).to_bytes(1, "little")
        preimage += script_code

        preimage += utxo["value"].to_bytes(8, "little")
        preimage += txin.get("sequence", 0xffffffff).to_bytes(4, "little")

        preimage += hash_outputs
        preimage += tx["locktime"].to_bytes(4, "little")
        preimage += (SIGHASH_ALL | SIGHASH_FORKID).to_bytes(4, "little")

        return hashlib.sha256(
            hashlib.sha256(preimage).digest()
        ).digest()

    # -------------------------
    # SIGN ALL INPUTS
    # -------------------------
    def sign_transaction(self, tx, utxos):

        witness = []

        for i in range(len(tx["inputs"])):

            privkey_hex = self.wallet.get_private_key(i)

            signer = Signer(privkey_hex)

            sighash = self.sighash(tx, i, utxos)

            signature = signer.sign(sighash)

            pubkey = signer.get_public_key()

            witness.append({
                "items": [
                    signature,
                    pubkey
                ]
            })

        return witness
