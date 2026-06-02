import hashlib
from pathlib import Path

from ecdsa import SigningKey, SECP256k1, util

from core.wallet_core_v1.tx_builder_service import TxBuilderService
from core.wallet_core_v1.wallet_core_service import WalletCoreService
from core.wallet_core_v1.lcc_address import private_key_for_address
from core.wallet_core_v1.raw_tx_service import (
    int_to_le,
    encode_varint,
    push_data,
    p2pkh_script_pubkey,
    script_pubkey_for_address
)
from core.bech32 import decode_segwit_address


SIGNED_RAW_DIR = Path("data/wallet_core/signed_raw")
SIGNED_RAW_DIR.mkdir(parents=True, exist_ok=True)

SIGHASH_ALL = 0x01
SIGHASH_FORKID = 0x40
SIGHASH_ALL_FORKID = SIGHASH_ALL | SIGHASH_FORKID


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class RawSignService:

    def __init__(self):
        self.tx_builder = TxBuilderService()
        self.wallet_service = WalletCoreService()

    def _signed_raw_path(self, plan_id: str) -> Path:
        return SIGNED_RAW_DIR / f"{plan_id}.signed.hex"

    def _serialize_tx_for_sig(self, plan: dict, input_index: int) -> bytes:
        version = int_to_le(1, 4)
        locktime = int_to_le(0, 4)

        inputs = plan.get("inputs", [])
        outputs = plan.get("outputs", [])

        raw = bytearray()
        raw += version
        raw += encode_varint(len(inputs))

        for idx, txin in enumerate(inputs):
            txid = bytes.fromhex(txin["txid"])[::-1]
            vout = int_to_le(int(txin["vout"]), 4)

            if idx == input_index:
                script_sig = p2pkh_script_pubkey(txin["address"])
            else:
                script_sig = b""

            sequence = bytes.fromhex("ffffffff")

            raw += txid
            raw += vout
            raw += encode_varint(len(script_sig))
            raw += script_sig
            raw += sequence

        raw += encode_varint(len(outputs))

        for txout in outputs:
            value = int_to_le(int(txout["value"]), 8)
            script_pubkey = script_pubkey_for_address(txout["address"])

            raw += value
            raw += encode_varint(len(script_pubkey))
            raw += script_pubkey

        raw += locktime
        raw += int_to_le(SIGHASH_ALL_FORKID, 4)

        return bytes(raw)

    def _serialize_signed_tx(self, plan: dict, scripts: list) -> bytes:
        version = int_to_le(1, 4)
        locktime = int_to_le(0, 4)

        inputs = plan.get("inputs", [])
        outputs = plan.get("outputs", [])

        raw = bytearray()
        raw += version
        raw += encode_varint(len(inputs))

        for idx, txin in enumerate(inputs):
            txid = bytes.fromhex(txin["txid"])[::-1]
            vout = int_to_le(int(txin["vout"]), 4)
            script_sig = scripts[idx]
            sequence = bytes.fromhex("ffffffff")

            raw += txid
            raw += vout
            raw += encode_varint(len(script_sig))
            raw += script_sig
            raw += sequence

        raw += encode_varint(len(outputs))

        for txout in outputs:
            value = int_to_le(int(txout["value"]), 8)
            script_pubkey = script_pubkey_for_address(txout["address"])

            raw += value
            raw += encode_varint(len(script_pubkey))
            raw += script_pubkey

        raw += locktime

        return bytes(raw)

    def _script_code_p2wpkh(self, address: str) -> bytes:
        h160 = decode_segwit_address(address)

        return (
            b"\x76" +
            b"\xa9" +
            b"\x14" +
            h160 +
            b"\x88" +
            b"\xac"
        )

    def _hash_prevouts(self, inputs: list) -> bytes:
        data = bytearray()

        for txin in inputs:
            data += bytes.fromhex(txin["txid"])[::-1]
            data += int_to_le(int(txin["vout"]), 4)

        return double_sha256(bytes(data))

    def _hash_sequence(self, inputs: list) -> bytes:
        data = bytearray()

        for _ in inputs:
            data += bytes.fromhex("ffffffff")

        return double_sha256(bytes(data))

    def _hash_outputs(self, outputs: list) -> bytes:
        data = bytearray()

        for txout in outputs:
            value = int_to_le(int(txout["value"]), 8)
            script_pubkey = script_pubkey_for_address(txout["address"])

            data += value
            data += encode_varint(len(script_pubkey))
            data += script_pubkey

        return double_sha256(bytes(data))

    def _serialize_segwit_sig_hash(self, plan: dict, input_index: int) -> bytes:
        version = int_to_le(1, 4)
        locktime = int_to_le(0, 4)

        inputs = plan.get("inputs", [])
        outputs = plan.get("outputs", [])
        txin = inputs[input_index]

        preimage = bytearray()
        preimage += version
        preimage += self._hash_prevouts(inputs)
        preimage += self._hash_sequence(inputs)
        preimage += bytes.fromhex(txin["txid"])[::-1]
        preimage += int_to_le(int(txin["vout"]), 4)

        script_code = self._script_code_p2wpkh(txin["address"])
        preimage += encode_varint(len(script_code))
        preimage += script_code

        preimage += int_to_le(int(txin["value"]), 8)
        preimage += bytes.fromhex("ffffffff")
        preimage += self._hash_outputs(outputs)
        preimage += locktime
        preimage += int_to_le(SIGHASH_ALL_FORKID, 4)

        return bytes(preimage)

    def _serialize_signed_tx_with_witness(
        self,
        plan: dict,
        scripts: list,
        witnesses: list
    ) -> bytes:
        version = int_to_le(1, 4)
        locktime = int_to_le(0, 4)

        inputs = plan.get("inputs", [])
        outputs = plan.get("outputs", [])

        has_witness = any(w for w in witnesses)

        raw = bytearray()
        raw += version

        if has_witness:
            raw += b"\x00\x01"

        raw += encode_varint(len(inputs))

        for idx, txin in enumerate(inputs):
            txid = bytes.fromhex(txin["txid"])[::-1]
            vout = int_to_le(int(txin["vout"]), 4)
            script_sig = scripts[idx]
            sequence = bytes.fromhex("ffffffff")

            raw += txid
            raw += vout
            raw += encode_varint(len(script_sig))
            raw += script_sig
            raw += sequence

        raw += encode_varint(len(outputs))

        for txout in outputs:
            value = int_to_le(int(txout["value"]), 8)
            script_pubkey = script_pubkey_for_address(txout["address"])

            raw += value
            raw += encode_varint(len(script_pubkey))
            raw += script_pubkey

        if has_witness:
            for witness in witnesses:
                raw += encode_varint(len(witness))

                for item in witness:
                    raw += encode_varint(len(item))
                    raw += item

        raw += locktime

        return bytes(raw)

    def sign_raw(self, plan_id: str, password: str):
        plan = self.tx_builder.get_plan(plan_id)

        if not plan.get("ok"):
            return plan

        wallet_id = plan.get("wallet_id")

        exported = self.wallet_service.export_seed(
            wallet_id=wallet_id,
            password=password
        )

        if not exported.get("ok"):
            return exported

        seed_phrase = exported["seed_phrase"]

        scripts = []
        witnesses = []
        signatures = []

        for idx, txin in enumerate(plan.get("inputs", [])):
            is_segwit = str(txin.get("address", "")).lower().startswith("lcc1")

            key_info = private_key_for_address(
                mnemonic_words=seed_phrase,
                target_address=txin["address"],
                count=500
            )

            if not key_info.get("ok"):
                return {
                    "ok": False,
                    "error": "PRIVATE_KEY_NOT_FOUND_FOR_INPUT",
                    "address": txin["address"]
                }

            if is_segwit:
                preimage = self._serialize_segwit_sig_hash(plan, idx)
            else:
                preimage = self._serialize_tx_for_sig(plan, idx)

            sighash = double_sha256(preimage)

            sk = SigningKey.from_string(
                bytes.fromhex(key_info["private_key"]),
                curve=SECP256k1
            )

            sig_der = sk.sign_digest(
                sighash,
                sigencode=util.sigencode_der_canonize
            ) + bytes([SIGHASH_ALL_FORKID])

            pubkey = bytes.fromhex(key_info["public_key"])

            if is_segwit:
                scripts.append(b"")
                witnesses.append([sig_der, pubkey])
            else:
                scripts.append(push_data(sig_der) + push_data(pubkey))
                witnesses.append([])

            signatures.append({
                "input_index": idx,
                "address": txin["address"],
                "type": "p2wpkh" if is_segwit else "p2pkh",
                "path": key_info["path"],
                "public_key": key_info["public_key"],
                "sighash": sighash.hex(),
                "signature_der_plus_hashtype": sig_der.hex()
            })

        signed_raw = self._serialize_signed_tx_with_witness(
            plan,
            scripts,
            witnesses
        )
        raw_hex = signed_raw.hex()

        path = self._signed_raw_path(plan_id)

        with open(path, "w", encoding="utf-8") as f:
            f.write(raw_hex)

        return {
            "ok": True,
            "plan_id": plan_id,
            "status": "signed_raw",
            "raw_hex_signed": raw_hex,
            "inputs_signed": len(scripts),
            "witness_inputs": sum(1 for w in witnesses if w),
            "signatures": signatures,
            "saved_to": str(path),
            "warning": "Raw transaction assinada. Faça validate-final antes de broadcast."
        }
