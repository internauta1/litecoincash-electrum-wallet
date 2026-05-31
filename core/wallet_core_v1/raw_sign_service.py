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
        signatures = []

        for idx, txin in enumerate(plan.get("inputs", [])):
            if str(txin.get("address", "")).lower().startswith("lcc1"):
                return {
                    "ok": False,
                    "error": "UNSUPPORTED_INPUT_ADDRESS_FORMAT",
                    "message": "Assinatura de inputs lcc1 ainda não está ativa neste core. Outputs lcc1 são suportados.",
                    "address": txin.get("address")
                }

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
            script_sig = push_data(sig_der) + push_data(pubkey)

            scripts.append(script_sig)

            signatures.append({
                "input_index": idx,
                "address": txin["address"],
                "path": key_info["path"],
                "public_key": key_info["public_key"],
                "sighash": sighash.hex(),
                "signature_der_plus_hashtype": sig_der.hex()
            })

        signed_raw = self._serialize_signed_tx(plan, scripts)
        raw_hex = signed_raw.hex()

        path = self._signed_raw_path(plan_id)

        with open(path, "w", encoding="utf-8") as f:
            f.write(raw_hex)

        return {
            "ok": True,
            "plan_id": plan_id,
            "status": "signed_raw",
            "raw_hex_signed": raw_hex,
            "raw_hex_signed": raw_hex,
            "inputs_signed": len(scripts),
            "signatures": signatures,
            "saved_to": str(path),
            "warning": "Raw transaction assinada. Faça validate-final antes de broadcast."
        }
