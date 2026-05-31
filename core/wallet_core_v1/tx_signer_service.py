import json
import hashlib
from pathlib import Path
from datetime import datetime

from ecdsa import SigningKey, VerifyingKey, SECP256k1

from core.wallet_core_v1.wallet_core_service import WalletCoreService
from core.wallet_core_v1.tx_builder_service import TxBuilderService
from core.wallet_core_v1.lcc_address import private_key_for_address


SIGNED_DIR = Path("data/wallet_core/signed_plans")
SIGNED_DIR.mkdir(parents=True, exist_ok=True)


class TxSignerService:

    def inspect_input_keys(self, plan_id: str, password: str):
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

        results = []

        for txin in plan.get("inputs", []):
            address = txin.get("address")

            key_info = private_key_for_address(
                mnemonic_words=seed_phrase,
                target_address=address,
                count=500
            )

            if not key_info.get("ok"):
                results.append({
                    "ok": False,
                    "address": address,
                    "error": key_info.get("error")
                })
                continue

            results.append({
                "ok": True,
                "address": address,
                "txid": txin.get("txid"),
                "vout": txin.get("vout"),
                "value": txin.get("value"),
                "path": key_info.get("path"),
                "public_key": key_info.get("public_key"),
                "private_key_found": True,
                "private_key_hidden": True
            })

        return {
            "ok": True,
            "plan_id": plan_id,
            "wallet_id": wallet_id,
            "inputs_count": len(plan.get("inputs", [])),
            "results": results,
            "warning": "Private keys encontradas, mas ocultas por segurança."
        }

    def __init__(self):
        self.wallet_service = WalletCoreService()
        self.tx_builder = TxBuilderService()

    def verify_signed_plan_dev(self, plan_id: str):
        path = self._signed_path(plan_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "SIGNED_PLAN_NOT_FOUND"
            }

        with open(path, "r", encoding="utf-8") as f:
            signed = json.load(f)

        message_hash = bytes.fromhex(signed["message_hash"])

        results = []

        for sig in signed.get("signatures", []):
            try:
                public_key_hex = sig["public_key"]
                signature = bytes.fromhex(sig["signature"])

                # compressed pubkey -> ecdsa lib não aceita direto
                # nesta fase DEV apenas confirmamos presença/estrutura
                valid_structure = (
                    len(public_key_hex) == 66 and
                    public_key_hex.startswith(("02", "03")) and
                    len(signature) > 40
                )

                results.append({
                    "address": sig.get("address"),
                    "txid": sig.get("txid"),
                    "vout": sig.get("vout"),
                    "path": sig.get("path"),
                    "valid_structure": valid_structure
                })

            except Exception as e:
                results.append({
                    "address": sig.get("address"),
                    "valid_structure": False,
                    "error": str(e)
                })

        return {
            "ok": True,
            "plan_id": plan_id,
            "status": signed.get("status"),
            "message_hash": signed.get("message_hash"),
            "signatures_count": len(signed.get("signatures", [])),
            "results": results,
            "warning": "DEV VERIFY: valida estrutura. Verificação criptográfica completa virá na raw transaction real."
        }

    def _signed_path(self, plan_id: str) -> Path:
        return SIGNED_DIR / f"{plan_id}.signed.json"

    def _canonical_plan_message(self, plan: dict) -> bytes:
        payload = {
            "plan_id": plan.get("plan_id"),
            "wallet_id": plan.get("wallet_id"),
            "inputs": plan.get("inputs", []),
            "outputs": plan.get("outputs", []),
            "fee_sats": plan.get("fee_sats")
        }

        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(raw.encode("utf-8")).digest()

    def sign_plan_dev(self, plan_id: str, password: str):
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

        message_hash = self._canonical_plan_message(plan)

        signatures = []

        for txin in plan.get("inputs", []):
            address = txin.get("address")

            key_info = private_key_for_address(
                mnemonic_words=seed_phrase,
                target_address=address,
                count=500
            )

            if not key_info.get("ok"):
                return {
                    "ok": False,
                    "error": "PRIVATE_KEY_NOT_FOUND_FOR_INPUT",
                    "address": address
                }

            private_key_bytes = bytes.fromhex(key_info["private_key"])

            sk = SigningKey.from_string(
                private_key_bytes,
                curve=SECP256k1
            )

            signature = sk.sign_digest(message_hash)

            signatures.append({
                "address": address,
                "txid": txin.get("txid"),
                "vout": txin.get("vout"),
                "path": key_info["path"],
                "public_key": key_info["public_key"],
                "signature": signature.hex()
            })

        signed = {
            **plan,
            "status": "dev_signed_plan",
            "signed_at": datetime.utcnow().isoformat() + "Z",
            "message_hash": message_hash.hex(),
            "signatures": signatures,
            "warning": "DEV ONLY: assinatura de plano, ainda não é raw transaction válida para broadcast."
        }

        path = self._signed_path(plan_id)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(signed, f, indent=2)

        signed["saved_to"] = str(path)

        return signed
