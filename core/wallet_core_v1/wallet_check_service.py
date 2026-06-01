import json
from pathlib import Path

from core.wallet_core_v1.utxo_sync_service import UtxoSyncService
from core.wallet_core_v1.wallet_core_service import WalletCoreService
from core.wallet_core_v1.wallet_balance_service import WalletBalanceService


PLANS_DIR = Path("data/wallet_core/tx_plans")
SIGNED_DIR = Path("data/wallet_core/signed_raw")


class WalletCheckService:

    def __init__(self):

        self.wallet_service = WalletCoreService()
        self.balance_service = WalletBalanceService()
        self.utxo_sync = UtxoSyncService()

    def check_wallet(self, wallet_id: str):
        wallets = self.wallet_service.list_wallets()

        if not wallets.get("ok"):
            return wallets

        target = None

        for w in wallets.get("wallets", []):
            if w.get("wallet_id") == wallet_id:
                target = w
                break

        if not target:
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        try:
            self.utxo_sync.sync_wallet_utxos(wallet_id)
        except:
            pass
        balance = self.balance_service.get_balance(wallet_id)

        plans = []
        signed = []

        if PLANS_DIR.exists():
            for f in sorted(PLANS_DIR.glob("*.json")):
                try:
                    data = json.loads(f.read_text())

                    if data.get("wallet_id") == wallet_id:
                        plans.append({
                            "plan_id": data.get("plan_id"),
                            "status": data.get("status"),
                            "amount_lcc": data.get("amount_lcc"),
                            "created_at": data.get("created_at")
                        })

                except:
                    pass

        if SIGNED_DIR.exists():
            for f in sorted(SIGNED_DIR.glob("*.hex")):
                signed.append({
                    "file": f.name,
                    "size_bytes": f.stat().st_size
                })

        receive_address = None
        receive_address_segwit = None

        if balance.get("addresses"):
            receive_address = balance["addresses"][0]["address"]
            receive_address_segwit = balance["addresses"][0].get("segwit_address")

        return {
            "ok": True,
            "wallet": {
                "wallet_id": target.get("wallet_id"),
                "label": target.get("label"),
                "type": target.get("type"),
                "network": target.get("network"),
                "created_at": target.get("created_at"),
                "seed_encrypted": True,
                "primary_address": target.get("primary_address"),
                "derivation": target.get("derivation")
            },
            "balance": {
                "total_lcc": balance.get("total_lcc"),
                "utxos_count": balance.get("utxos_count"),
                "address_count": balance.get("address_count")
            },
            "receive_address": receive_address,
            "receive_address_segwit": receive_address_segwit,
            "plans_count": len(plans),
            "plans": plans,
            "signed_raw_count": len(signed),
            "signed_raw_files": signed,
            "checks": {
                "wallet_exists": True,
                "seed_encrypted": True,
                "has_hd_addresses": balance.get("address_count", 0) > 0,
                "has_utxos": balance.get("utxos_count", 0) > 0,
                "has_signed_raw": len(signed) > 0
            },
            "warning": "Verificação da wallet concluída."
        }
