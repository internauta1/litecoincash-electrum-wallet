import json
import secrets
from pathlib import Path
from datetime import datetime

from core.wallet_core_v1.wallet_balance_service import WalletBalanceService
from core.wallet_core_v1.lcc_network import LCC_SATOSHI


TX_PLAN_DIR = Path("data/wallet_core/tx_plans")
TX_PLAN_DIR.mkdir(parents=True, exist_ok=True)


class TxBuilderService:

    def __init__(self):
        self.balance_service = WalletBalanceService()

    def _plan_path(self, plan_id: str) -> Path:
        return TX_PLAN_DIR / f"{plan_id}.json"

    def prepare_send(
        self,
        wallet_id: str,
        to_address: str,
        amount_lcc: float,
        fee_sats: int = 10000,
        save: bool = True
    ):
        if amount_lcc <= 0:
            return {
                "ok": False,
                "error": "INVALID_AMOUNT"
            }

        if fee_sats < 0:
            return {
                "ok": False,
                "error": "INVALID_FEE"
            }

        amount_sats = int(amount_lcc * LCC_SATOSHI)

        balance = self.balance_service.get_balance(wallet_id)

        if not balance.get("ok"):
            return balance

        all_utxos = balance.get("utxos", [])

        spendable_utxos = [
            u for u in all_utxos
            if not str(u.get("address", "")).lower().startswith("lcc1")
        ]

        total_balance = sum(int(u.get("value", 0)) for u in spendable_utxos)
        segwit_locked_balance = sum(
            int(u.get("value", 0))
            for u in all_utxos
            if str(u.get("address", "")).lower().startswith("lcc1")
        )

        needed = amount_sats + fee_sats

        if total_balance < needed:
            return {
                "ok": False,
                "error": "INSUFFICIENT_SPENDABLE_FUNDS",
                "total_spendable_balance": total_balance,
                "segwit_locked_balance": segwit_locked_balance,
                "needed": needed,
                "missing": needed - total_balance,
                "unit": "satoshis",
                "message": "Spending from lcc1 UTXOs is not yet enabled. Legacy C... UTXOs are spendable."
            }

        selected = []
        selected_total = 0

        for utxo in spendable_utxos:
            selected.append(utxo)
            selected_total += int(utxo["value"])

            if selected_total >= needed:
                break

        change = selected_total - needed

        outputs = [
            {
                "address": to_address,
                "value": amount_sats,
                "type": "payment"
            }
        ]

        if change > 0:
            receive = self.balance_service.get_receive_address(wallet_id)

            if not receive.get("ok"):
                return receive

            outputs.append({
                "address": receive["receive_address"],
                "value": change,
                "type": "change"
            })

        plan_id = secrets.token_hex(12)

        plan = {
            "ok": True,
            "plan_id": plan_id,
            "wallet_id": wallet_id,
            "status": "unsigned_plan",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "amount_lcc": amount_lcc,
            "amount_sats": amount_sats,
            "fee_sats": fee_sats,
            "selected_utxos_count": len(selected),
            "selected_total": selected_total,
            "change": change,
            "inputs": selected,
            "outputs": outputs,
            "warning": "UNSIGNED ONLY: plano de transação. Ainda não assina nem transmite."
        }

        if save:
            path = self._plan_path(plan_id)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(plan, f, indent=2)

            plan["saved_to"] = str(path)

        return plan

    def list_plans(self):
        plans = []

        for path in TX_PLAN_DIR.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                plans.append({
                    "plan_id": data.get("plan_id"),
                    "wallet_id": data.get("wallet_id"),
                    "status": data.get("status"),
                    "created_at": data.get("created_at"),
                    "amount_lcc": data.get("amount_lcc"),
                    "fee_sats": data.get("fee_sats"),
                    "selected_utxos_count": data.get("selected_utxos_count"),
                    "change": data.get("change")
                })

            except Exception:
                continue

        return {
            "ok": True,
            "plans": plans
        }

    def get_plan(self, plan_id: str):
        path = self._plan_path(plan_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "PLAN_NOT_FOUND"
            }

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
