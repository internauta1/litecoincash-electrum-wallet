from core.wallet_core_v1.tx_builder_service import TxBuilderService
from core.wallet_core_v1.raw_decode_service import RawDecodeService
from core.wallet_core_v1.wallet_balance_service import WalletBalanceService


class FinalValidateService:

    def __init__(self):
        self.tx_builder = TxBuilderService()
        self.raw_decode = RawDecodeService()
        self.balance_service = WalletBalanceService()

    def validate_final(self, plan_id: str):
        plan = self.tx_builder.get_plan(plan_id)

        if not plan.get("ok"):
            return plan

        decoded = self.raw_decode.decode_signed_raw(plan_id)

        if not decoded.get("ok"):
            return decoded

        wallet_id = plan["wallet_id"]
        balance = self.balance_service.get_balance(wallet_id)

        if not balance.get("ok"):
            return balance

        plan_input_total = sum(int(i["value"]) for i in plan.get("inputs", []))
        plan_output_total = sum(int(o["value"]) for o in plan.get("outputs", []))
        expected_fee = plan_input_total - plan_output_total

        decoded_output_total = sum(int(o["value"]) for o in decoded.get("outputs", []))

        input_utxos = {
            f'{u["txid"]}:{u["vout"]}': int(u["value"])
            for u in balance.get("utxos", [])
        }

        inputs_exist = True

        for i in plan.get("inputs", []):
            key = f'{i["txid"]}:{i["vout"]}'
            if key not in input_utxos:
                inputs_exist = False

        checks = {
            "plan_exists": True,
            "signed_raw_exists": True,
            "raw_fully_parsed": decoded.get("fully_parsed") is True,
            "inputs_exist_in_wallet_utxo_db": inputs_exist,
            "input_total_matches": plan_input_total == int(plan.get("selected_total", 0)),
            "decoded_outputs_total_matches_plan": decoded_output_total == plan_output_total,
            "fee_matches": expected_fee == int(plan.get("fee_sats", -1)),
            "has_signature_script": all(
                i.get("script_sig_len", 0) > 0
                for i in decoded.get("inputs", [])
            ),
            "outputs_count_matches": decoded.get("outputs_count") == len(plan.get("outputs", [])),
            "inputs_count_matches": decoded.get("inputs_count") == len(plan.get("inputs", [])),
        }

        all_ok = all(checks.values())

        return {
            "ok": all_ok,
            "plan_id": plan_id,
            "wallet_id": wallet_id,
            "amount_lcc": plan.get("amount_lcc"),
            "input_total": plan_input_total,
            "output_total": plan_output_total,
            "fee_sats": expected_fee,
            "change": plan.get("change"),
            "checks": checks,
            "ready_for_broadcast": all_ok,
            "warning": "Se ready_for_broadcast=true, a estrutura local está pronta. Broadcast ainda deve exigir confirmação dupla."
        }
