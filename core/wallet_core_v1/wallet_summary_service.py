from core.wallet_core_v1.wallet_balance_service import WalletBalanceService
from core.wallet_core_v1.wallet_history_detail_service import WalletHistoryDetailService


class WalletSummaryService:

    def __init__(self):
        self.balance_service = WalletBalanceService()
        self.history_service = WalletHistoryDetailService()

    def get_summary(self, wallet_id: str):
        balance = self.balance_service.get_balance(wallet_id)

        if not balance.get("ok"):
            return balance

        history = self.history_service.get_detail(wallet_id)

        if not history.get("ok"):
            return history

        total_received = 0
        total_sent = 0
        total_fees = 0

        last_tx = None

        transactions = history.get("transactions", [])

        for tx in transactions:
            tx_type = tx.get("type")

            if tx_type == "RECEIVED":
                total_received += int(tx.get("received", 0))

            if tx_type in ("SENT", "SENT_WITH_CHANGE"):
                total_sent += int(tx.get("sent_external", 0))
                total_fees += int(tx.get("fee") or 0)

        if transactions:
            last_tx = transactions[0]

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "label": balance.get("label"),
            "balance": {
                "confirmed": balance.get("total_balance"),
                "confirmed_lcc": balance.get("total_lcc"),
                "utxos_count": balance.get("utxos_count"),
                "address_count": balance.get("address_count")
            },
            "activity": {
                "transactions_count": len(transactions),
                "total_received": total_received,
                "total_received_lcc": total_received / 10000000,
                "total_sent": total_sent,
                "total_sent_lcc": total_sent / 10000000,
                "total_fees": total_fees,
                "total_fees_lcc": total_fees / 10000000
            },
            "last_transaction": last_tx
        }
