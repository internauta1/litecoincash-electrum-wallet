import json
import sqlite3
import time
from pathlib import Path

from core.wallet_core_v1.tx_builder_service import TxBuilderService


UTXO_DB = Path("data/utxo.db")
WALLET_DIR = Path("data/wallet_core")


class UtxoUpdateService:

    def __init__(self):
        self.tx_builder = TxBuilderService()

    def _wallet_path(self, wallet_id: str) -> Path:
        return WALLET_DIR / f"{wallet_id}.json"

    def _load_wallet_addresses(self, wallet_id: str):
        path = self._wallet_path(wallet_id)

        if not path.exists():
            return set()

        wallet = json.loads(path.read_text())

        addresses = set()

        if wallet.get("primary_address"):
            addresses.add(wallet["primary_address"])

        for item in wallet.get("addresses", []):
            if item.get("address"):
                addresses.add(item["address"])

        return addresses

    def _ensure_schema(self, cursor):
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS utxos (
            txid TEXT,
            vout INTEGER,
            address TEXT,
            value INTEGER,
            status TEXT DEFAULT 'CONFIRMED',
            spent_in_tx TEXT,
            created_at INTEGER,
            PRIMARY KEY(txid, vout)
        )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_addr ON utxos(address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON utxos(status)")

    def apply_broadcast_result(self, plan_id: str, txid: str):
        plan = self.tx_builder.get_plan(plan_id)

        if not plan.get("ok"):
            return plan

        wallet_id = plan["wallet_id"]
        wallet_addresses = self._load_wallet_addresses(wallet_id)

        conn = sqlite3.connect(str(UTXO_DB))
        c = conn.cursor()

        self._ensure_schema(c)

        marked_spent = 0
        added_outputs = 0
        now = int(time.time())

        for txin in plan.get("inputs", []):
            c.execute(
                """
                UPDATE utxos
                SET status = 'SPENT',
                    spent_in_tx = ?
                WHERE txid = ?
                  AND vout = ?
                  AND status != 'SPENT'
                """,
                (
                    txid,
                    txin["txid"],
                    int(txin["vout"])
                )
            )

            marked_spent += c.rowcount

        for index, output in enumerate(plan.get("outputs", [])):
            address = output.get("address")

            if address in wallet_addresses:
                c.execute(
                    """
                    INSERT OR REPLACE INTO utxos (
                        txid,
                        vout,
                        address,
                        value,
                        status,
                        spent_in_tx,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        txid,
                        index,
                        address,
                        int(output["value"]),
                        "CONFIRMED",
                        None,
                        now
                    )
                )

                added_outputs += 1

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "plan_id": plan_id,
            "txid": txid,
            "marked_spent_inputs": marked_spent,
            "added_wallet_outputs": added_outputs,
            "warning": "UTXO DB atualizado: inputs marcados como SPENT e troco adicionado."
        }
