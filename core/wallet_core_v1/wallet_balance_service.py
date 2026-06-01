import json
import sqlite3
from pathlib import Path

from core.wallet_core_v1.lcc_network import LCC_SATOSHI


WALLET_DIR = Path("data/wallet_core")
UTXO_DB = Path("data/utxo.db")


class WalletBalanceService:

    def _wallet_path(self, wallet_id: str) -> Path:
        return WALLET_DIR / f"{wallet_id}.json"

    def get_balance(self, wallet_id: str):
        wallet_path = self._wallet_path(wallet_id)

        if not wallet_path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        if not UTXO_DB.exists():
            return {
                "ok": False,
                "error": "UTXO_DB_NOT_FOUND"
            }

        with open(wallet_path, "r", encoding="utf-8") as f:
            wallet_data = json.load(f)

        addresses = wallet_data.get("addresses", [])

        if not addresses:
            primary = wallet_data.get("primary_address")

            if primary:
                addresses = [{
                    "index": 0,
                    "path": wallet_data.get("derivation"),
                    "address": primary
                }]

        if not addresses:
            return {
                "ok": False,
                "error": "NO_ADDRESSES_FOUND"
            }

        address_list = []

        for item in addresses:
            for key in ("address", "segwit_address"):
                addr = item.get(key)

                if addr and addr not in address_list:
                    address_list.append(addr)

        conn = sqlite3.connect(str(UTXO_DB))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        placeholders = ",".join(["?"] * len(address_list))
        c.execute(f"""
            SELECT
                address,
                txid,
                vout,
                value,
                status,
                spent_in_tx
            FROM utxos
            WHERE address IN ({placeholders})
              AND status IN ('CONFIRMED', 'MEMPOOL')
            ORDER BY value DESC
        """, address_list)

        rows = c.fetchall()
        conn.close()
        utxos = [
            {
                "address": row["address"],
                "txid": row["txid"],
                "vout": row["vout"],
                "value": row["value"],
                "status": row["status"],
                "spent_in_tx": row["spent_in_tx"]
            }
            for row in rows
        ]

        balances = {}

        address_meta = {}

        for item in addresses:
            legacy = item.get("address")
            segwit = item.get("segwit_address")

            if legacy:
                address_meta[legacy] = item

            if segwit:
                address_meta[segwit] = item

        for address in address_list:
            meta = address_meta.get(address, {})

            balances[address] = {
                "address": address,
                "linked_legacy_address": meta.get("address") if address.startswith("lcc1") else None,
                "segwit_address": meta.get("segwit_address"),
                "balance": 0,
                "utxos_count": 0
            }

        for u in utxos:
            balances[u["address"]]["balance"] += int(u["value"])
            balances[u["address"]]["utxos_count"] += 1

        total = sum(item["balance"] for item in balances.values())

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "label": wallet_data.get("label"),
            "address_count": len(address_list),
            "utxos_count": len(utxos),
            "total_balance": total,
            "unit": "satoshis",
            "total_lcc": total / LCC_SATOSHI,
            "addresses": list(balances.values()),
            "utxos": utxos
        }

    def get_receive_address(self, wallet_id: str):
        result = self.get_balance(wallet_id)

        if not result.get("ok"):
            return result

        for item in result["addresses"]:
            if item["balance"] == 0 and item["utxos_count"] == 0:
                return {
                    "ok": True,
                    "wallet_id": wallet_id,
                    "label": result.get("label"),
                    "receive_address": item["address"],
                    "receive_address_segwit": item.get("segwit_address"),
                    "message": "Use estes endereços para receber LCC."
                }

        return {
            "ok": False,
            "error": "NO_EMPTY_ADDRESS_FOUND",
            "message": "Gere mais endereços HD com o comando addresses."
        }
