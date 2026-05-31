import json
import socket
import sqlite3
import hashlib
import time
from pathlib import Path

from core.wallet_core_v1.lcc_network import LCC_SATOSHI


WALLET_DIR = Path("data/wallet_core")
UTXO_DB = Path("data/utxo.db")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def address_to_scripthash(address: str):
    from core.wallet_core_v1.raw_tx_service import p2pkh_script_pubkey

    script = p2pkh_script_pubkey(address)
    return sha256(script)[::-1].hex()


class UtxoSyncService:

    def __init__(self, host: str = "127.0.0.1", port: int = 50001):
        self.host = host
        self.port = port

    def _wallet_path(self, wallet_id: str) -> Path:
        return WALLET_DIR / f"{wallet_id}.json"

    def _load_addresses(self, wallet_id: str):
        path = self._wallet_path(wallet_id)

        if not path.exists():
            return None

        wallet = json.loads(path.read_text())

        addresses = []

        primary = wallet.get("primary_address")
        if primary:
            addresses.append(primary)

        for item in wallet.get("addresses", []):
            addr = item.get("address")

            if addr and addr not in addresses:
                addresses.append(addr)

        return addresses

    def _open_socket(self):
        return socket.create_connection(
            (self.host, self.port),
            timeout=30
        )

    def _rpc_sequence(self, calls: list):
        sock = self._open_socket()

        try:
            for request_id, method, params in calls:
                payload = {
                    "id": request_id,
                    "method": method,
                    "params": params
                }

                sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))

            responses_by_id = {}
            buffer = ""

            while len(responses_by_id) < len(calls):
                data = sock.recv(65536)

                if not data:
                    break

                buffer += data.decode("utf-8", errors="replace")

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    response_id = obj.get("id")

                    if response_id is not None:
                        responses_by_id[response_id] = obj

            ordered = []

            for request_id, _, _ in calls:
                ordered.append(
                    responses_by_id.get(
                        request_id,
                        {
                            "id": request_id,
                            "error": {
                                "message": "NO_RESPONSE"
                            }
                        }
                    )
                )

            return ordered

        finally:
            sock.close()

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

        cursor.execute("PRAGMA table_info(utxos)")
        columns = {row[1] for row in cursor.fetchall()}

        if "spent_in_tx" not in columns:
            cursor.execute("ALTER TABLE utxos ADD COLUMN spent_in_tx TEXT")

        if "created_at" not in columns:
            cursor.execute("ALTER TABLE utxos ADD COLUMN created_at INTEGER")

    def _insert_or_update_utxo(
        self,
        cursor,
        txid: str,
        vout: int,
        address: str,
        value: int,
        status: str,
        now: int
    ):
        cursor.execute(
            """
            INSERT INTO utxos (
                txid,
                vout,
                address,
                value,
                status,
                spent_in_tx,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(txid, vout) DO UPDATE SET
                address = excluded.address,
                value = excluded.value,
                status = excluded.status,
                spent_in_tx = NULL
            """,
            (
                txid,
                vout,
                address,
                value,
                status,
                None,
                now
            )
        )

    def sync_wallet_utxos(self, wallet_id: str):
        addresses = self._load_addresses(wallet_id)

        if addresses is None:
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        calls = [(1, "server.version", ["lcc-wallet", "1.4"])]

        request_map = {}
        request_id = 2

        for address in addresses:
            scripthash = address_to_scripthash(address)

            calls.append((
                request_id,
                "blockchain.scripthash.listunspent",
                [scripthash]
            ))
            request_map[request_id] = {
                "address": address,
                "kind": "confirmed"
            }
            request_id += 1

            calls.append((
                request_id,
                "blockchain.scripthash.get_mempool",
                [scripthash]
            ))
            request_map[request_id] = {
                "address": address,
                "kind": "mempool"
            }
            request_id += 1

        responses = self._rpc_sequence(calls)

        if not responses or "error" in responses[0]:
            return {
                "ok": False,
                "error": "SERVER_VERSION_FAILED",
                "responses": responses
            }

        conn = sqlite3.connect(str(UTXO_DB))
        c = conn.cursor()

        self._ensure_schema(c)

        now = int(time.time())
        synced = []
        mempool_seen = []
        errors = []
        live_keys = set()

        for response in responses[1:]:
            rid = response.get("id")
            meta = request_map.get(rid)

            if not meta:
                continue

            address = meta["address"]
            kind = meta["kind"]

            if "error" in response:
                errors.append({
                    "address": address,
                    "kind": kind,
                    "error": response["error"]
                })
                continue

            if kind == "confirmed":
                for u in response.get("result", []):
                    txid = u.get("tx_hash")
                    vout = int(u.get("tx_pos"))
                    value = int(u.get("value"))

                    live_keys.add((txid, vout))

                    self._insert_or_update_utxo(
                        cursor=c,
                        txid=txid,
                        vout=vout,
                        address=address,
                        value=value,
                        status="CONFIRMED",
                        now=now
                    )

                    synced.append({
                        "address": address,
                        "txid": txid,
                        "vout": vout,
                        "value": value,
                        "value_lcc": value / LCC_SATOSHI,
                        "status": "CONFIRMED"
                    })

            if kind == "mempool":
                for m in response.get("result", []):
                    mempool_seen.append({
                        "address": address,
                        "tx_hash": m.get("tx_hash"),
                        "height": m.get("height"),
                        "fee": m.get("fee")
                    })

        marked_spent = 0

        if addresses:
            placeholders = ",".join(["?"] * len(addresses))

            c.execute(
                f"""
                SELECT txid, vout
                FROM utxos
                WHERE address IN ({placeholders})
                  AND status IN ('CONFIRMED', 'MEMPOOL')
                """,
                addresses
            )

            existing = c.fetchall()

            for txid, vout in existing:
                if (txid, int(vout)) not in live_keys:
                    c.execute(
                        """
                        UPDATE utxos
                        SET status = 'SPENT'
                        WHERE txid = ?
                          AND vout = ?
                          AND status != 'SPENT'
                        """,
                        (txid, int(vout))
                    )

                    marked_spent += c.rowcount

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "addresses_checked": len(addresses),
            "utxos_synced": len(synced),
            "mempool_seen": len(mempool_seen),
            "marked_spent": marked_spent,
            "utxos": synced,
            "mempool": mempool_seen,
            "errors": errors
        }
