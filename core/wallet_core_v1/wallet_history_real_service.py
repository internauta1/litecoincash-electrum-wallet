import json
import socket
import hashlib
from pathlib import Path


WALLET_DIR = Path("data/wallet_core")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def address_to_scripthash(address: str):
    from core.wallet_core_v1.raw_tx_service import p2pkh_script_pubkey

    script = p2pkh_script_pubkey(address)
    return sha256(script)[::-1].hex()


class WalletHistoryRealService:

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

    def get_history(self, wallet_id: str):
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
                "blockchain.scripthash.get_history",
                [scripthash]
            ))

            request_map[request_id] = address
            request_id += 1

        responses = self._rpc_sequence(calls)

        if not responses or "error" in responses[0]:
            return {
                "ok": False,
                "error": "SERVER_VERSION_FAILED",
                "responses": responses
            }

        history = []
        errors = []
        seen = set()

        for response in responses[1:]:
            rid = response.get("id")
            address = request_map.get(rid)

            if not address:
                continue

            if "error" in response:
                errors.append({
                    "address": address,
                    "error": response["error"]
                })
                continue

            for item in response.get("result", []):
                tx_hash = item.get("tx_hash")
                height = item.get("height")

                key = (address, tx_hash, height)

                if key in seen:
                    continue

                seen.add(key)

                history.append({
                    "address": address,
                    "tx_hash": tx_hash,
                    "height": height
                })

        history.sort(key=lambda x: x.get("height", 0), reverse=True)

        unique_txids = sorted(
            {item["tx_hash"] for item in history if item.get("tx_hash")}
        )

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "addresses_checked": len(addresses),
            "transactions_count": len(history),
            "unique_transactions_count": len(unique_txids),
            "unique_txids": unique_txids,
            "history": history,
            "errors": errors
        }
