import json
import socket
import hashlib
from pathlib import Path

from core.wallet_core_v1.lcc_network import LCC_SATOSHI


WALLET_DIR = Path("data/wallet_core")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def address_to_scripthash(address: str):
    from core.wallet_core_v1.raw_tx_service import p2pkh_script_pubkey

    script = p2pkh_script_pubkey(address)
    return sha256(script)[::-1].hex()


class WalletHistoryDetailService:

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

        return set(addresses)

    def _rpc_sequence(self, calls: list):
        sock = socket.create_connection((self.host, self.port), timeout=30)

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

            return [
                responses_by_id.get(
                    request_id,
                    {
                        "id": request_id,
                        "error": {
                            "message": "NO_RESPONSE"
                        }
                    }
                )
                for request_id, _, _ in calls
            ]

        finally:
            sock.close()

    def _get_unique_txids_from_history(self, addresses):
        calls = [(1, "server.version", ["lcc-wallet", "1.4"])]

        request_id = 2
        request_map = {}

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

        txids = {}
        errors = []

        for response in responses[1:]:
            address = request_map.get(response.get("id"))

            if "error" in response:
                errors.append({
                    "address": address,
                    "error": response["error"]
                })
                continue

            for item in response.get("result", []):
                tx_hash = item.get("tx_hash")

                if not tx_hash:
                    continue

                txids[tx_hash] = {
                    "txid": tx_hash,
                    "height": item.get("height")
                }

        return {
            "ok": True,
            "txids": list(txids.values()),
            "errors": errors
        }

    def _get_transactions(self, txids):
        calls = [(1, "server.version", ["lcc-wallet", "1.4"])]

        request_map = {}
        request_id = 2

        for item in txids:
            txid = item["txid"]

            calls.append((
                request_id,
                "blockchain.transaction.get",
                [txid, True]
            ))

            request_map[request_id] = item
            request_id += 1

        responses = self._rpc_sequence(calls)

        txs = []
        errors = []

        for response in responses[1:]:
            meta = request_map.get(response.get("id"))

            if "error" in response:
                errors.append({
                    "txid": meta.get("txid") if meta else None,
                    "error": response["error"]
                })
                continue

            tx = response.get("result")

            if isinstance(tx, dict):
                tx["_wallet_height"] = meta.get("height") if meta else None
                txs.append(tx)

        return {
            "ok": True,
            "transactions": txs,
            "errors": errors
        }

    def _extract_output_address(self, vout):
        script = vout.get("scriptPubKey", {})
        addresses = script.get("addresses")

        if isinstance(addresses, list) and addresses:
            return addresses[0]

        return None

    def _output_value_units(self, vout):
        value_lcc = float(vout.get("value", 0))
        value_units = int(round(value_lcc * LCC_SATOSHI))
        return value_units, value_lcc

    def _build_wallet_prevout_map(self, transactions, wallet_addresses):
        prevouts = {}

        for tx in transactions:
            txid = tx.get("txid")

            for out in tx.get("vout", []):
                address = self._extract_output_address(out)

                if address not in wallet_addresses:
                    continue

                value_units, value_lcc = self._output_value_units(out)
                n = int(out.get("n"))

                prevouts[(txid, n)] = {
                    "txid": txid,
                    "vout": n,
                    "address": address,
                    "value": value_units,
                    "value_lcc": value_lcc
                }

        return prevouts

    def _analyze_tx(self, tx, wallet_addresses, wallet_prevouts):
        txid = tx.get("txid")
        height = tx.get("_wallet_height")
        outputs = tx.get("vout", [])
        inputs = tx.get("vin", [])

        wallet_outputs = []
        external_outputs = []
        wallet_inputs = []

        for vin in inputs:
            prev_txid = vin.get("txid")
            prev_vout = vin.get("vout")

            if prev_txid is None or prev_vout is None:
                continue

            key = (prev_txid, int(prev_vout))

            if key in wallet_prevouts:
                wallet_inputs.append(wallet_prevouts[key])

        for out in outputs:
            address = self._extract_output_address(out)
            value_units, value_lcc = self._output_value_units(out)

            entry = {
                "n": out.get("n"),
                "address": address,
                "value": value_units,
                "value_lcc": value_lcc
            }

            if address in wallet_addresses:
                wallet_outputs.append(entry)
            else:
                external_outputs.append(entry)

        wallet_input_total = sum(item["value"] for item in wallet_inputs)
        wallet_output_total = sum(item["value"] for item in wallet_outputs)
        external_output_total = sum(item["value"] for item in external_outputs)

        if wallet_inputs:
            tx_type = "SENT_WITH_CHANGE" if wallet_outputs else "SENT"

            sent_external = external_output_total
            change = wallet_output_total
            received = 0
            fee = max(wallet_input_total - sent_external - change, 0)
        else:
            tx_type = "RECEIVED" if wallet_outputs else "EXTERNAL"

            received = wallet_output_total
            sent_external = 0
            change = 0
            fee = None

        return {
            "txid": txid,
            "height": height,
            "type": tx_type,
            "received": received,
            "received_lcc": received / LCC_SATOSHI,
            "sent_external": sent_external,
            "sent_external_lcc": sent_external / LCC_SATOSHI,
            "change": change,
            "change_lcc": change / LCC_SATOSHI,
            "fee": fee,
            "fee_lcc": None if fee is None else fee / LCC_SATOSHI,
            "wallet_input_total": wallet_input_total,
            "wallet_input_total_lcc": wallet_input_total / LCC_SATOSHI,
            "wallet_inputs": wallet_inputs,
            "wallet_outputs": wallet_outputs,
            "external_outputs": external_outputs
        }

    def get_detail(self, wallet_id: str):
        wallet_addresses = self._load_addresses(wallet_id)

        if wallet_addresses is None:
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        history = self._get_unique_txids_from_history(wallet_addresses)

        if not history.get("ok"):
            return history

        txs_result = self._get_transactions(history["txids"])
        transactions = txs_result.get("transactions", [])

        wallet_prevouts = self._build_wallet_prevout_map(
            transactions=transactions,
            wallet_addresses=wallet_addresses
        )

        details = []

        for tx in transactions:
            detail = self._analyze_tx(
                tx=tx,
                wallet_addresses=wallet_addresses,
                wallet_prevouts=wallet_prevouts
            )

            if detail["type"] != "EXTERNAL":
                details.append(detail)

        details.sort(key=lambda x: x.get("height") or 0, reverse=True)

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "addresses_checked": len(wallet_addresses),
            "transactions_count": len(details),
            "transactions": details,
            "errors": history.get("errors", []) + txs_result.get("errors", [])
        }
