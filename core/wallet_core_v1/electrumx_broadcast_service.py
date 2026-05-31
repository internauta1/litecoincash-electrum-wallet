import json
import socket
import ssl
from pathlib import Path

from core.wallet_core_v1.final_validate_service import FinalValidateService
from core.wallet_core_v1.utxo_update_service import UtxoUpdateService


SIGNED_RAW_DIR = Path("data/wallet_core/signed_raw")


class ElectrumXBroadcastService:

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 50001,
        use_ssl: bool = False
    ):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.validator = FinalValidateService()
        self.utxo_update = UtxoUpdateService()

    def _signed_raw_path(self, plan_id: str) -> Path:
        return SIGNED_RAW_DIR / f"{plan_id}.signed.hex"

    def _open_socket(self):
        sock = socket.create_connection(
            (self.host, self.port),
            timeout=30
        )

        if self.use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(
                sock,
                server_hostname=self.host
            )

        return sock

    def _send_rpc_on_socket(
        self,
        sock,
        request_id: int,
        method: str,
        params: list
    ):
        payload = {
            "id": request_id,
            "method": method,
            "params": params
        }

        message = json.dumps(payload) + "\n"
        sock.sendall(message.encode("utf-8"))

        buffer = ""

        while True:
            data = sock.recv(4096)

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

                if obj.get("id") == request_id:
                    return obj

        return {
            "error": {
                "message": "NO_RESPONSE_WITH_REQUEST_ID",
                "request_id": request_id
            }
        }

    def _rpc_sequence(self, calls: list):
        sock = self._open_socket()

        try:
            responses = []

            for request_id, method, params in calls:
                response = self._send_rpc_on_socket(
                    sock=sock,
                    request_id=request_id,
                    method=method,
                    params=params
                )

                responses.append(response)

                if "error" in response:
                    break

            return responses

        finally:
            sock.close()

    def broadcast_plan(self, plan_id: str):
        validation = self.validator.validate_final(plan_id)

        if not validation.get("ready_for_broadcast"):
            return {
                "ok": False,
                "error": "VALIDATION_FAILED",
                "validation": validation
            }

        path = self._signed_raw_path(plan_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "SIGNED_RAW_NOT_FOUND"
            }

        raw_hex = path.read_text().strip()

        responses = self._rpc_sequence([
            (1, "server.version", ["lcc-wallet", "1.4"]),
            (2, "blockchain.transaction.broadcast", [raw_hex])
        ])

        if len(responses) < 1:
            return {
                "ok": False,
                "error": "NO_ELECTRUMX_RESPONSE"
            }

        version_response = responses[0]

        if "error" in version_response:
            return {
                "ok": False,
                "error": "SERVER_VERSION_FAILED",
                "response": version_response
            }

        if len(responses) < 2:
            return {
                "ok": False,
                "error": "NO_BROADCAST_RESPONSE",
                "server_version": version_response
            }

        broadcast_response = responses[1]

        if "error" in broadcast_response:
            return {
                "ok": False,
                "error": "ELECTRUMX_BROADCAST_ERROR",
                "server_version": version_response,
                "response": broadcast_response
            }

        txid = broadcast_response.get("result")

        if not txid:
            return {
                "ok": False,
                "error": "EMPTY_TXID",
                "plan_id": plan_id,
                "txid": txid,
                "server_version": version_response,
                "response": broadcast_response
            }

        utxo_update = self.utxo_update.apply_broadcast_result(
            plan_id=plan_id,
            txid=txid
        )

        return {
            "ok": True,
            "plan_id": plan_id,
            "txid": txid,
            "server_version": version_response,
            "response": broadcast_response,
            "utxo_update": utxo_update,
            "warning": "Broadcast enviado via ElectrumX e UTXO DB atualizado."
        }
