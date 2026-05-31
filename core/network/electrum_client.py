import json
import socket
import time


class ElectrumClient:

    def __init__(
        self,
        host="127.0.0.1",
        port=50001,
        timeout=30
    ):

        self.host = host
        self.port = port
        self.timeout = timeout

    # -----------------------------------
    # MAIN CALL
    # -----------------------------------
    def call(
        self,
        method,
        params=None,
        retries=3
    ):

        if params is None:
            params = []

        payload = {
            "id": 2,
            "method": method,
            "params": params
        }

        last_error = None

        for _ in range(retries):

            try:

                return self._send(payload)

            except Exception as e:

                last_error = e

                time.sleep(0.5)

        raise last_error

    # -----------------------------------
    # SEND WITH AUTO HANDSHAKE
    # -----------------------------------
    def _send(self, payload):

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(self.timeout)

        s.connect(
            (self.host, self.port)
        )

        # -----------------------------------
        # HANDSHAKE
        # -----------------------------------
        hello = {
            "id": 1,
            "method": "server.version",
            "params": [
                "LCCWallet",
                "1.4"
            ]
        }

        s.sendall(
            (
                json.dumps(hello) + "\n"
            ).encode()
        )

        self._read_response(
            s,
            expected_id=1
        )

        # -----------------------------------
        # REAL REQUEST
        # -----------------------------------
        s.sendall(
            (
                json.dumps(payload) + "\n"
            ).encode()
        )

        result = self._read_response(
            s,
            expected_id=2
        )

        s.close()

        return result

    # -----------------------------------
    # RESPONSE READER
    # -----------------------------------
    def _read_response(
        self,
        sock,
        expected_id
    ):

        buffer = ""

        while True:

            chunk = sock.recv(4096)

            if not chunk:
                break

            buffer += chunk.decode()

            while "\n" in buffer:

                line, buffer = buffer.split(
                    "\n",
                    1
                )

                line = line.strip()

                if not line:
                    continue

                data = json.loads(line)

                # ignore async notifications
                if "id" not in data:
                    continue

                # wrong response id
                if data["id"] != expected_id:
                    continue

                # electrum error
                if data.get("error"):
                    raise Exception(
                        data["error"]
                    )

                return data.get("result")

        raise Exception(
            "No valid Electrum response"
        )

    # -----------------------------------
    # DIRECT SERVER VERSION
    # -----------------------------------
    def server_version(self):

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(self.timeout)

        s.connect(
            (self.host, self.port)
        )

        payload = {
            "id": 1,
            "method": "server.version",
            "params": [
                "LCCWallet",
                "1.4"
            ]
        }

        s.sendall(
            (
                json.dumps(payload) + "\n"
            ).encode()
        )

        result = self._read_response(
            s,
            expected_id=1
        )

        s.close()

        return result

    # -----------------------------------
    # BROADCAST
    # -----------------------------------
    def broadcast(self, rawtx):

        return self.call(
            "blockchain.transaction.broadcast",
            [rawtx]
        )
