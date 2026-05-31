import socket
import ssl
import json
import threading
import hashlib
import base58


class LCCNetwork:

    def __init__(self, server):

        self.host, self.port, self.ssl_enabled = self.parse_server(server)

        self.sock = None
        self.file = None

        self.lock = threading.Lock()

        self.req_id = 0

        self.version_sent = False

    # -------------------------
    # PARSE SERVER
    # -------------------------
    def parse_server(self, server):

        host, port = server.split(":")
        return host, int(port), True

    # -------------------------
    # CONNECT
    # -------------------------
    def connect(self):

        if self.sock:
            return

        raw = socket.create_connection(
            (self.host, self.port),
            timeout=15
        )

        if self.ssl_enabled:

            ctx = ssl.create_default_context()

            self.sock = ctx.wrap_socket(
                raw,
                server_hostname=self.host
            )

        else:
            self.sock = raw

        self.file = self.sock.makefile("rwb")

    # -------------------------
    # SEND RPC
    # -------------------------
    def _send(self, method, params):

        self.req_id += 1

        payload = {
            "id": self.req_id,
            "method": method,
            "params": params
        }

        self.file.write(
            (json.dumps(payload) + "\n").encode()
        )

        self.file.flush()

        return self.req_id

    # -------------------------
    # READ RESPONSE
    # -------------------------
    def _read(self, req_id):

        while True:

            raw = self.file.readline()

            if not raw:
                raise Exception("Connection closed")

            msg = json.loads(raw.decode())

            #
            # IGNORE NOTIFICATIONS
            #
            if "id" not in msg:
                continue

            if msg["id"] != req_id:
                continue

            if msg.get("error"):

                raise Exception(
                    f"RPC error: {msg['error']}"
                )

            return msg["result"]

    # -------------------------
    # HANDSHAKE
    # -------------------------
    def handshake(self):

        if self.version_sent:
            return

        req_id = self._send(
            "server.version",
            ["LCC-Wallet", "1.4"]
        )

        self._read(req_id)

        self.version_sent = True

    # -------------------------
    # RPC
    # -------------------------
    def rpc(self, method, params=None):

        if params is None:
            params = []

        with self.lock:

            self.connect()

            self.handshake()

            req_id = self._send(
                method,
                params
            )

            return self._read(req_id)

    # -------------------------
    # ADDRESS -> SCRIPTHASH
    # -------------------------
    def address_to_scripthash(self, address):

        decoded = base58.b58decode(address)

        h160 = decoded[1:-4]

        script = (
            b"\x76\xa9\x14"
            + h160 +
            b"\x88\xac"
        )

        return hashlib.sha256(
            script
        ).digest()[::-1].hex()

    # -------------------------
    # GET UTXOS
    # -------------------------
    def get_utxos(self, address):

        scripthash = self.address_to_scripthash(
            address
        )

        return self.rpc(
            "blockchain.scripthash.listunspent",
            [scripthash]
        )

    # -------------------------
    # BROADCAST
    # -------------------------
    def broadcast(self, raw_hex):

        return self.rpc(
            "blockchain.transaction.broadcast",
            [raw_hex]
        )

    # -------------------------
    # CLOSE
    # -------------------------
    def close(self):

        if self.sock:
            self.sock.close()

        self.sock = None
        self.file = None
        self.version_sent = False
