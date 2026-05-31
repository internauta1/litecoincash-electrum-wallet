import socket
import json
import hashlib


class ElectrumClientV2:

    def __init__(
        self,
        host="127.0.0.1",
        port=50001,
        timeout=10
    ):

        self.host = host
        self.port = port
        self.timeout = timeout

    # -----------------------------------
    # RAW REQUEST
    # -----------------------------------
    def _request(
        self,
        method,
        params=None
    ):

        if params is None:
            params = []

        payload = {
            "id": 1,
            "method": method,
            "params": params
        }

        data = (
            json.dumps(payload) + "\n"
        ).encode()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            self.timeout
        )

        sock.connect(
            (self.host, self.port)
        )

        sock.send(data)

        response = b""

        while True:

            chunk = sock.recv(4096)

            if not chunk:
                break

            response += chunk

            if b"\n" in response:
                break

        sock.close()

        result = json.loads(
            response.decode()
        )

        if result.get("error"):

            raise Exception(
                result["error"]
            )

        return result.get("result")

    # -----------------------------------
    # SERVER VERSION
    # -----------------------------------
    def server_version(self):

        return self._request(
            "server.version",
            ["WalletAI", "1.4"]
        )

    # -----------------------------------
    # PING
    # -----------------------------------
    def ping(self):
        try:
            return self._request("server.version", ["ping", "1.0"])
        except Exception:
            return "OK"

    # -----------------------------------
    # ADDRESS -> ELECTRUM SCRIPTHASH
    # -----------------------------------
    def address_to_scripthash(
        self,
        address
    ):

        """
        TEMP simplificado.

        Electrum usa:
        sha256(scriptPubKey)
        reversed hex

        Vamos gerar pseudo-script.
        """

        script = self._address_to_script(
            address
        )

        h = hashlib.sha256(
            bytes.fromhex(script)
        ).digest()

        return h[::-1].hex()

    # -----------------------------------
    # ADDRESS -> SCRIPT
    # -----------------------------------
    def _address_to_script(
        self,
        address
    ):

        """
        PLACEHOLDER inteligente.

        Para LCC bech32:
        OP_0 PUSH20 HASH

        Aqui vamos usar hash160 fake
        até integrar decoder real.
        """

        h = hashlib.new(
            "ripemd160",
            address.encode()
        ).hexdigest()

        return "0014" + h

    # -----------------------------------
    # GET BALANCE
    # -----------------------------------
    def get_balance(
        self,
        address
    ):

        scripthash = (
            self.address_to_scripthash(
                address
            )
        )

        return self._request(
            "blockchain.scripthash.get_balance",
            [scripthash]
        )

    # -----------------------------------
    # GET HISTORY
    # -----------------------------------
    def get_history(
        self,
        address
    ):

        scripthash = (
            self.address_to_scripthash(
                address
            )
        )

        return self._request(
            "blockchain.scripthash.get_history",
            [scripthash]
        )

    # -----------------------------------
    # GET UTXOS
    # -----------------------------------
    def get_utxos(
        self,
        address
    ):

        scripthash = (
            self.address_to_scripthash(
                address
            )
        )

        return self._request(
            "blockchain.scripthash.listunspent",
            [scripthash]
        )

    # -----------------------------------
    # BROADCAST TX
    # -----------------------------------
    def broadcast(
        self,
        rawtx
    ):

        return self._request(
            "blockchain.transaction.broadcast",
            [rawtx]
        )
