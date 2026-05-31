import hashlib


class AddressCodecV1:

    def hash160(self, data: bytes) -> bytes:
        sha = hashlib.sha256(data).digest()
        rip = hashlib.new("ripemd160", sha).digest()
        return rip

    def p2pkh_script(self, pubkey_hash: str) -> str:
        return "76a914" + pubkey_hash + "88ac"

    def p2sh_script(self, script_hash: str) -> str:
        return "a914" + script_hash + "87"

    def segwit_script(self, witness_program: str) -> str:
        return "0014" + witness_program

    def address_to_script(self, address: str) -> str:

        if address.startswith("lcc1"):
            data = address.encode()
            h = self.hash160(data).hex()
            return self.segwit_script(h)

        else:
            h = self.hash160(address.encode()).hex()
            return self.p2pkh_script(h)

    def script_to_scripthash(self, script_hex: str) -> str:

        script_bytes = bytes.fromhex(script_hex)
        sha = hashlib.sha256(script_bytes).digest()
        return sha[::-1].hex()

    def address_to_scripthash(self, address: str) -> str:

        script = self.address_to_script(address)
        return self.script_to_scripthash(script)
