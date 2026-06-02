from pathlib import Path

from core.wallet_core_v1.lcc_network import LCC_SATOSHI


SIGNED_RAW_DIR = Path("data/wallet_core/signed_raw")


def read_varint(data: bytes, offset: int):
    first = data[offset]
    offset += 1

    if first < 0xfd:
        return first, offset

    if first == 0xfd:
        value = int.from_bytes(data[offset:offset + 2], "little")
        return value, offset + 2

    if first == 0xfe:
        value = int.from_bytes(data[offset:offset + 4], "little")
        return value, offset + 4

    value = int.from_bytes(data[offset:offset + 8], "little")
    return value, offset + 8


class RawDecodeService:

    def _signed_raw_path(self, plan_id: str) -> Path:
        return SIGNED_RAW_DIR / f"{plan_id}.signed.hex"

    def show_raw(self, plan_id: str):
        path = self._signed_raw_path(plan_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "SIGNED_RAW_NOT_FOUND"
            }

        raw_hex = path.read_text().strip()

        return {
            "ok": True,
            "plan_id": plan_id,
            "raw_hex": raw_hex,
            "electrum_command": f'deserialize("{raw_hex}")',
            "warning": "Copie apenas para deserialize/validação. Não usar broadcast ainda."
        }

    def decode_signed_raw(self, plan_id: str):
        path = self._signed_raw_path(plan_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "SIGNED_RAW_NOT_FOUND"
            }

        raw_hex = path.read_text().strip()
        data = bytes.fromhex(raw_hex)

        offset = 0

        version = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4

        is_segwit = False

        if offset + 2 <= len(data) and data[offset] == 0 and data[offset + 1] == 1:
            is_segwit = True
            offset += 2

        input_count, offset = read_varint(data, offset)

        inputs = []

        for _ in range(input_count):
            txid = data[offset:offset + 32][::-1].hex()
            offset += 32

            vout = int.from_bytes(data[offset:offset + 4], "little")
            offset += 4

            script_len, offset = read_varint(data, offset)
            script_sig = data[offset:offset + script_len].hex()
            offset += script_len

            sequence = data[offset:offset + 4].hex()
            offset += 4

            inputs.append({
                "txid": txid,
                "vout": vout,
                "script_sig_len": script_len,
                "script_sig": script_sig,
                "sequence": sequence
            })

        output_count, offset = read_varint(data, offset)

        outputs = []

        for _ in range(output_count):
            value = int.from_bytes(data[offset:offset + 8], "little")
            offset += 8

            script_len, offset = read_varint(data, offset)
            script_pubkey = data[offset:offset + script_len].hex()
            offset += script_len

            outputs.append({
                "value": value,
                "value_lcc": value / LCC_SATOSHI,
                "script_pubkey_len": script_len,
                "script_pubkey": script_pubkey
            })

        witnesses = []

        if is_segwit:
            for _ in range(input_count):
                item_count, offset = read_varint(data, offset)
                items = []

                for _ in range(item_count):
                    item_len, offset = read_varint(data, offset)
                    item = data[offset:offset + item_len].hex()
                    offset += item_len
                    items.append(item)

                witnesses.append({
                    "items_count": item_count,
                    "items": items
                })

        locktime = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4

        return {
            "ok": True,
            "plan_id": plan_id,
            "version": version,
            "is_segwit": is_segwit,
            "inputs_count": input_count,
            "outputs_count": output_count,
            "inputs": inputs,
            "outputs": outputs,
            "witnesses": witnesses,
            "locktime": locktime,
            "raw_size_bytes": len(data),
            "fully_parsed": offset == len(data),
            "warning": "Decode local OK. Ainda falta validar no node/LCC decoder antes de broadcast."
        }
