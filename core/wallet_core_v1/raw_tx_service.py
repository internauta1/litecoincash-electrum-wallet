import json
import struct
from pathlib import Path

from core.bech32 import decode_segwit_address
from core.wallet_core_v1.tx_builder_service import TxBuilderService
from core.wallet_core_v1.lcc_address import (
    sha256,
    base58_encode,
    B58_ALPHABET
)


RAW_TX_DIR = Path("data/wallet_core/raw_txs")
RAW_TX_DIR.mkdir(parents=True, exist_ok=True)


def int_to_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="little")


def encode_varint(value: int) -> bytes:
    if value < 0xfd:
        return value.to_bytes(1, "little")

    if value <= 0xffff:
        return b"\xfd" + value.to_bytes(2, "little")

    if value <= 0xffffffff:
        return b"\xfe" + value.to_bytes(4, "little")

    return b"\xff" + value.to_bytes(8, "little")


def base58_decode(value: str) -> bytes:
    num = 0

    for char in value:
        num *= 58
        num += B58_ALPHABET.index(char)

    combined = num.to_bytes((num.bit_length() + 7) // 8, "big")

    pad = 0
    for char in value:
        if char == "1":
            pad += 1
        else:
            break

    return b"\x00" * pad + combined


def base58check_decode(address: str) -> dict:
    raw = base58_decode(address)

    if len(raw) < 5:
        raise ValueError("Invalid base58check length")

    payload_with_prefix = raw[:-4]
    checksum = raw[-4:]

    check = sha256(sha256(payload_with_prefix))[:4]

    if checksum != check:
        raise ValueError("Invalid base58check checksum")

    prefix = payload_with_prefix[0]
    payload = payload_with_prefix[1:]

    return {
        "prefix": prefix,
        "payload": payload
    }


def p2pkh_script_pubkey(address: str) -> bytes:
    decoded = base58check_decode(address)

    pubkey_hash = decoded["payload"]

    if len(pubkey_hash) != 20:
        raise ValueError("Invalid pubkey hash length")

    return (
        b"\x76" +
        b"\xa9" +
        b"\x14" +
        pubkey_hash +
        b"\x88" +
        b"\xac"
    )


def p2wpkh_script_pubkey(address: str) -> bytes:
    h160 = decode_segwit_address(address)

    if len(h160) != 20:
        raise ValueError("Invalid lcc1 witness program length")

    return b"\x00\x14" + h160


def script_pubkey_for_address(address: str) -> bytes:
    address = address.strip()

    if address.lower().startswith("lcc1"):
        return p2wpkh_script_pubkey(address)

    return p2pkh_script_pubkey(address)


class RawTxService:

    def __init__(self):
        self.tx_builder = TxBuilderService()

    def _raw_path(self, plan_id: str) -> Path:
        return RAW_TX_DIR / f"{plan_id}.unsigned.hex"

    def build_unsigned_raw_tx(self, plan_id: str):
        plan = self.tx_builder.get_plan(plan_id)

        if not plan.get("ok"):
            return plan

        version = int_to_le(1, 4)
        locktime = int_to_le(0, 4)

        inputs = plan.get("inputs", [])
        outputs = plan.get("outputs", [])

        raw = bytearray()
        raw += version
        raw += encode_varint(len(inputs))

        for txin in inputs:
            txid = bytes.fromhex(txin["txid"])[::-1]
            vout = int_to_le(int(txin["vout"]), 4)

            script_sig = b""
            sequence = bytes.fromhex("ffffffff")

            raw += txid
            raw += vout
            raw += encode_varint(len(script_sig))
            raw += script_sig
            raw += sequence

        raw += encode_varint(len(outputs))

        for txout in outputs:
            value = int_to_le(int(txout["value"]), 8)
            script_pubkey = script_pubkey_for_address(txout["address"])

            raw += value
            raw += encode_varint(len(script_pubkey))
            raw += script_pubkey

        raw += locktime

        raw_hex = raw.hex()
        path = self._raw_path(plan_id)

        with open(path, "w", encoding="utf-8") as f:
            f.write(raw_hex)

        return {
            "ok": True,
            "plan_id": plan_id,
            "status": "unsigned_raw_skeleton",
            "inputs_count": len(inputs),
            "outputs_count": len(outputs),
            "raw_hex_unsigned": raw_hex,
            "saved_to": str(path),
            "warning": "UNSIGNED RAW TX: ainda falta scriptSig e assinatura real."
        }


def der_encode_signature(r: int, s: int) -> bytes:
    def encode_int(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b

    rb = encode_int(r)
    sb = encode_int(s)

    return (
        b"\x30" +
        bytes([len(rb) + len(sb) + 4]) +
        b"\x02" + bytes([len(rb)]) + rb +
        b"\x02" + bytes([len(sb)]) + sb
    )


def push_data(data: bytes) -> bytes:
    if len(data) < 0x4c:
        return bytes([len(data)]) + data

    raise ValueError("push_data too large")
