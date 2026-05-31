import hashlib
import struct
import requests


class LCCTransaction:

    def __init__(self, network, wallet):
        self.net = network
        self.wallet = wallet

    # -------------------------
    # ESCOLHER UTXOs
    # -------------------------
    def select_utxos(self, utxos, amount):

        selected = []
        total = 0

        for u in utxos:
            selected.append(u)
            total += u["value"]

            if total >= amount:
                break

        if total < amount:
            raise Exception("Insufficient funds")

        return selected, total

    # -------------------------
    # RAW TX BUILDER (simplificado)
    # -------------------------
    def build_raw_tx(self, inputs, to_address, amount, change_address, fee):

        tx = {
            "inputs": inputs,
            "outputs": [
                {"address": to_address, "value": amount},
            ]
        }

        change = sum(i["value"] for i in inputs) - amount - fee

        if change > 0:
            tx["outputs"].append({
                "address": change_address,
                "value": change
            })

        return tx

    # -------------------------
    # SIMPLES SERIALIZER (placeholder compatível Electrum)
    # -------------------------
    def serialize(self, tx):

        return {
            "inputs": tx["inputs"],
            "outputs": tx["outputs"]
        }

    # -------------------------
    # BROADCAST
    # -------------------------
    def broadcast(self, raw_tx):

        return self.net.call(
            "blockchain.transaction.broadcast",
            [raw_tx]
        )

    # -------------------------
    # FLOW COMPLETO
    # -------------------------
    def send(self, utxos, to_address, amount, fee, change_address):

        inputs, total = self.select_utxos(utxos, amount + fee)

        tx = self.build_raw_tx(
            inputs,
            to_address,
            amount,
            change_address,
            fee
        )

        raw = self.serialize(tx)

        return self.broadcast(raw)
