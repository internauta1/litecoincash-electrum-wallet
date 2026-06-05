import json
import base64
import secrets
import hashlib

from pathlib import Path
from datetime import datetime
from mnemonic import Mnemonic

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.wallet_core_v1.lcc_address import (
    lcc_address_from_mnemonic,
    lcc_addresses_from_mnemonic
)


WALLET_DIR = Path("data/wallet_core")
WALLET_DIR.mkdir(parents=True, exist_ok=True)


class WalletCoreService:

    def _wallet_path(self, wallet_id: str) -> Path:
        return WALLET_DIR / f"{wallet_id}.json"

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000,
        )

        return kdf.derive(password.encode("utf-8"))

    def _encrypt(self, plaintext: str, password: str):
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        key = self._derive_key(password, salt)

        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            None
        )

        return {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def _decrypt(self, encrypted: dict, password: str) -> str:
        salt = base64.b64decode(encrypted["salt"])
        nonce = base64.b64decode(encrypted["nonce"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])

        key = self._derive_key(password, salt)

        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")

    def _generate_seed_material(self, seed_words: int = 12) -> str:
        """
        Gera seed BIP39 de 12 ou 24 palavras.
        """

        mnemo = Mnemonic("english")

        if seed_words == 24:
            return mnemo.generate(strength=256)

        return mnemo.generate(strength=128)

    def create_wallet(
        self,
        password: str,
        label: str = "main",
        seed_words: int = 12
    ):

        if not password or len(password) < 10:
            return {
                "ok": False,
                "error": "PASSWORD_TOO_SHORT",
                "message": "Use uma password com pelo menos 10 caracteres."
            }

        wallet_id = secrets.token_hex(12)

        seed_material = self._generate_seed_material(seed_words=seed_words)

        address_info = lcc_address_from_mnemonic(seed_material)

        encrypted_seed = self._encrypt(
            seed_material,
            password
        )

        wallet_data = {

            "wallet_id": wallet_id,

            "label": label,

            "type": "encrypted_bip39_seed",

            "network": "LCC",

            "created_at": datetime.utcnow().isoformat() + "Z",

            "seed_hash": hashlib.sha256(
                seed_material.encode()
            ).hexdigest(),

            "primary_address": address_info["address"],

            "public_key": address_info["public_key"],

            "derivation": address_info["derivation"],

            "encrypted_seed": encrypted_seed
        }

        path = self._wallet_path(wallet_id)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(wallet_data, f, indent=2)

        return {

            "ok": True,

            "wallet_id": wallet_id,

            "label": label,

            "created_at": wallet_data["created_at"],

            "seed_hash": wallet_data["seed_hash"],

            "primary_address": address_info["address"],

            "derivation": address_info["derivation"],

            "warning": (
                "Wallet BIP39 criada e seed guardada encriptada."
            )
        }

    def unlock_wallet(self, wallet_id: str, password: str):

        path = self._wallet_path(wallet_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        try:

            with open(path, "r", encoding="utf-8") as f:
                wallet_data = json.load(f)

            seed_material = self._decrypt(
                wallet_data["encrypted_seed"],
                password
            )

            seed_hash = hashlib.sha256(
                seed_material.encode()
            ).hexdigest()

            if seed_hash != wallet_data.get("seed_hash"):

                return {
                    "ok": False,
                    "error": "SEED_HASH_MISMATCH"
                }

            return {

                "ok": True,

                "wallet_id": wallet_id,

                "label": wallet_data.get("label"),

                "seed_hash": seed_hash,

                "primary_address": wallet_data.get(
                    "primary_address"
                ),

                "derivation": wallet_data.get(
                    "derivation"
                ),

                "unlocked": True,

                "warning": (
                    "Seed validada com sucesso."
                )
            }

        except Exception:

            return {
                "ok": False,
                "error": "INVALID_PASSWORD_OR_CORRUPT_WALLET"
            }

    def derive_addresses(
        self,
        wallet_id: str,
        password: str,
        count: int = 5
    ):

        if count < 1:
            count = 1

        if count > 100:
            count = 100

        path = self._wallet_path(wallet_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        try:

            with open(path, "r", encoding="utf-8") as f:
                wallet_data = json.load(f)

            seed_material = self._decrypt(
                wallet_data["encrypted_seed"],
                password
            )

            seed_hash = hashlib.sha256(
                seed_material.encode()
            ).hexdigest()

            if seed_hash != wallet_data.get("seed_hash"):

                return {
                    "ok": False,
                    "error": "SEED_HASH_MISMATCH"
                }

            addresses = lcc_addresses_from_mnemonic(
                mnemonic_words=seed_material,
                count=count
            )

            return {

                "ok": True,

                "wallet_id": wallet_id,

                "count": len(addresses),

                "addresses": addresses,

                "warning": (
                    "Endereços derivados com sucesso."
                )
            }

        except Exception:

            return {
                "ok": False,
                "error": "INVALID_PASSWORD_OR_CORRUPT_WALLET"
            }

    def import_seed(
        self,
        seed_phrase: str,
        password: str,
        label: str = "imported"
    ):

        if not password or len(password) < 10:
            return {
                "ok": False,
                "error": "PASSWORD_TOO_SHORT",
                "message": "Use uma password com pelo menos 10 caracteres."
            }

        seed_phrase = " ".join(seed_phrase.strip().split())

        mnemo = Mnemonic("english")

        if not mnemo.check(seed_phrase):
            return {
                "ok": False,
                "error": "INVALID_BIP39_SEED"
            }

        wallet_id = secrets.token_hex(12)

        address_info = lcc_address_from_mnemonic(seed_phrase)

        addresses = lcc_addresses_from_mnemonic(
            mnemonic_words=seed_phrase,
            count=20
        )

        encrypted_seed = self._encrypt(
            seed_phrase,
            password
        )

        wallet_data = {

            "wallet_id": wallet_id,

            "label": label,

            "type": "encrypted_bip39_seed",

            "network": "LCC",

            "created_at": datetime.utcnow().isoformat() + "Z",

            "seed_hash": hashlib.sha256(
                seed_phrase.encode()
            ).hexdigest(),

            "primary_address": address_info["address"],

            "public_key": address_info["public_key"],

            "derivation": address_info["derivation"],

            "encrypted_seed": encrypted_seed,

            "addresses": addresses,

            "address_count": len(addresses)
        }

        path = self._wallet_path(wallet_id)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(wallet_data, f, indent=2)

        return {

            "ok": True,

            "wallet_id": wallet_id,

            "label": label,

            "primary_address": address_info["address"],

            "derivation": address_info["derivation"],

            "address_count": len(addresses),

            "addresses_preview": addresses[:3],

            "warning": (
                "Seed importada, guardada encriptada e 20 endereços HD foram gerados. "
                "Ainda validar derivação antes de usar fundos reais."
            )
        }

    def export_seed(self, wallet_id: str, password: str):

        path = self._wallet_path(wallet_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        try:

            with open(path, "r", encoding="utf-8") as f:
                wallet_data = json.load(f)

            seed_material = self._decrypt(
                wallet_data["encrypted_seed"],
                password
            )

            seed_hash = hashlib.sha256(
                seed_material.encode()
            ).hexdigest()

            if seed_hash != wallet_data.get("seed_hash"):

                return {
                    "ok": False,
                    "error": "SEED_HASH_MISMATCH"
                }

            return {

                "ok": True,

                "wallet_id": wallet_id,

                "label": wallet_data.get("label"),

                "seed_phrase": seed_material,

                "warning": (
                    "ALTAMENTE SENSÍVEL: "
                    "guarde offline. "
                    "Nunca envie esta seed para ninguém."
                )
            }

        except Exception:

            return {
                "ok": False,
                "error": "INVALID_PASSWORD_OR_CORRUPT_WALLET"
            }

    def generate_and_persist_addresses(
        self,
        wallet_id: str,
        password: str,
        count: int = 20
    ):

        if count < 1:
            count = 1

        if count > 500:
            count = 500

        path = self._wallet_path(wallet_id)

        if not path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        try:
            with open(path, "r", encoding="utf-8") as f:
                wallet_data = json.load(f)

            seed_material = self._decrypt(
                wallet_data["encrypted_seed"],
                password
            )

            seed_hash = hashlib.sha256(seed_material.encode()).hexdigest()

            if seed_hash != wallet_data.get("seed_hash"):
                return {
                    "ok": False,
                    "error": "SEED_HASH_MISMATCH"
                }

            addresses = lcc_addresses_from_mnemonic(
                mnemonic_words=seed_material,
                count=count
            )

            wallet_data["addresses"] = addresses
            wallet_data["address_count"] = len(addresses)
            wallet_data["updated_at"] = datetime.utcnow().isoformat() + "Z"

            with open(path, "w", encoding="utf-8") as f:
                json.dump(wallet_data, f, indent=2)

            return {
                "ok": True,
                "wallet_id": wallet_id,
                "address_count": len(addresses),
                "addresses": addresses,
                "warning": "Endereços persistidos com sucesso."
            }

        except Exception as e:
            return {
                "ok": False,
                "error": "GENERATE_ADDRESSES_FAILED",
                "details": str(e)
            }

    def list_wallets(self):

        wallets = []

        for path in WALLET_DIR.glob("*.json"):

            try:

                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                wallets.append({

                    "wallet_id": data.get("wallet_id"),

                    "label": data.get("label"),

                    "type": data.get("type"),

                    "network": data.get("network"),

                    "created_at": data.get("created_at"),

                    "seed_hash": data.get("seed_hash"),

                    "primary_address": data.get("primary_address"),

                    "derivation": data.get("derivation"),

                    "address_count": data.get("address_count", 0)
                })

            except Exception:
                continue

        return {
            "ok": True,
            "wallets": wallets
        }
