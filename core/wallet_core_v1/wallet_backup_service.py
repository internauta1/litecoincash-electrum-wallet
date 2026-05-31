import json
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet


WALLET_DIR = Path("data/wallet_core")
BACKUP_DIR = Path("data/wallet_core/backups")


class WalletBackupService:

    @staticmethod
    def _derive_key(password: str):
        digest = hashlib.sha256(password.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def _wallet_path(wallet_id: str):
        return WALLET_DIR / f"{wallet_id}.json"

    @staticmethod
    def export_wallet(wallet_id: str, password: str):
        wallet_path = WalletBackupService._wallet_path(wallet_id)

        if not wallet_path.exists():
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND",
                "wallet_path": str(wallet_path)
            }

        if not password or len(password) < 8:
            return {
                "ok": False,
                "error": "WEAK_BACKUP_PASSWORD",
                "message": "Use uma password de backup com pelo menos 8 caracteres."
            }

        wallet_data = json.loads(wallet_path.read_text(encoding="utf-8"))

        key = WalletBackupService._derive_key(password)
        fernet = Fernet(key)

        encrypted_wallet_json = fernet.encrypt(
            json.dumps(wallet_data, ensure_ascii=False, indent=2).encode("utf-8")
        ).decode("utf-8")

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_file = BACKUP_DIR / f"backup_{wallet_id}_{timestamp}.json"

        backup_data = {
            "ok": True,
            "backup_version": 1,
            "type": "encrypted_lcc_wallet_backup",
            "wallet_id": wallet_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "encryption": "fernet_sha256_password_key",
            "encrypted_wallet_json": encrypted_wallet_json,
            "warning": "Backup encriptado. Sem a password de backup não é possível restaurar."
        }

        backup_file.write_text(
            json.dumps(backup_data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "backup_file": str(backup_file),
            "warning": "Backup criado. Guarda este ficheiro e a password em local seguro."
        }

    @staticmethod
    def decrypt_backup_file(backup_file: str, password: str):
        path = Path(backup_file)

        if not path.exists():
            return {
                "ok": False,
                "error": "BACKUP_FILE_NOT_FOUND"
            }

        backup_data = json.loads(path.read_text(encoding="utf-8"))

        encrypted_wallet_json = backup_data.get("encrypted_wallet_json")

        if not encrypted_wallet_json:
            return {
                "ok": False,
                "error": "INVALID_BACKUP_FILE"
            }

        try:
            key = WalletBackupService._derive_key(password)
            fernet = Fernet(key)

            wallet_json = fernet.decrypt(
                encrypted_wallet_json.encode("utf-8")
            ).decode("utf-8")

            wallet_data = json.loads(wallet_json)

            return {
                "ok": True,
                "wallet_id": wallet_data.get("wallet_id"),
                "wallet": wallet_data
            }

        except Exception:
            return {
                "ok": False,
                "error": "DECRYPT_FAILED",
                "message": "Password errada ou backup corrompido."
            }
    @staticmethod
    def import_backup(backup_file: str, password: str):
        result = WalletBackupService.decrypt_backup_file(
            backup_file=backup_file,
            password=password
        )

        if not result.get("ok"):
            return result

        wallet_data = result.get("wallet")

        if not wallet_data:
            return {
                "ok": False,
                "error": "INVALID_WALLET_DATA"
            }

        wallet_id = wallet_data.get("wallet_id")

        if not wallet_id:
            return {
                "ok": False,
                "error": "INVALID_WALLET_ID"
            }

        WALLET_DIR.mkdir(parents=True, exist_ok=True)

        wallet_path = WALLET_DIR / f"{wallet_id}.json"

        wallet_path.write_text(
            json.dumps(wallet_data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "restored_to": str(wallet_path),
            "message": "Wallet restaurada com sucesso."
        }
