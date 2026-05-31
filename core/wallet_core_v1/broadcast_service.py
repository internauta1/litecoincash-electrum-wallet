import subprocess
from pathlib import Path

from core.wallet_core_v1.final_validate_service import FinalValidateService
from core.wallet_core_v1.raw_decode_service import RawDecodeService


SIGNED_RAW_DIR = Path("data/wallet_core/signed_raw")


class BroadcastService:

    def __init__(self):
        self.validator = FinalValidateService()
        self.raw_decode = RawDecodeService()

    def _signed_raw_path(self, plan_id: str) -> Path:
        return SIGNED_RAW_DIR / f"{plan_id}.signed.hex"

    def broadcast_safe(self, plan_id: str):
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

        try:
            cmd = [
                "electrum",
                "broadcast",
                raw_hex
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return {
                    "ok": False,
                    "error": "BROADCAST_FAILED",
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }

            return {
                "ok": True,
                "plan_id": plan_id,
                "broadcast_result": result.stdout.strip(),
                "warning": "Broadcast executado. Confirmar no explorer."
            }

        except FileNotFoundError:
            return {
                "ok": False,
                "error": "ELECTRUM_COMMAND_NOT_FOUND",
                "message": "Comando electrum não encontrado no sistema."
            }

        except Exception as e:
            return {
                "ok": False,
                "error": "BROADCAST_EXCEPTION",
                "details": str(e)
            }
