from pathlib import Path


TX_PLAN_DIR = Path("data/wallet_core/tx_plans")
SIGNED_RAW_DIR = Path("data/wallet_core/signed_raw")


class CleanPlansService:

    def clean(self):
        removed_plans = 0
        removed_signed = 0

        TX_PLAN_DIR.mkdir(parents=True, exist_ok=True)
        SIGNED_RAW_DIR.mkdir(parents=True, exist_ok=True)

        for path in TX_PLAN_DIR.glob("*.json"):
            path.unlink(missing_ok=True)
            removed_plans += 1

        for path in SIGNED_RAW_DIR.glob("*.signed.hex"):
            path.unlink(missing_ok=True)
            removed_signed += 1

        return {
            "ok": True,
            "removed_plans": removed_plans,
            "removed_signed_raw": removed_signed,
            "warning": "UTXOs e wallet preservados."
        }
