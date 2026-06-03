import html
from pathlib import Path
from datetime import datetime

import qrcode

from core.wallet_core_v1.wallet_balance_service import WalletBalanceService
from core.wallet_core_v1.wallet_core_service import WalletCoreService


PAPER_DIR = Path("data/paper_wallets")


class PaperWalletService:

    def __init__(self):
        self.balance_service = WalletBalanceService()
        self.wallet_service = WalletCoreService()

    def generate(self, wallet_id: str):
        wallets = self.wallet_service.list_wallets()

        if not wallets.get("ok"):
            return wallets

        wallet = None

        for item in wallets.get("wallets", []):
            if item.get("wallet_id") == wallet_id:
                wallet = item
                break

        if not wallet:
            return {
                "ok": False,
                "error": "WALLET_NOT_FOUND"
            }

        balance = self.balance_service.get_balance(wallet_id)

        if not balance.get("ok"):
            return balance

        pair = None

        for item in balance.get("addresses", []):
            legacy_candidate = item.get("linked_legacy_address") or item.get("address")
            segwit_candidate = item.get("segwit_address")

            if legacy_candidate and legacy_candidate.startswith("C") and segwit_candidate:
                pair = {
                    "legacy": legacy_candidate,
                    "segwit": segwit_candidate
                }
                break

        if not pair:
            return {
                "ok": False,
                "error": "NO_LEGACY_SEGWIT_PAIR_FOUND"
            }

        legacy = pair["legacy"]
        segwit = pair["segwit"]

        out_dir = PAPER_DIR / wallet_id
        out_dir.mkdir(parents=True, exist_ok=True)

        legacy_qr = out_dir / "qr_legacy.png"
        segwit_qr = out_dir / "qr_segwit.png"

        qrcode.make(legacy).save(legacy_qr)

        if segwit:
            qrcode.make(segwit).save(segwit_qr)

        created_at = datetime.utcnow().isoformat() + "Z"

        html_file = out_dir / "index.html"

        html_file.write_text(f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>LitecoinCash Physical Wallet</title>
<style>
body {{
  font-family: Arial, sans-serif;
  background: #f4f4f4;
  padding: 30px;
}}
.wallet {{
  max-width: 900px;
  margin: auto;
  background: white;
  border: 2px solid #222;
  padding: 30px;
}}
.header {{
  text-align: center;
  border-bottom: 1px solid #ddd;
  margin-bottom: 25px;
}}
.grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 25px;
}}
.box {{
  border: 1px solid #ccc;
  padding: 20px;
  text-align: center;
}}
.addr {{
  font-family: monospace;
  word-break: break-all;
  font-size: 14px;
}}
.warning {{
  margin-top: 25px;
  padding: 15px;
  border: 2px dashed #900;
  color: #900;
  font-weight: bold;
}}
.private {{
  margin-top: 25px;
  border-top: 2px dashed #333;
  padding-top: 20px;
}}
@media print {{
  body {{ background: white; }}
  .wallet {{ border: 2px solid #000; }}
}}
</style>
</head>
<body>
<div class="wallet">
  <div class="header">
    <h1>LitecoinCash Physical Wallet</h1>
    <p>Created: {html.escape(created_at)}</p>
  </div>

  <div class="grid">
    <div class="box">
      <h2>Legacy Address</h2>
      <img src="qr_legacy.png" width="220">
      <p class="addr">{html.escape(legacy)}</p>
    </div>

    <div class="box">
      <h2>SegWit Address</h2>
      <img src="qr_segwit.png" width="220">
      <p class="addr">{html.escape(segwit or "")}</p>
    </div>
  </div>

  <div class="private">
    <h2>Private Seed Phrase</h2>
    <p>Write the seed phrase here manually. Do not store it digitally.</p>
    <p>1. __________ 2. __________ 3. __________ 4. __________</p>
    <p>5. __________ 6. __________ 7. __________ 8. __________</p>
    <p>9. __________ 10. _________ 11. _________ 12. _________</p>
    <p>13. _________ 14. _________ 15. _________ 16. _________</p>
    <p>17. _________ 18. _________ 19. _________ 20. _________</p>
    <p>21. _________ 22. _________ 23. _________ 24. _________</p>
  </div>

  <div class="warning">
    WARNING: Anyone with the seed phrase can spend the funds.
    Print offline. Do not save this as PDF with the seed filled in.
  </div>
</div>
</body>
</html>
""", encoding="utf-8")

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "legacy_address": legacy,
            "segwit_address": segwit,
            "output_dir": str(out_dir),
            "html": str(html_file),
            "qr_legacy": str(legacy_qr),
            "qr_segwit": str(segwit_qr),
            "warning": "Seed is not included. Write it manually after printing."
        }
