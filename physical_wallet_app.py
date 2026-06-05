from pathlib import Path
from datetime import datetime, UTC
import html
import shutil
import webbrowser

import qrcode

from core.wallet_core_v1.wallet_core_service import WalletCoreService
from core.wallet_core_v1.lcc_address import lcc_address_from_mnemonic


OUT_DIR = Path("physical_wallet_output")
ASSETS_DIR = Path("assets")


def make_qr(text: str, path: Path):
    img = qrcode.make(text)
    img.save(path)


def main():
    print("LitecoinCash Physical Wallet Generator")
    print("--------------------------------------")
    print("Creates a printable physical wallet.")
    print("Seed is included as text only. No seed QR is generated.")
    print()

    label = input("Wallet label [physical-wallet]: ").strip() or "physical-wallet"

    password = input("Password to encrypt wallet locally: ").strip()
    confirm = input("Confirm password: ").strip()

    if password != confirm:
        print("ERROR: passwords do not match.")
        return

    svc = WalletCoreService()

    seed_choice = input("Seed words [12/24, default 24]: ").strip()

    seed_words = 24

    if seed_choice == "12":
        seed_words = 12

    elif seed_choice == "24" or seed_choice == "":
        seed_words = 24

    else:
        print("ERROR: choose 12 or 24.")
        return

    created = svc.create_wallet(
        label=label,
        password=password,
        seed_words=seed_words
    )

    if not created.get("ok"):
        print(created)
        return

    wallet_id = created["wallet_id"]

    exported = svc.export_seed(wallet_id=wallet_id, password=password)

    if not exported.get("ok"):
        print(exported)
        return

    seed_phrase = exported["seed_phrase"]

    legacy_info = lcc_address_from_mnemonic(
     mnemonic_words=seed_phrase,
     path="m/44'/192'/0'/0/0"
    )

    segwit_info = lcc_address_from_mnemonic(
      mnemonic_words=seed_phrase,
      path="m/84'/192'/0'/0/0"
    )

    legacy = legacy_info["address"]
    segwit = segwit_info["segwit_address"]

    legacy_path = legacy_info["derivation"]
    segwit_path = segwit_info["derivation"]
    out = OUT_DIR / wallet_id
    out.mkdir(parents=True, exist_ok=True)

    qr_legacy = out / "qr_legacy.png"
    qr_segwit = out / "qr_segwit.png"
    logo_src = ASSETS_DIR / "logo.png"
    logo_dst = out / "logo.png"

    make_qr(legacy, qr_legacy)
    make_qr(segwit, qr_segwit)

    if logo_src.exists():
        shutil.copyfile(logo_src, logo_dst)

    created_at = datetime.now(UTC).isoformat()

    seed_words = seed_phrase.split()
    seed_slots = []

    for i in range(24):
        word = seed_words[i] if i < len(seed_words) else ""
        seed_slots.append(
            f"<span><b>{i + 1}.</b> {html.escape(word)}</span>"
        )

    seed_html = ""

    for i in range(0, 24, 4):
        seed_html += (
            "<div class='seed-row'>"
            + "".join(seed_slots[i:i + 4])
            + "</div>\n"
        )

    index = out / "index.html"

    page = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>LitecoinCash Physical Wallet</title>
<style>
body {{
  font-family: Segoe UI, Arial, sans-serif;
  background: #0f1115;
  margin: 0;
  padding: 30px;
  color: white;
}}

.wallet {{
  max-width: 1100px;
  margin: auto;
  background: linear-gradient(180deg,#1c1f26,#111319);
  border: 3px solid #5bd15b;
  border-radius: 18px;
  overflow: hidden;
  box-shadow: 0 0 30px rgba(0,0,0,.45);
}}

.header {{
  text-align: center;
  padding: 30px;
  background: #15181f;
  border-bottom: 2px solid #2f3542;
}}

.logo {{
  width: 120px;
  margin-bottom: 10px;
}}

.title {{
  font-size: 36px;
  font-weight: bold;
  color: #7cff7c;
}}

.subtitle {{
  color: #cfcfcf;
  font-size: 16px;
}}

.meta {{
  color: #9fa6b2;
  font-size: 12px;
}}

.grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 25px;
  padding: 30px;
}}

.box {{
  background: #181b22;
  border: 1px solid #2c313d;
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}}

.box h2 {{
  color: #7cff7c;
}}

.addr {{
  font-family: Consolas, monospace;
  word-break: break-all;
  font-size: 13px;
  margin-top: 15px;
}}

.private {{
  margin: 20px 30px 30px;
  padding: 25px;
  background: #181b22;
  border: 1px solid #2c313d;
  border-radius: 12px;
}}

.private h2 {{
  color: #7cff7c;
}}

.seed-row {{
  display: grid;
  grid-template-columns: repeat(4,1fr);
  gap: 10px;
  margin-bottom: 10px;
}}

.seed-row span {{
  background: #101216;
  border: 1px solid #2f3542;
  padding: 8px;
  border-radius: 6px;
  font-family: Consolas, monospace;
}}

.warning {{
  margin: 20px 30px 30px;
  background: #311313;
  border: 2px solid #a73333;
  color: #ffb4b4;
  border-radius: 12px;
  padding: 15px;
  font-weight: bold;
}}

.footer {{
  text-align: center;
  padding: 15px;
  color: #9fa6b2;
  border-top: 1px solid #2f3542;
}}

@media print {{
  body {{
    background: white;
    padding: 0;
  }}

  .wallet {{
    box-shadow: none;
  }}
}}
</style>
</head>
<body>
<div class="wallet">
  <div class="header">
    <img src="logo.png" class="logo">
    <div class="title">Litecoin Cash</div>
    <div class="subtitle">Physical Wallet v1.3</div>
     <p class="meta">BIP39 • SLIP44 Coin Type 192 • Electrum-LCC / Gleec Compatible</p>
     <p class="meta">Wallet ID: {html.escape(wallet_id)}</p>
     <p class="meta">Created: {html.escape(created_at)}</p>
  </div>

  <div class="grid">
    <div class="box">
      <h2>Legacy Address</h2>
      <img src="qr_legacy.png" width="220">
      <p class="addr">{html.escape(legacy)}</p>
      <p class="meta">Path: {html.escape(legacy_path)}</p>
    </div>

    <div class="box">
      <h2>SegWit Address</h2>
      <img src="qr_segwit.png" width="220">
      <p class="addr">{html.escape(segwit)}</p>
      <p class="meta">Path: {html.escape(segwit_path)}</p>
    </div>
  </div>

  <div class="private">
    <h2>Private Recovery Seed</h2>
     <p>
      Seed type: BIP39. Use this seed with the derivation paths shown above.
     </p>
    <p>Keep these words private. Anyone with this seed can spend the funds.</p>
    {seed_html}
  </div>

  <div class="warning">
    WARNING: Print offline. Do not upload this file. Do not save as PDF unless you understand the risk.
  </div>

  <div class="footer">
    LitecoinCash Physical Wallet — Beta
  </div>
</div>
</body>
</html>
"""

    index.write_text(page, encoding="utf-8")

    print()
    print("OK: Physical wallet generated.")
    print("Wallet ID:", wallet_id)
    print("Legacy:", legacy)
    print("SegWit:", segwit)
    print("HTML:", index)
    print()
    print("Opening HTML...")
    webbrowser.open(index.resolve().as_uri())


if __name__ == "__main__":
    main()
