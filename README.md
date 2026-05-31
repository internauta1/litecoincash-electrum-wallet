# LCC Wallet V1

Community wallet for Litecoin Cash (LCC).

This is the first public release candidate of the LCC Wallet backend/API.

## Features

- BIP39 seed wallet
- HD derivation: m/44'/2'/0'/0/x
- Legacy LCC addresses: C...
- Send to C... addresses
- Send to lcc1... Bech32 / SegWit addresses
- ElectrumX backend support
- Encrypted wallet storage
- Backup and restore
- Prepare transaction
- Sign raw transaction
- Validate transaction
- Broadcast transaction
- Local UTXO tracking

## Current status

Stable V1 release candidate.

Supported:

- Receive to C... addresses
- Spend from C... addresses
- Send to C... addresses
- Send to lcc1... addresses

Not yet supported:

- Native internal lcc1 wallet addresses
- Spending from lcc1 UTXOs
- Google login / encrypted cloud backup
- Desktop app installer

These are planned for V2.

## Security

This is intended to be a non-custodial wallet.

Users must save their seed phrase.

The server must never store plain seed phrases.

Use small amounts first. This software is under active development.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn api.wallet_api:app --host 0.0.0.0 --port 8080
curl http://127.0.0.1:8080/
