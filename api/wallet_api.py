import os

from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.wallet_core_v1.access_token_service import AccessTokenService
from core.wallet_core_v1.electrumx_broadcast_service import ElectrumXBroadcastService
from core.wallet_core_v1.final_validate_service import FinalValidateService
from core.wallet_core_v1.raw_sign_service import RawSignService
from core.wallet_core_v1.tx_builder_service import TxBuilderService
from core.wallet_core_v1.wallet_balance_service import WalletBalanceService
from core.wallet_core_v1.wallet_summary_service import WalletSummaryService
from core.wallet_core_v1.utxo_sync_service import UtxoSyncService
from core.wallet_core_v1.wallet_history_detail_service import WalletHistoryDetailService


app = FastAPI(
    title="LCC Wallet API",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://wallet.litecoincash.com.br",
        "http://wallet.litecoincash.com.br",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

access_token_service = AccessTokenService()
broadcast_service = ElectrumXBroadcastService()
final_validate_service = FinalValidateService()
raw_sign_service = RawSignService()
tx_builder_service = TxBuilderService()
balance_service = WalletBalanceService()
summary_service = WalletSummaryService()
sync_service = UtxoSyncService()
history_detail_service = WalletHistoryDetailService()


class PrepareSendRequest(BaseModel):
    to_address: str
    amount_lcc: float


class SignRawRequest(BaseModel):
    plan_id: str
    password: str


class ValidateFinalRequest(BaseModel):
    plan_id: str


class BroadcastRequest(BaseModel):
    plan_id: str
    confirm: str
    confirm2: str


def require_wallet_token(wallet_id: str, token: str, required: str):
    return access_token_service.verify_token(
        token=token,
        wallet_id=wallet_id,
        required=required
    )


@app.get("/")
def root():
    return {
        "ok": True,
        "service": "LCC Wallet API",
        "version": "0.2.0"
    }

@app.get("/wallet/{wallet_id}/auth-info")
def wallet_auth_info(wallet_id: str, x_wallet_token: str = Header(default=None)):
    auth = require_wallet_token(wallet_id, x_wallet_token, "VIEW")
    if not auth.get("ok"):
        return auth

    return {
        "ok": True,
        "wallet_id": wallet_id,
        "permission": auth.get("permission")
    }


@app.get("/wallet/{wallet_id}/balance")
def wallet_balance(wallet_id: str, x_wallet_token: str = Header(default=None)):
    auth = require_wallet_token(wallet_id, x_wallet_token, "VIEW")
    if not auth.get("ok"):
        return auth

    return balance_service.get_balance(wallet_id)


@app.get("/wallet/{wallet_id}/summary")
def wallet_summary(wallet_id: str, x_wallet_token: str = Header(default=None)):
    auth = require_wallet_token(wallet_id, x_wallet_token, "VIEW")
    if not auth.get("ok"):
        return auth

    return summary_service.get_summary(wallet_id)


@app.post("/wallet/{wallet_id}/sync")
def wallet_sync(wallet_id: str, x_wallet_token: str = Header(default=None)):
    auth = require_wallet_token(wallet_id, x_wallet_token, "VIEW")
    if not auth.get("ok"):
        return auth

    return sync_service.sync_wallet_utxos(wallet_id)


@app.get("/wallet/{wallet_id}/history-detail")
def wallet_history_detail(wallet_id: str, x_wallet_token: str = Header(default=None)):
    auth = require_wallet_token(wallet_id, x_wallet_token, "VIEW")
    if not auth.get("ok"):
        return auth

    return history_detail_service.get_detail(wallet_id)


@app.post("/wallet/{wallet_id}/prepare-send")
def wallet_prepare_send(
    wallet_id: str,
    req: PrepareSendRequest,
    x_wallet_token: str = Header(default=None)
):
    auth = require_wallet_token(wallet_id, x_wallet_token, "SPEND")
    if not auth.get("ok"):
        return auth

    return tx_builder_service.prepare_send(
        wallet_id=wallet_id,
        to_address=req.to_address,
        amount_lcc=req.amount_lcc
    )


@app.post("/wallet/{wallet_id}/sign-raw")
def wallet_sign_raw(
    wallet_id: str,
    req: SignRawRequest,
    x_wallet_token: str = Header(default=None)
):
    auth = require_wallet_token(wallet_id, x_wallet_token, "SPEND")
    if not auth.get("ok"):
        return auth

    result = raw_sign_service.sign_raw(
        plan_id=req.plan_id,
        password=req.password
    )

    if result.get("wallet_id") and result.get("wallet_id") != wallet_id:
        return {
            "ok": False,
            "error": "WALLET_ID_MISMATCH",
            "plan_wallet_id": result.get("wallet_id"),
            "url_wallet_id": wallet_id
        }

    return result


@app.post("/wallet/{wallet_id}/validate-final")
def wallet_validate_final(
    wallet_id: str,
    req: ValidateFinalRequest,
    x_wallet_token: str = Header(default=None)
):
    auth = require_wallet_token(wallet_id, x_wallet_token, "SPEND")
    if not auth.get("ok"):
        return auth

    result = final_validate_service.validate_final(
        plan_id=req.plan_id
    )

    if result.get("wallet_id") and result.get("wallet_id") != wallet_id:
        return {
            "ok": False,
            "error": "WALLET_ID_MISMATCH",
            "plan_wallet_id": result.get("wallet_id"),
            "url_wallet_id": wallet_id
        }

    return result


@app.post("/wallet/{wallet_id}/broadcast")
def wallet_broadcast(
    wallet_id: str,
    req: BroadcastRequest,
    x_wallet_token: str = Header(default=None)
):
    auth = require_wallet_token(wallet_id, x_wallet_token, "SPEND")
    if not auth.get("ok"):
        return auth

    if req.confirm != "BROADCAST":
        return {
            "ok": False,
            "error": "CANCELLED_STEP_1"
        }

    if req.confirm2 != "ENVIAR":
        return {
            "ok": False,
            "error": "CANCELLED_STEP_2"
        }

    validation = final_validate_service.validate_final(
        plan_id=req.plan_id
    )

    if validation.get("wallet_id") and validation.get("wallet_id") != wallet_id:
        return {
            "ok": False,
            "error": "WALLET_ID_MISMATCH",
            "plan_wallet_id": validation.get("wallet_id"),
            "url_wallet_id": wallet_id
        }

    if not validation.get("ready_for_broadcast"):
        return {
            "ok": False,
            "error": "VALIDATION_FAILED",
            "validation": validation
        }

    return broadcast_service.broadcast_plan(
        plan_id=req.plan_id
    )
