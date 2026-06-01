#!/usr/bin/env python3

import argparse
import getpass
import json

from core.wallet_core_v1.wallet_backup_service import WalletBackupService
from core.wallet_core_v1.access_token_service import AccessTokenService
from core.wallet_core_v1.wallet_summary_service import WalletSummaryService
from core.wallet_core_v1.wallet_history_detail_service import WalletHistoryDetailService
from core.wallet_core_v1.wallet_history_real_service import WalletHistoryRealService
from core.wallet_core_v1.clean_plans_service import CleanPlansService
from core.wallet_core_v1.utxo_sync_service import UtxoSyncService
from core.wallet_core_v1.utxo_update_service import UtxoUpdateService
from core.wallet_core_v1.electrumx_broadcast_service import ElectrumXBroadcastService
from core.wallet_core_v1.broadcast_service import BroadcastService
from core.wallet_core_v1.final_validate_service import FinalValidateService
from core.wallet_core_v1.wallet_check_service import WalletCheckService
from core.wallet_core_v1.raw_decode_service import RawDecodeService
from core.wallet_core_v1.raw_sign_service import RawSignService
from core.wallet_core_v1.raw_tx_service import RawTxService
from core.wallet_core_v1.tx_signer_service import TxSignerService
from core.wallet_core_v1.wallet_core_service import WalletCoreService
from core.wallet_core_v1.wallet_balance_service import WalletBalanceService
from core.wallet_core_v1.tx_builder_service import TxBuilderService



access_token_service = AccessTokenService()
summary_service = WalletSummaryService()
history_detail_service = WalletHistoryDetailService()
history_real_service = WalletHistoryRealService()
utxo_sync_service = UtxoSyncService()
utxo_update_service = UtxoUpdateService()
electrumx_broadcast_service = ElectrumXBroadcastService()
broadcast_service = BroadcastService()
final_validate_service = FinalValidateService()
wallet_check_service = WalletCheckService()
raw_decode_service = RawDecodeService()
service = WalletCoreService()
balance_service = WalletBalanceService()
tx_builder = TxBuilderService()
tx_signer = TxSignerService()
raw_tx_service = RawTxService()
raw_sign_service = RawSignService()


def cmd_init_access_db(args):
    result = access_token_service.init_db()
    pretty(result)


def cmd_create_access_token(args):
    result = access_token_service.create_token(
        wallet_id=args.wallet_id,
        permission=args.permission,
        label=args.label
    )
    pretty(result)


def cmd_list_access_tokens(args):
    result = access_token_service.list_tokens(
        wallet_id=args.wallet_id
    )
    pretty(result)


def cmd_revoke_access_token(args):
    result = access_token_service.revoke_token(
        token=args.token
    )
    pretty(result)


def cmd_summary(args):
    result = summary_service.get_summary(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_history_detail(args):
    result = history_detail_service.get_detail(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_history_real(args):
    result = history_real_service.get_history(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_clean_plans(args):
    service = CleanPlansService()
    result = service.clean()
    print(json.dumps(result, indent=2))

def cmd_sync_utxo(args):
    result = utxo_sync_service.sync_wallet_utxos(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_apply_utxo_update(args):
    result = utxo_update_service.apply_broadcast_result(
        plan_id=args.plan_id,
        txid=args.txid
    )

    pretty(result)

def cmd_broadcast_electrumx(args):
    validation = final_validate_service.validate_final(
        plan_id=args.plan_id
    )

def cmd_export_backup(args):
    password = input("Password para encriptar backup: ").strip()

    result = WalletBackupService.export_wallet(
        wallet_id=args.wallet_id,
        password=password
    )

    pretty(result)

def cmd_test_backup(args):
    password = input("Password do backup: ").strip()

    result = WalletBackupService.decrypt_backup_file(
        backup_file=args.backup_file,
        password=password
    )

    if result.get("ok"):
        pretty({
            "ok": True,
            "wallet_id": result.get("wallet_id"),
            "message": "Backup desencriptado com sucesso."
        })
        return

    pretty(result)
    return

def cmd_import_backup(args):
    password = input("Password do backup: ").strip()

    result = WalletBackupService.import_backup(
        backup_file=args.backup_file,
        password=password
    )

    pretty(result)


def cmd_broadcast_safe(args):
    validation = final_validate_service.validate_final(
        plan_id=args.plan_id
    )

    pretty({
        "pre_broadcast_validation": validation
    })

    if not validation.get("ready_for_broadcast"):
        return

    print("\n⚠️  ATENÇÃO: isto vai transmitir uma transação real.")
    print("Escreva BROADCAST para continuar.")
    c1 = input("> ")

    if c1 != "BROADCAST":
        pretty({"ok": False, "error": "CANCELLED_STEP_1"})
        return

    print("Confirma novamente. Escreva ENVIAR.")
    c2 = input("> ")

    if c2 != "ENVIAR":
        pretty({"ok": False, "error": "CANCELLED_STEP_2"})
        return

    result = broadcast_service.broadcast_safe(
        plan_id=args.plan_id
    )

    pretty(result)


def cmd_validate_final(args):
    result = final_validate_service.validate_final(
        plan_id=args.plan_id
    )

    pretty(result)

def cmd_dev_clear(args):
    confirm = input(
        "Isto remove UTXOs DEV e planos. Escreva LIMPAR: "
    )

    if confirm != "LIMPAR":
        pretty({
            "ok": False,
            "error": "CANCELLED"
        })
        return

    result = dev_clear_service.clear_wallet_dev_data(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_clean_plans(args):
    service = CleanPlansService()
    result = service.clean()
    pretty(result)

def cmd_check(args):
    result = wallet_check_service.check_wallet(
        wallet_id=args.wallet_id
    )

    pretty(result)

def cmd_show_raw(args):
    result = raw_decode_service.show_raw(
        plan_id=args.plan_id
    )

    pretty(result)

def cmd_decode_raw(args):
    result = raw_decode_service.decode_signed_raw(
        plan_id=args.plan_id
    )

    pretty(result)

def cmd_sign_raw_dev(args):
    password = getpass.getpass("Password da wallet: ")

    result = raw_sign_service.sign_raw_dev(
        plan_id=args.plan_id,
        password=password
    )

    pretty(result)

def cmd_input_keys(args):
    password = getpass.getpass("Password da wallet: ")

    result = tx_signer.inspect_input_keys(
        plan_id=args.plan_id,
        password=password
    )

    pretty(result)

def cmd_raw_unsigned(args):
    result = raw_tx_service.build_unsigned_raw_tx(
        plan_id=args.plan_id
    )

    pretty(result)

def cmd_verify_plan_dev(args):
    result = tx_signer.verify_signed_plan_dev(
        plan_id=args.plan_id
    )

    pretty(result)

def cmd_sign_plan_dev(args):
    password = getpass.getpass("Password da wallet: ")

    result = tx_signer.sign_plan_dev(
        plan_id=args.plan_id,
        password=password
    )

    pretty(result)

def cmd_plans(args):
    pretty(tx_builder.list_plans())


def cmd_plan(args):
    pretty(tx_builder.get_plan(args.plan_id))

def cmd_dev_fund(args):
    result = dev_fund_service.fund(
        wallet_id=args.wallet_id,
        amount_lcc=args.amount
    )

    pretty(result)

def cmd_prepare_send(args):
    result = tx_builder.prepare_send(
        wallet_id=args.wallet_id,
        to_address=args.to_address,
        amount_lcc=args.amount,
        fee_sats=args.fee
    )

    pretty(result)

def cmd_history(args):
    result = balance_service.get_balance(
        wallet_id=args.wallet_id
    )

    if not result.get("ok"):
        pretty(result)
        return

    pretty({
        "ok": True,
        "wallet_id": result["wallet_id"],
        "label": result.get("label"),
        "utxos_count": result.get("utxos_count"),
        "total_balance": result.get("total_balance"),
        "total_lcc": result.get("total_lcc"),
        "utxos": result.get("utxos", [])
    })

def pretty(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_create(args):
    password = getpass.getpass("Password da wallet: ")
    confirm = getpass.getpass("Confirmar password: ")

    if password != confirm:
        pretty({"ok": False, "error": "PASSWORDS_DO_NOT_MATCH"})
        return

    result = service.create_wallet(
        password=password,
        label=args.label
    )

    pretty(result)


def cmd_list(args):
    pretty(service.list_wallets())


def cmd_unlock(args):
    password = getpass.getpass("Password da wallet: ")

    result = service.unlock_wallet(
        wallet_id=args.wallet_id,
        password=password
    )

    pretty(result)


def cmd_addresses(args):
    password = getpass.getpass("Password da wallet: ")

    result = service.generate_and_persist_addresses(
        wallet_id=args.wallet_id,
        password=password,
        count=args.count
    )

    pretty(result)


def cmd_balance(args):
    result = balance_service.get_balance(
        wallet_id=args.wallet_id
    )

    pretty(result)


def cmd_receive(args):
    result = balance_service.get_receive_address(
        wallet_id=args.wallet_id
    )

    pretty(result)


def cmd_export_seed(args):
    print("⚠️  ATENÇÃO: Isto mostra a seed phrase.")
    print("Nunca partilhe, nunca copie para sites, nunca envie para ninguém.")

    confirm = input("Escreva EXPORTAR para continuar: ")

    if confirm != "EXPORTAR":
        pretty({"ok": False, "error": "EXPORT_CANCELLED"})
        return

    password = getpass.getpass("Password da wallet: ")

    result = service.export_seed(
        wallet_id=args.wallet_id,
        password=password
    )

    pretty(result)


def cmd_import_seed(args):
    print("⚠️  Importar seed phrase.")

    seed = getpass.getpass("Seed phrase: ")
    password = getpass.getpass("Nova password da wallet: ")
    confirm = getpass.getpass("Confirmar password: ")

    if password != confirm:
        pretty({"ok": False, "error": "PASSWORDS_DO_NOT_MATCH"})
        return

    result = service.import_seed(
        seed_phrase=seed,
        password=password,
        label=args.label
    )

    pretty(result)

def cmd_show_seed(args):
    password = input("Password da wallet: ").strip()

    service = WalletCoreService()

    result = service.export_seed(
        wallet_id=args.wallet_id,
        password=password
    )

    if not result.get("ok"):
        pretty(result)
        return

    print("\n==============================")
    print("LCC WALLET SEED PHRASE")
    print("==============================\n")

    print(result["seed_phrase"])

    print("\n==============================")
    print("ATENÇÃO:")
    print("- Quem tiver esta seed controla os fundos.")
    print("- Nunca partilhar.")
    print("- Guardar offline.")
    print("==============================\n")

def cmd_import_seed(args):
    seed_phrase = input("Seed phrase BIP39: ").strip()
    label = input("Label da nova wallet: ").strip()
    password = input("Nova password da wallet: ").strip()

    service = WalletCoreService()

    result = service.import_seed(
        seed_phrase=seed_phrase,
        label=label,
        password=password
    )

    pretty(result)


def main():
    parser = argparse.ArgumentParser(
        description="LitecoinCash Electrum Wallet CLI"
    )

    sub = parser.add_subparsers(dest="command")

    p_create = sub.add_parser("create")
    p_create.add_argument("--label", default="main")
    p_create.set_defaults(func=cmd_create)

    p_list = sub.add_parser("list")
    p_list.set_defaults(func=cmd_list)

    p_unlock = sub.add_parser("unlock")
    p_unlock.add_argument("wallet_id")
    p_unlock.set_defaults(func=cmd_unlock)

    p_addresses = sub.add_parser("addresses")
    p_addresses.add_argument("wallet_id")
    p_addresses.add_argument("--count", type=int, default=20)
    p_addresses.set_defaults(func=cmd_addresses)

    p_balance = sub.add_parser("balance")
    p_balance.add_argument("wallet_id")
    p_balance.set_defaults(func=cmd_balance)

    p_receive = sub.add_parser("receive")
    p_receive.add_argument("wallet_id")
    p_receive.set_defaults(func=cmd_receive)

    p_export = sub.add_parser("export-seed")
    p_export.add_argument("wallet_id")
    p_export.set_defaults(func=cmd_export_seed)

    p_history = sub.add_parser("history")
    p_history.add_argument("wallet_id")
    p_history.set_defaults(func=cmd_history)

    p_prepare = sub.add_parser("prepare-send")
    p_prepare.add_argument("wallet_id")
    p_prepare.add_argument("to_address")
    p_prepare.add_argument("amount", type=float)
    p_prepare.add_argument("--fee", type=int, default=10000)
    p_prepare.set_defaults(func=cmd_prepare_send)

    p_plans = sub.add_parser("plans")
    p_plans.set_defaults(func=cmd_plans)

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("plan_id")
    p_plan.set_defaults(func=cmd_plan)

    p_raw_unsigned = sub.add_parser("raw-unsigned")
    p_raw_unsigned.add_argument("plan_id")
    p_raw_unsigned.set_defaults(func=cmd_raw_unsigned)

    p_input_keys = sub.add_parser("input-keys")
    p_input_keys.add_argument("plan_id")
    p_input_keys.set_defaults(func=cmd_input_keys)

    p_sign_raw_dev = sub.add_parser("sign-raw")
    p_sign_raw_dev.add_argument("plan_id")
    p_sign_raw_dev.set_defaults(func=cmd_sign_raw_dev)

    p_decode_raw = sub.add_parser("decode-raw")
    p_decode_raw.add_argument("plan_id")
    p_decode_raw.set_defaults(func=cmd_decode_raw)

    p_show_raw = sub.add_parser("show-raw")
    p_show_raw.add_argument("plan_id")
    p_show_raw.set_defaults(func=cmd_show_raw)

    p_check = sub.add_parser("check")
    p_check.add_argument("wallet_id")
    p_check.set_defaults(func=cmd_check)

    p_validate_final = sub.add_parser("validate-final")
    p_validate_final.add_argument("plan_id")
    p_validate_final.set_defaults(func=cmd_validate_final)

    p_broadcast_safe = sub.add_parser("broadcast-safe")
    p_broadcast_safe.add_argument("plan_id")
    p_broadcast_safe.set_defaults(func=cmd_broadcast_safe)

    p_broadcast_ex = sub.add_parser("broadcast-electrumx")
    p_broadcast_ex.add_argument("plan_id")
    p_broadcast_ex.set_defaults(func=cmd_broadcast_electrumx)

    p_apply_utxo = sub.add_parser("apply-utxo-update")
    p_apply_utxo.add_argument("plan_id")
    p_apply_utxo.add_argument("txid")
    p_apply_utxo.set_defaults(func=cmd_apply_utxo_update)

    p_sync_utxo = sub.add_parser("sync-utxo")
    p_sync_utxo.add_argument("wallet_id")
    p_sync_utxo.set_defaults(func=cmd_sync_utxo)

    p_clean_plans = sub.add_parser("clean-plans")
    p_clean_plans.set_defaults(func=cmd_clean_plans)

    p_history_real = sub.add_parser("history-real")
    p_history_real.add_argument("wallet_id")
    p_history_real.set_defaults(func=cmd_history_real)

    p_history_detail = sub.add_parser("history-detail")
    p_history_detail.add_argument("wallet_id")
    p_history_detail.set_defaults(func=cmd_history_detail)

    p_summary = sub.add_parser("summary")
    p_summary.add_argument("wallet_id")
    p_summary.set_defaults(func=cmd_summary)

    p_init_access_db = sub.add_parser("init-access-db")
    p_init_access_db.set_defaults(func=cmd_init_access_db)

    p_create_access_token = sub.add_parser("create-access-token")
    p_create_access_token.add_argument("wallet_id")
    p_create_access_token.add_argument("permission")
    p_create_access_token.add_argument("--label", default=None)
    p_create_access_token.set_defaults(func=cmd_create_access_token)

    p_list_access_tokens = sub.add_parser("list-access-tokens")
    p_list_access_tokens.add_argument("wallet_id")
    p_list_access_tokens.set_defaults(func=cmd_list_access_tokens)

    p_revoke_access_token = sub.add_parser("revoke-access-token")
    p_revoke_access_token.add_argument("token")
    p_revoke_access_token.set_defaults(func=cmd_revoke_access_token)

    p_export_backup = sub.add_parser("export-backup")
    p_export_backup.add_argument("wallet_id")
    p_export_backup.set_defaults(func=cmd_export_backup)

    p_test_backup = sub.add_parser("test-backup")
    p_test_backup.add_argument("backup_file")
    p_test_backup.set_defaults(func=cmd_test_backup)

    p_import_backup = sub.add_parser("import-backup")
    p_import_backup.add_argument("backup_file")
    p_import_backup.set_defaults(func=cmd_import_backup)

    p_show_seed = sub.add_parser("show-seed")
    p_show_seed.add_argument("wallet_id")
    p_show_seed.set_defaults(func=cmd_show_seed)

    p_import_seed = sub.add_parser("import-seed")
    p_import_seed.set_defaults(func=cmd_import_seed)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
