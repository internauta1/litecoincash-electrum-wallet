"""
Experimental read-only ElectrumX wallet preview.

Values are server-reported and NOT SPV verified.
Never use these values for spending decisions.
No wallet database writes.
"""

import asyncio
import os

from .bitcoin import address_to_scripthash


async def fetch_unverified_wallet_preview(
    network,
    wallet,
    *,
    max_addresses=200,
    concurrency=6,
    timeout=12,
):
    if os.environ.get(
        "ELECTRUM_LCC_EXPERIMENTAL_WALLET_SYNC"
    ) != "1":
        raise RuntimeError(
            "Experimental wallet preview disabled"
        )

    addresses = list(dict.fromkeys(
        wallet.get_addresses()
    ))

    if (
        len(addresses) > max_addresses
        or not all(
            isinstance(a, str) and a
            for a in addresses
        )
    ):
        raise ValueError(
            "Invalid or excessive wallet address set"
        )

    interface = network.interface

    if interface is None:
        raise ConnectionError(
            "ElectrumX interface unavailable"
        )

    semaphore = asyncio.Semaphore(concurrency)

    async def query_address(address):
        sh = address_to_scripthash(address)

        async with semaphore:
            async def request(method):
                return await asyncio.wait_for(
                    getattr(interface, method)(sh),
                    timeout=timeout,
                )

            balance, history, utxos = await asyncio.gather(
                request("get_balance_for_scripthash"),
                request("get_history_for_scripthash"),
                request("listunspent_for_scripthash"),
            )

        if (
            not isinstance(balance, dict)
            or not isinstance(history, list)
            or not isinstance(utxos, list)
        ):
            raise ValueError(
                "Unexpected ElectrumX response"
            )

        confirmed = balance.get("confirmed")
        unconfirmed = balance.get("unconfirmed")

        if (
            type(confirmed) is not int
            or confirmed < 0
            or type(unconfirmed) is not int
        ):
            raise ValueError(
                "Invalid server balance"
            )

        return (
            confirmed,
            unconfirmed,
            len(history),
            len(utxos),
        )

    results = await asyncio.gather(
        *(query_address(a) for a in addresses),
        return_exceptions=True,
    )

    errors = sum(
        isinstance(result, BaseException)
        for result in results
    )

    if network.interface is not interface:
        errors += 1

    if errors:
        # Never expose a partial sum as the full wallet balance.
        return {
            "status": "incomplete",
            "source": "electrumx",
            "spv_verified": False,
            "address_count": len(addresses),
            "failed_queries": errors,
            "confirmed_sats": None,
            "unconfirmed_sats": None,
            "history_entries": None,
            "utxo_count": None,
        }

    return {
        "status": "server_unverified",
        "source": "electrumx",
        "spv_verified": False,
        "address_count": len(addresses),
        "failed_queries": 0,
        "confirmed_sats": sum(x[0] for x in results),
        "unconfirmed_sats": sum(x[1] for x in results),
        "history_entries": sum(x[2] for x in results),
        "utxo_count": sum(x[3] for x in results),
    }
