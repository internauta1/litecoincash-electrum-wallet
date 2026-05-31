import sqlite3
import os


class UTXODB:

    def __init__(self):

        os.makedirs(
            "wallet_data",
            exist_ok=True
        )

        self.conn = sqlite3.connect(
            "wallet_data/utxos.db"
        )

        self.create_tables()

    #
    # CREATE TABLES
    #
    def create_tables(self):

        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS utxos (

            txid TEXT,
            vout INTEGER,
            address TEXT,
            value INTEGER,
            height INTEGER,

            PRIMARY KEY (
                txid,
                vout
            )
        )
        """)

        self.conn.commit()

    #
    # SAVE UTXO
    #
    def save_utxo(
        self,
        txid,
        vout,
        address,
        value,
        height
    ):

        cur = self.conn.cursor()

        cur.execute("""
        INSERT OR REPLACE INTO utxos
        VALUES (?, ?, ?, ?, ?)
        """, (
            txid,
            vout,
            address,
            value,
            height
        ))

        self.conn.commit()

    #
    # GET ALL
    #
    def get_utxos(self):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT * FROM utxos
        """)

        rows = cur.fetchall()

        result = []

        for r in rows:

            result.append({

                "txid": r[0],
                "vout": r[1],
                "address": r[2],
                "value": r[3],
                "height": r[4]
            })

        return result

    #
    # BALANCE
    #
    def get_balance(self):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT SUM(value)
        FROM utxos
        """)

        val = cur.fetchone()[0]

        return val or 0

    #
    # CLEAR
    #
    def clear(self):

        cur = self.conn.cursor()

        cur.execute("""
        DELETE FROM utxos
        """)

        self.conn.commit()
