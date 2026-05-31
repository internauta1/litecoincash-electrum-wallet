import sqlite3
import os


class WalletDB:

    def __init__(self):

        os.makedirs(
            "wallet_data",
            exist_ok=True
        )

        self.conn = sqlite3.connect(
            "wallet_data/wallet.db"
        )

        self.conn.row_factory = sqlite3.Row

        self.create_tables()

    # -------------------------
    # TABLES
    # -------------------------
    def create_tables(self):

        cur = self.conn.cursor()

        #
        # ADDRESSES
        #
        cur.execute("""
        CREATE TABLE IF NOT EXISTS addresses (

            id INTEGER PRIMARY KEY,

            addr TEXT UNIQUE,

            idx INTEGER,

            used INTEGER DEFAULT 0
        )
        """)

        #
        # UTXOS
        #
        cur.execute("""
        CREATE TABLE IF NOT EXISTS utxos (

            id INTEGER PRIMARY KEY,

            txid TEXT,
            vout INTEGER,

            address TEXT,

            value INTEGER,

            height INTEGER,

            spent INTEGER DEFAULT 0
        )
        """)

        #
        # TX HISTORY
        #
        cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (

            id INTEGER PRIMARY KEY,

            txid TEXT UNIQUE,

            amount INTEGER,

            height INTEGER
        )
        """)

        self.conn.commit()

    # -------------------------
    # SAVE ADDRESS
    # -------------------------
    def save_address(self, addr, idx):

        cur = self.conn.cursor()

        cur.execute("""
        INSERT OR IGNORE INTO addresses (
            addr,
            idx
        )
        VALUES (?, ?)
        """, (
            addr,
            idx
        ))

        self.conn.commit()

    # -------------------------
    # SAVE UTXO
    # -------------------------
    def save_utxo(self, utxo, address):

        cur = self.conn.cursor()

        cur.execute("""
        INSERT INTO utxos (

            txid,
            vout,
            address,
            value,
            height

        )
        VALUES (?, ?, ?, ?, ?)
        """, (

            utxo["tx_hash"],
            utxo["tx_pos"],
            address,
            utxo["value"],
            utxo["height"]

        ))

        self.conn.commit()

    # -------------------------
    # GET BALANCE
    # -------------------------
    def get_balance(self):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT SUM(value)
        as total

        FROM utxos

        WHERE spent = 0
        """)

        row = cur.fetchone()

        if row["total"] is None:
            return 0

        return row["total"]

    # -------------------------
    # GET UTXOS
    # -------------------------
    def get_utxos(self):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT *
        FROM utxos

        WHERE spent = 0
        """)

        return cur.fetchall()
