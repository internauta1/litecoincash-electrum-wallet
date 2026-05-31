import secrets
import sqlite3
import time
from pathlib import Path


ACCESS_DB = Path("data/access_tokens.db")


class AccessTokenService:

    def _connect(self):
        ACCESS_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(ACCESS_DB))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self._connect()
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                label TEXT,
                active INTEGER DEFAULT 1,
                created_at INTEGER,
                last_used_at INTEGER
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_wallet_id ON access_tokens(wallet_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_active ON access_tokens(active)")

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "db": str(ACCESS_DB),
            "warning": "Access token DB pronto."
        }

    def create_token(self, wallet_id: str, permission: str, label: str = None):
        self.init_db()

        permission = permission.upper().strip()

        if permission not in ("VIEW", "SPEND", "ADMIN"):
            return {
                "ok": False,
                "error": "INVALID_PERMISSION",
                "allowed": ["VIEW", "SPEND", "ADMIN"]
            }

        token = secrets.token_urlsafe(32)
        now = int(time.time())

        conn = self._connect()
        c = conn.cursor()

        c.execute("""
            INSERT INTO access_tokens (
                token, wallet_id, permission, label, active, created_at, last_used_at
            )
            VALUES (?, ?, ?, ?, 1, ?, NULL)
        """, (
            token,
            wallet_id,
            permission,
            label,
            now
        ))

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "permission": permission,
            "label": label,
            "token": token,
            "warning": "Guarda este token. Ele só deve ser mostrado uma vez."
        }

    def verify_token(self, token: str, wallet_id: str, required: str):
        self.init_db()

        if not token:
            return {
                "ok": False,
                "error": "TOKEN_REQUIRED"
            }

        required = required.upper().strip()

        conn = self._connect()
        c = conn.cursor()

        c.execute("""
            SELECT *
            FROM access_tokens
            WHERE token = ?
              AND wallet_id = ?
              AND active = 1
            LIMIT 1
        """, (
            token,
            wallet_id
        ))

        row = c.fetchone()

        if not row:
            conn.close()
            return {
                "ok": False,
                "error": "INVALID_TOKEN"
            }

        permission = row["permission"]

        allowed = False

        if permission == "ADMIN":
            allowed = True
        elif permission == "SPEND" and required in ("VIEW", "SPEND"):
            allowed = True
        elif permission == "VIEW" and required == "VIEW":
            allowed = True

        if not allowed:
            conn.close()
            return {
                "ok": False,
                "error": "INSUFFICIENT_PERMISSION",
                "token_permission": permission,
                "required": required
            }

        now = int(time.time())

        c.execute("""
            UPDATE access_tokens
            SET last_used_at = ?
            WHERE token = ?
        """, (
            now,
            token
        ))

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "permission": permission
        }

    def list_tokens(self, wallet_id: str):
        self.init_db()

        conn = self._connect()
        c = conn.cursor()

        c.execute("""
            SELECT wallet_id, permission, label, active, created_at, last_used_at,
                   substr(token, 1, 8) || '...' AS token_preview
            FROM access_tokens
            WHERE wallet_id = ?
            ORDER BY created_at DESC
        """, (
            wallet_id,
        ))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()

        return {
            "ok": True,
            "wallet_id": wallet_id,
            "tokens": rows
        }

    def revoke_token(self, token: str):
        self.init_db()

        conn = self._connect()
        c = conn.cursor()

        c.execute("""
            UPDATE access_tokens
            SET active = 0
            WHERE token = ?
        """, (
            token,
        ))

        changed = c.rowcount

        conn.commit()
        conn.close()

        return {
            "ok": True,
            "revoked": changed
        }
