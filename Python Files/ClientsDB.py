import sqlite3
import hashlib
import os
import re
import hmac


class ClientDatabase:
    def __init__(self, db_name="clients.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        self.conn.commit()

    @staticmethod
    def _server_hash(client_hash: str, salt: bytes) -> str:
        # Re-hash client-provided hash with PBKDF2
        return hashlib.pbkdf2_hmac('sha256', client_hash.encode(), salt, 100_000).hex()

    def insert(self, username: str, client_hash: str) -> bool:
        if not self.is_acceptable(username, client_hash):
            return False
        salt = os.urandom(16)
        server_hash = self._server_hash(client_hash, salt)
        try:
            self.cursor.execute(
                "INSERT INTO clients (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, server_hash, salt)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get(self, username: str) -> tuple[str, bytes] | None:
        self.cursor.execute(
            "SELECT password_hash, salt FROM clients WHERE username = ?",
            (username,)
        )
        result = self.cursor.fetchone()
        return result if result else None

    def does_exist(self, username: str) -> bool:
        self.cursor.execute("SELECT 1 FROM clients WHERE username = ?", (username,))
        return self.cursor.fetchone() is not None

    def delete(self, username: str) -> bool:
        self.cursor.execute("DELETE FROM clients WHERE username = ?", (username,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def is_acceptable(self, username: str, client_hash: str) -> bool:
        if len(username) < 3:
            return False
        if self.does_exist(username):
            return False
        if len(client_hash) != 64:  # Expecting SHA-256 hex digest
            return False
        if not re.fullmatch(r'[0-9a-fA-F]{64}', client_hash):
            return False
        return True

    def verify(self, username: str, client_hash: str) -> bool:
        data = self.get(username)
        if not data:
            return False
        stored_hash, salt = data
        computed_hash = self._server_hash(client_hash, salt)
        return hmac.compare_digest(stored_hash, computed_hash)

    def close(self):
        self.conn.close()
