import sqlite3
import os
from datetime import datetime


class Database:
    def __init__(self, db_path="aes_keys.db"):
        self.db_path = db_path
        self._create_table()

    def _create_table(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS aes_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    group_id TEXT,
                    aes_key BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            conn.commit()

    def insert_key(self, aes_key: bytes, user_id: str = None, group_id: str = None):
        created_at = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO aes_keys (user_id, group_id, aes_key, created_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, group_id, aes_key, created_at))
            conn.commit()
            return cursor.lastrowid

    def get_key_by_id(self, key_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT aes_key FROM aes_keys WHERE id = ?', (key_id,))
            row = cursor.fetchone()
            return row[0] if row else None

    def get_keys_by_user(self, user_id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, aes_key FROM aes_keys WHERE user_id = ?', (user_id,))
            return cursor.fetchall()

    def delete_key_by_id(self, key_id: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM aes_keys WHERE id = ?', (key_id,))
            conn.commit()

    def list_all_keys(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, user_id, group_id, created_at FROM aes_keys')
            return cursor.fetchall()
