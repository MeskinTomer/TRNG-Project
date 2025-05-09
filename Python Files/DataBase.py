import sqlite3
import pickle
from typing import Optional, List


class ProtocolDatabase:
    def __init__(self, db_path: str = "protocol_instances.db"):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protocol_objects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL UNIQUE,
                    obj_data BLOB NOT NULL
                )
            ''')
            conn.commit()

    def insert_instance(self, client_id: str, instance) -> int:
        data = pickle.dumps(instance)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO protocol_objects (client_id, obj_data) 
                VALUES (?, ?)
            ''', (client_id, data))
            conn.commit()
            return cursor.lastrowid

    def update_instance(self, client_id: str, instance) -> bool:
        if not self.has_instance(client_id):
            return False
        data = pickle.dumps(instance)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE protocol_objects SET obj_data = ? WHERE client_id = ?
            ''', (data, client_id))
            conn.commit()
            return True

    def has_instance(self, client_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM protocol_objects WHERE client_id = ?', (client_id,))
            return cursor.fetchone() is not None

    def get_instance_by_client_id(self, client_id: str) -> Optional[object]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT obj_data FROM protocol_objects WHERE client_id = ?', (client_id,))
            row = cursor.fetchone()
            return pickle.loads(row[0]) if row else None

    def delete_instance_by_client_id(self, client_id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM protocol_objects WHERE client_id = ?', (client_id,))
            conn.commit()

    def list_all_instances(self) -> List[tuple[str, object]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT client_id, obj_data FROM protocol_objects')
            rows = cursor.fetchall()
            return [(client_id, pickle.loads(obj_data)) for client_id, obj_data in rows]


if __name__ == "__main__":
    import logging
    from Protocol import Protocol

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    db = ProtocolDatabase("test_clients.db")

    # Store protocol instances
    for client in ["alice", "bob", "charlie"]:
        proto = Protocol()
        db.insert_instance(client, proto)
        print(f"✅ Stored protocol for {client}")

    # Retrieve
    print("\n📥 Retrieving individual clients:")
    for client in ["alice", "bob", "charlie"]:
        obj = db.get_instance_by_client_id(client)
        print(f" - {client}: {obj}")

    # List all
    print("\n📋 All stored clients:")
    for client_id, instance in db.list_all_instances():
        print(f" - {client_id}: {instance}")

    # Optional delete
    db.delete_instance_by_client_id("bob")
    print("\n🗑️ Deleted Bob's instance.")

    new_alice_instance = Protocol()
    db.update_instance("alice", new_alice_instance)