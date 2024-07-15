import json
from typing import Any, Dict, List

import psycopg2
import psycopg2.extras
from presidio_analyzer import Pattern


class Database:
    def __init__(self, host, database, user, password):
        try:
            self.conn = psycopg2.connect(host=host, database=database, user=user, password=password)
            print(f"Connected to database {database} on {host}")
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except (Exception, psycopg2.DatabaseError) as e:
            print("Cannot connect to the database")
            raise e

    def execute(self, query, *args):
        try:
            self.cursor.execute(query, args)
            if query.strip().upper().startswith("SELECT"):
                result = self.cursor.fetchall()
                return [dict(row) for row in result]
            else:
                self.conn.commit()
                return None
        except (Exception, psycopg2.DatabaseError) as e:
            print(f"Error: {str(e)}\nIn query: {query}")
            raise e

    def get_custom_entity_types(self) -> List[Dict[str, Any]]:
        return self.execute("SELECT id, name, detection_type FROM custom_entity_types")

    def get_custom_patterns(self, entity_type_id: int) -> List[Pattern]:
        result = self.execute(
            "SELECT name, regex, score FROM custom_patterns WHERE entity_type_id = %s", entity_type_id
        )
        return [Pattern(name=r["name"], regex=r["regex"], score=r["score"]) for r in result]

    def get_custom_deny_list(self, entity_type_id: int) -> List[str]:
        result = self.execute("SELECT value FROM custom_deny_list WHERE entity_type_id = %s", entity_type_id)
        return [r["value"] for r in result]

    def get_custom_context_words(self, entity_type_id: int) -> List[str]:
        result = self.execute("SELECT word FROM custom_context_words WHERE entity_type_id = %s", entity_type_id)
        return [r["word"] for r in result]

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.execute(
            """SELECT r.id, r.codigo, r.description, cet.name as entity, r.level, r.confidence_level, 
            r.hits_lower, r.hits_upper, r.action 
            FROM rules r
            INNER JOIN custom_entity_types cet ON r.entity_id = cet.id
            WHERE r.status = true"""
        )

    def get_rules_network(self, origin_ip: str) -> List[Dict[str, Any]]:
        return self.execute(
            """SELECT r.id, r.codigo, cet.name as entity, r.confidence_level, r.hits_lower, r.hits_upper, r.action, r.level
            FROM rules r
            INNER JOIN custom_entity_types cet ON r.entity_id = cet.id
            INNER JOIN groups_rules gr ON gr.rule_id = r.id
            INNER JOIN networks n ON n.id = gr.network_id
            WHERE r.status = true AND %s <<= n.subnet::inet""",
            origin_ip,
        )

    def get_last_update_time(self) -> float:
        result = self.execute(
            """SELECT GREATEST(
                MAX(updated_at),
                MAX(created_at)
            ) as last_update
            FROM (
                SELECT updated_at, created_at FROM custom_entity_types
                UNION ALL
                SELECT updated_at, created_at FROM rules
            ) as updates"""
        )
        return result[0]["last_update"].timestamp() if result and result[0]["last_update"] else 0

    def save_history(self, history_entry):
        query = """
            INSERT INTO history (origin, destination, sensitive_data, results, level, action, text, text_redacted, file, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        metadata = history_entry.metadata or {}
        if history_entry.file_name:
            metadata["file_name"] = history_entry.file_name

        values = (
            history_entry.origin,
            history_entry.destination,
            history_entry.sensitive_data,
            json.dumps(history_entry.results),
            history_entry.level,
            history_entry.action,
            history_entry.text,
            history_entry.text_redacted,
            history_entry.file,
            json.dumps(metadata) if metadata else None,
        )
        self.execute(query, *values)

    def close(self):
        if self.conn is not None:
            self.conn.close()


class HistoryEntry:
    def __init__(
        self,
        origin,
        destination,
        sensitive_data,
        results,
        level,
        action,
        text,
        text_redacted,
        file,
        file_name=None,
        metadata=None,
    ):
        self.origin = origin
        self.destination = destination
        self.sensitive_data = sensitive_data
        self.results = results
        self.level = level
        self.action = action
        self.text = text
        self.text_redacted = text_redacted
        self.file = file
        self.file_name = file_name
        self.metadata = metadata or {}

    def insert(self, db: Database):
        db.save_history(self)
