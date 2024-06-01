import json

import psycopg2
import psycopg2.extras
from presidio_analyzer import Pattern


class Database:
    def __init__(self, host, database, user, password):
        try:
            self.conn = psycopg2.connect(host=host, database=database, user=user, password=password)
            print(f"Conectado a la base de datos {database} en {host}")
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except (Exception, psycopg2.DatabaseError) as e:
            self.close()
            print("No se puede conectar a la base de datos")

    def execute(self, query, *args):
        try:
            self.cursor.execute(query, args)
            # Check for results before fetching
            if query.strip().upper().startswith("SELECT"):
                # If the query is a SELECT statement
                result = self.cursor.fetchall()
                result = [dict(row) for row in result]
                return result
            else:
                # If the query is an INSERT, UPDATE, or DELETE statement
                self.conn.commit()
                return None
        except (Exception, psycopg2.DatabaseError) as e:
            self.close()
            print("Error: ", str(e), "\nEn query: ", query)

    def get_custom_entity_types(self):
        result = self.execute("SELECT id, name FROM custom_entity_types")
        return result

    def get_custom_patterns(self, entity_type_id):
        result = self.execute(
            "SELECT name, regex, score FROM custom_patterns WHERE entity_type_id = %s",
            (entity_type_id),
        )
        return result

    def get_custom_deny_list(self, entity_type_id):
        result = self.execute(
            "SELECT value FROM custom_deny_list WHERE entity_type_id = %s",
            (entity_type_id,),
        )
        return result

    def get_custom_context_words(self, entity_type_id):
        result = self.execute(
            "SELECT word FROM custom_context_words WHERE entity_type_id = %s",
            (entity_type_id,),
        )
        return result

    def get_default_entity_types(self):
        result = self.execute("SELECT name FROM default_entity_types")
        return result

    def get_rules(self):
        result = self.execute(
            """select r.id, r.codigo, r.description, cet.name as entity, r.level, r.confidence_level, r.hits_lower, r.hits_upper, r.action  from rules r
            inner join custom_entity_types cet on r.entity_id = cet.id
            where r.status = true"""
        )
        return result

    def get_rules_network(self, origin_ip: str):
        result = self.execute(
            """select r.id, r.codigo, cet.name as entity, r.confidence_level, r.hits_lower, r.hits_upper, r.action
            from rules r
            inner join custom_entity_types cet on r.entity_id = cet.id
            inner join groups_rules gr on gr.rule_id = r.id
            inner join networks n on n.id = gr.network_id
            where r.status = true and %s <<= n.subnet::inet""",
            (origin_ip),
        )
        return result

    def save_results_to_history(self, results):
        pass

    def close(self):
        self.conn.close()


class HistoryEntry:
    def __init__(
        self, origin, destination, sensitive_data, results, level, action, text, text_redacted, file, metadata=None
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
        self.metadata = metadata

    def insert(self, db: Database):
        query = """
            INSERT INTO history (origin, destination, sensitive_data, results, level, action, text, text_redacted, file, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            self.origin,
            self.destination,
            self.sensitive_data,
            json.dumps(self.results),
            self.level,
            self.action,
            self.text,
            self.text_redacted,
            self.file,
            json.dumps(self.metadata) if self.metadata else None,
        )
        db.execute(query, *values)
