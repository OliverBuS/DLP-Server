import psycopg2
import psycopg2.extras
from presidio_analyzer import Pattern


class Database:
    def __init__(self, host, database, user, password):
        try:
            self.conn = psycopg2.connect(
                host=host, database=database, user=user, password=password
            )
            print(f"Conectado a la base de datos {database} en {host}")
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except (Exception, psycopg2.DatabaseError) as e:
            self.close()
            print("No se puede conectar a la base de datos")

    def execute(self, query, *args):
        try:
            self.cursor.execute(query, args)
            result = self.cursor.fetchall()
            result = [dict(row) for row in result]
            return result
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

    def get_rules_network(self):
        result = self.execute(
            """select r.id, r.codigo, r.description, cet.name as entity, r.level, r.confidence_level, r.hits_lower, r.hits_upper, r.action  from rules r
            inner join custom_entity_types cet on r.entity_id = cet.id
            where r.status = true"""
        )
        return result

    def close(self):
        self.conn.close()
