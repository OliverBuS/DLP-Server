import json
import pprint
import re
import threading
import time
from typing import Dict, Union

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from regex import R

from db import Database, HistoryEntry
from icapserver import AnalysisResult


class DLP:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.analyzer = self._initialize_analyzer()
        self.anonymizer = AnonymizerEngine()
        self.last_update_time = time.time()
        self.update_interval = 60  # Check for updates every 60 seconds
        self._start_update_thread()

    def _initialize_analyzer(self):
        analyzer = AnalyzerEngine(
            nlp_engine=NlpEngineProvider(conf_file="./languages-config.yml").create_engine(),
            supported_languages=["es"],
        )

        custom_entity_types = self.db.get_custom_entity_types()
        for entity_type in custom_entity_types:

            if entity_type["detection_type"] == "Native":
                continue

            entity_type_id = entity_type["id"]
            entity_type_name = entity_type["name"]

            patterns = self.db.get_custom_patterns(entity_type_id)
            deny_list = self.db.get_custom_deny_list(entity_type_id)
            context_words = self.db.get_custom_context_words(entity_type_id)

            recognizer = PatternRecognizer(
                supported_entity=entity_type_name,
                patterns=[p for p in patterns],
                deny_list=deny_list,
                context=context_words,
                supported_language="es",
            )

            analyzer.registry.add_recognizer(recognizer)

        return analyzer

    def _start_update_thread(self):
        def update_checker():
            while True:
                time.sleep(self.update_interval)
                if self._check_for_updates():
                    self.analyzer = self._initialize_analyzer()

        thread = threading.Thread(target=update_checker, daemon=True)
        thread.start()

    def _check_for_updates(self) -> bool:
        current_time = time.time()
        last_db_update = self.db.get_last_update_time()
        if last_db_update > self.last_update_time:
            self.last_update_time = current_time
            return True
        return False

    def analyze_network(
        self,
        text: str,
        origin_ip: str = "127.0.0.1",
        destination_ip: str = "127.0.0.1",
        file_name: str = None,
        metadata: str = None,
    ) -> AnalysisResult:
        rules = self.db.get_rules_network(origin_ip)
        entities = [rule["entity"] for rule in rules]

        def clear_text(text: str) -> str:
            text = re.sub(r"\s+", " ", text)
            return text.strip()

        text_cleared = clear_text(text)

        results = self.analyzer.analyze(text=text_cleared, language="es", entities=entities)

        rules_matched = []
        entity_dict = {}
        action = Action.NOTHING
        level = Level.NOTHING

        for result in results:
            pprint.pprint(
                f"Type: {result.entity_type}, Value: {text_cleared[result.start : result.end]}, Confidence: {result.score:.2f}"
            )

        for rule in rules:
            result_matched = []
            for result in results:
                if rule["entity"] == result.entity_type and rule["confidence_level"] <= result.score:
                    data = text_cleared[result.start : result.end]
                    result_matched.append({**result.to_dict(), "data": data})
                    action = Action.priority(rule["action"], action)
                    level = Level.priority(rule["level"], level)

            if len(result_matched) >= rule["hits_lower"] and len(result_matched) <= rule["hits_upper"]:
                for result in result_matched:
                    if rule["action"] == Action.REDACT:
                        entity_dict[result["data"]] = result["entity_type"]
                rules_matched.append({"matches": result_matched, "rule": rule})

        redacted_text = self.anonymize(text=text, results=entity_dict)

        is_file = bool(file_name)
        metadata_dict = json.loads(metadata) if metadata else {}
        if file_name:
            metadata_dict["file_name"] = file_name

        if action == Action.NOTHING or level == Level.NOTHING:
            return AnalysisResult({}, False, "No rules matched")

        history = HistoryEntry(
            origin=origin_ip,
            destination=destination_ip,
            sensitive_data=str(entity_dict),
            results=rules_matched,
            level=level,
            action=action,
            text=text,
            text_redacted=redacted_text,
            file=is_file,
            metadata=metadata_dict,
        )

        try:
            history.insert(db=self.db)
        except Exception as e:
            print(f"No se ha podido insertar el historial: {e}")

        return AnalysisResult(entity_dict, action == Action.BLOCK, "Content blocked due to policy violation")

    def anonymize(self, text: str, results: Union[list, Dict[str, str]]) -> str:
        if isinstance(results, dict):
            for word, redaction in results.items():
                text = text.replace(word, redaction)
            return text

        return self.anonymizer.anonymize(text=text, analyzer_results=results).text


class AnalysisResult:
    def __init__(self, censor_dict: Dict[str, str], block: bool, block_message: str):
        self.censor_dict = censor_dict
        self.block = block
        self.block_message = block_message


class Action:
    NOTHING = "Nothing"
    BLOCK = "Block"
    REDACT = "Redact"
    ALERT = "Alert"

    @staticmethod
    def priority(action1, action2):
        actions = [action1, action2]
        priority = ["Block", "Redact", "Alert", "Nothing"]
        return next((action for action in priority if action in actions), "Nothing")


class Level:
    NOTHING = "Nothing"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

    @staticmethod
    def priority(level1, level2):
        levels = [level1, level2]
        priority = ["High", "Medium", "Low", "Nothing"]
        return next((level for level in priority if level in levels), "Nothing")
