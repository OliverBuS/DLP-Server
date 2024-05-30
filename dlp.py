from pprint import pprint
from typing import Literal, Union

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, EngineResult

from db import Database

LANGUAGES_CONFIG_FILE = "./languages-config.yml"
provider = NlpEngineProvider(conf_file=LANGUAGES_CONFIG_FILE)
nlp_engine_english_with_spanish = provider.create_engine()


class Action:
    NOTHING = "Nothing"
    BLOCK = "Block"
    REDACT = "Redact"
    ALERT = "Alert"

    def priority(action1, action2) -> Literal["Nothing", "Block", "Redact", "Alert"]:
        actions = [action1, action2]
        priority = ["Block", "Redact", "Alert", "Nothing"]
        for priority_action in priority:
            if priority_action in actions:
                return priority_action

        return "Nothing"


class DLP:
    def __init__(self, db: Database) -> None:
        self.db = db

        custom_entity_types = db.get_custom_entity_types()
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine_english_with_spanish,
            supported_languages=["en", "es"],
        )

        for entity_type in custom_entity_types:
            entity_type_id = entity_type["id"]
            entity_type_name = entity_type["name"]

            patterns_db_result = db.get_custom_patterns(entity_type_id)
            patterns = [
                Pattern(
                    name=pattern["name"],
                    regex=pattern["regex"],
                    score=pattern["score"],
                )
                for pattern in patterns_db_result
            ]
            deny_list = db.get_custom_deny_list(entity_type_id)
            context_words = db.get_custom_context_words(entity_type_id)

            recognizer = PatternRecognizer(
                supported_entity=entity_type_name,
                patterns=patterns,
                deny_list=deny_list,
                context=context_words,
                supported_language="es",
            )
            print("-" * 50)
            print("Recognizer:", recognizer.supported_entities)
            pprint(recognizer.patterns)

            analyzer.registry.add_recognizer(recognizer)

        self.anonymizer = AnonymizerEngine()
        self.analyzer = analyzer

    def analyze(self, text: str, redact_dict=False) -> list[RecognizerResult]:
        if not self.analyzer:
            return "error, presidio no ha sido inicializado"

        results = self.analyzer.analyze(text=text, language="es")
        print("-" * 25 + " Presidio RESULTS " + "-" * 25)
        pprint(results)

        # If not adaptation for redaction in dict, return results
        if not redact_dict:
            return results

        # Rules check
        rules = self.db.get_rules()
        rules_matched = []

        # Create a dictionary to save values needed for redaction
        entity_dict = {}
        # Create a variable to indicate the action to be taken
        action = Literal["Block", "Redact", "Alert", "Nothing"]
        # For each rule recollect all the results that match the rule
        # For this the result must have a high enough confidence level
        for rule in rules:
            result_matched = []
            for result in results:
                if rule["entity"] == result.entity_type and rule["confidence_level"] <= result.score:
                    data = text[result.start : result.end]
                    result_matched.append({**result.to_dict(), "data": data})
                    action = Action.priority(rule["action"], action)

            if len(result_matched) >= rule["hits_lower"] and len(result_matched) <= rule["hits_upper"]:
                for result in result_matched:
                    if rule["action"] == Action.REDACT:
                        entity_dict[result["data"]] = result["entity_type"]
                rules_matched.append({"matches": result_matched, "rule": rule})

        print("-" * 25 + " HISTORY RESULTS " + "-" * 25)
        redacted_text = self.anonymize(text=text, results=entity_dict)
        history_results = {
            "results": rules_matched,
            "original_text": text,
            "redacted_text": redacted_text,
        }
        pprint(history_results)
        print("-" * 25 + " Action" + "-" * 25)
        print(action)

        return entity_dict

    def analyze_network(
        self,
        text: str,
        origin_ip: str = "127.0.0.1",
        destination_ip: str = "127.0.0.1",
        file_name: str = "Text",
        file_metadata: str = "",
    ) -> list[RecognizerResult]:
        if not self.analyzer:
            return "error, presidio no ha sido inicializado"

        rules = self.db.get_rules_network(origin_ip)
        entities = [rule["entity"] for rule in rules]

        results = self.analyzer.analyze(text=text, language="es", entities=entities)
        print("-" * 25 + " Presidio RESULTS " + "-" * 25)
        pprint(results)

        # Rules check
        rules_matched = []

        # Create a dictionary to save values needed for redaction
        entity_dict = {}
        # Create a variable to indicate the action to be taken
        action = Literal["Block", "Redact", "Alert", "Nothing"]
        # For each rule recollect all the results that match the rule
        # For this the result must have a high enough confidence level
        for rule in rules:
            result_matched = []
            for result in results:
                if rule["entity"] == result.entity_type and rule["confidence_level"] <= result.score:
                    data = text[result.start : result.end]
                    result_matched.append({**result.to_dict(), "data": data})
                    action = Action.priority(rule["action"], action)

            if len(result_matched) >= rule["hits_lower"] and len(result_matched) <= rule["hits_upper"]:
                for result in result_matched:
                    if rule["action"] == Action.REDACT:
                        entity_dict[result["data"]] = result["entity_type"]
                rules_matched.append({"matches": result_matched, "rule": rule})

        print("-" * 25 + " HISTORY RESULTS " + "-" * 25)
        redacted_text = self.anonymize(text=text, results=entity_dict)
        history_results = {
            "results": rules_matched,
            "original_text": text,
            "redacted_text": redacted_text,
        }
        pprint(history_results)
        print("-" * 25 + " Action" + "-" * 25)
        print(action)

        return entity_dict

    def anonymize(self, text: str, results: Union[list[RecognizerResult], dict[str, str]]) -> EngineResult:
        redacted_text = text
        if isinstance(results, dict):
            for word, redaction in results.items():
                redacted_text = redacted_text.replace(word, redaction)
            return redacted_text

        return self.anonymizer.anonymize(text=text, analyzer_results=results)


db = Database("127.0.0.1", "dlp", "oliver", "oliver")
dlp = DLP(db=db)


def test(
    text,
):
    results = dlp.analyze(text=text, redact_dict=True)
    print("-" * 25 + " RESULTS " + "-" * 25)
    pprint(results)
    anonymazed_results = dlp.anonymize(text=text, results=results)
    print("-" * 25 + " ANONYMIZED RESULTS " + "-" * 25)
    print(anonymazed_results)


def main():
    with open("testFile.txt", "r") as f:
        text = f.read()
    test(text=text)


if __name__ == "__main__":
    main()
