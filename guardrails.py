from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

analyzer.registry.add_recognizer(PatternRecognizer(
    supported_entity="IN_MOBILE",
    patterns=[Pattern("in_mobile", r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b", 0.6)],
))
analyzer.registry.add_recognizer(PatternRecognizer(
    supported_entity="IN_PAN",
    patterns=[Pattern("in_pan", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.6)],
))
analyzer.registry.add_recognizer(PatternRecognizer(
    supported_entity="IN_AADHAAR",
    patterns=[Pattern("in_aadhaar", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.5)],
))

ENTITIES_TO_REDACT = [
    "PHONE_NUMBER", "CREDIT_CARD", "US_SSN",
    "IN_MOBILE", "IN_PAN", "IN_AADHAAR",
]


def redact(text):
    results = analyzer.analyze(text=text, language="en", entities=ENTITIES_TO_REDACT)
    if not results:
        return text, []
    cleaned = anonymizer.anonymize(text=text, analyzer_results=results)
    found = sorted({r.entity_type for r in results})
    return cleaned.text, found