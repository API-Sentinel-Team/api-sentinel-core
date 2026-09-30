"""Every rule a bundled template uses must be understood by the validator.

An unknown key is silently ignored, which turns a specific check into "any 2xx", i.e. false
positives. This test fails when a template starts using a rule the engine does not implement.
"""
import glob
import os

import yaml

from sentinel_core.modules.test_executor.response_validator import ResponseValidator

LIB = os.path.join(os.path.dirname(__file__), "..", "..", "sentinel_core", "tests_library")
SUPPORTED = {
    "response_code", "response_payload", "response_header", "response_headers", "and", "or",
    *ResponseValidator.UNVERIFIABLE_RULES, *ResponseValidator.NON_RESPONSE_RULES,
}


def test_templates_only_use_validate_rules_the_engine_implements():
    unknown = {}
    for path in glob.glob(os.path.join(LIB, "**", "*.y*ml"), recursive=True):
        doc = yaml.safe_load(open(path, encoding="utf-8"))
        validate = doc.get("validate") if isinstance(doc, dict) else None
        if isinstance(validate, dict):
            for key in validate:
                if key not in SUPPORTED:
                    unknown.setdefault(key, []).append(os.path.basename(path))
    assert not unknown, f"validate rules with no implementation (silently ignored): {unknown}"
