import pytest
from sentinel_core.modules.test_executor.response_validator import ResponseValidator

def test_status_code_validation_pass():
    validator = ResponseValidator()
    response = {"status_code": 200, "body": '{"data": "secret"}'}
    rules = {"response_code": {"eq": 200}}
    # In our implementation, validate returns True if rules match (i.e. vuln found)
    assert validator.validate(response, rules) is True

def test_body_contains_check():
    validator = ResponseValidator()
    response = {"body": "root:x:0:0"}
    rules = {"response_payload": {"contains": ["root:"]}}
    assert validator.validate(response, rules) is True

def test_status_code_mismatch():
    validator = ResponseValidator()
    response = {"status_code": 404}
    rules = {"response_code": {"eq": 200}}
    assert validator.validate(response, rules) is False


# Templates write the rule as ``response_headers`` (plural); it used to be ignored, so a template
# meant to flag a MISSING header flagged every 2xx response.
_MISSING_CONTENT_TYPE = {
    "response_code": {"gte": 200, "lt": 300},
    "response_headers": {"for_all": {"key": {"neq": "Content-Type"}}},
}


def test_missing_header_template_flags_a_response_without_the_header():
    assert ResponseValidator().validate({"status_code": 200, "headers": {"Server": "x"}}, _MISSING_CONTENT_TYPE)


def test_missing_header_template_does_not_flag_a_response_that_has_the_header():
    response = {"status_code": 200, "headers": {"Server": "x", "Content-Type": "application/json"}}
    assert not ResponseValidator().validate(response, _MISSING_CONTENT_TYPE)


def test_for_one_header_rule_in_the_plural_form_is_enforced():
    rules = {"response_headers": {"for_one": {"key": {"eq": "content-type"}, "value": {"contains": "json"}}}}
    assert ResponseValidator().validate({"status_code": 200, "headers": {"Content-Type": "application/json"}}, rules)
    assert not ResponseValidator().validate({"status_code": 200, "headers": {"Content-Type": "text/html"}}, rules)
