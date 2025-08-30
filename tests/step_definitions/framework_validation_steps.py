# Step Definitions for Framework Validation
import pytest
import json
from pytest_bdd import given, when, then, scenarios
from jsonschema import validate, ValidationError

# Load all scenarios from the feature file
scenarios('../features/framework_validation/basic_testing.feature')

@pytest.fixture
def validation_context():
    """Context for framework validation tests."""
    return {
        'framework_ready': False,
        'test_executed': False,
        'result': None,
        'test_data': None,
        'validation_result': None
    }

# Basic BDD scenario execution
@given('the testing framework is set up')
def framework_is_set_up(validation_context):
    """Verify the testing framework is ready."""
    validation_context['framework_ready'] = True

@when('I run a simple test scenario')
def run_simple_test_scenario(validation_context):
    """Execute a simple test scenario."""
    if validation_context['framework_ready']:
        validation_context['test_executed'] = True
        validation_context['result'] = "success"

@then('the test should execute successfully')
def verify_test_execution(validation_context):
    """Verify the test executed successfully."""
    assert validation_context['test_executed'], "Test should have executed"
    assert validation_context['result'] == "success", "Test should have succeeded"

@then('I should see the expected result')
def verify_expected_result(validation_context):
    """Verify we got the expected result."""
    assert validation_context['result'] is not None, "Should have a result"

# JSON validation scenario
@given('I have test data in JSON format')
def setup_test_json_data(validation_context):
    """Set up test JSON data."""
    validation_context['test_data'] = {
        "valid": {
            "name": "test",
            "version": "1.0",
            "data": {"key": "value"}
        },
        "invalid": {
            "name": "test"
            # Missing required fields
        }
    }

@when('I validate the JSON against a schema')
def validate_json_against_schema(validation_context):
    """Validate JSON data against a schema."""
    schema = {
        "type": "object",
        "required": ["name", "version", "data"],
        "properties": {
            "name": {"type": "string"},
            "version": {"type": "string"},
            "data": {"type": "object"}
        }
    }
    
    results = {}
    
    # Test valid data
    try:
        validate(validation_context['test_data']['valid'], schema)
        results['valid'] = True
    except ValidationError:
        results['valid'] = False
    
    # Test invalid data
    try:
        validate(validation_context['test_data']['invalid'], schema)
        results['invalid'] = True
    except ValidationError:
        results['invalid'] = False
    
    validation_context['validation_result'] = results

@then('the validation should succeed for valid data')
def verify_valid_data_passes(validation_context):
    """Verify valid data passes validation."""
    assert validation_context['validation_result']['valid'], "Valid data should pass validation"

@then('the validation should fail for invalid data')
def verify_invalid_data_fails(validation_context):
    """Verify invalid data fails validation."""
    assert not validation_context['validation_result']['invalid'], "Invalid data should fail validation"