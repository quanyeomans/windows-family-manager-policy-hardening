# Testing Framework Documentation

## Overview
This directory contains the comprehensive testing framework for the Family Device Control System, implementing BDD (Behavior-Driven Development), integration testing, and contract testing patterns.

## Directory Structure

```
tests/
├── features/                    # BDD feature files (Gherkin)
│   ├── admin_interface/         # Admin interface user scenarios
│   ├── system_assessment/       # System assessment workflows
│   ├── policy_deployment/       # Policy deployment scenarios
│   ├── microsoft_integration/   # Microsoft Family Safety integration
│   └── framework_validation/    # Framework testing scenarios
├── step_definitions/            # BDD step implementations (Python)
├── contracts/                   # Contract tests (interface agreements)
├── integration/                 # Integration tests (multi-component)
├── ui/                         # Streamlit interface tests
├── unit/                       # Unit tests (individual components)
├── support/                    # Test utilities and fixtures
├── conftest.py                 # pytest configuration and fixtures
├── requirements-test.txt       # Testing dependencies
└── README.md                   # This file
```

## Test Categories and Markers

### Core Test Types
- **`@pytest.mark.unit`**: Individual component tests (50% target)
- **`@pytest.mark.contract`**: Component interface agreement tests (15% target)
- **`@pytest.mark.integration`**: Multi-component interaction tests (25% target)
- **`@pytest.mark.bdd`**: User experience scenario tests (10% target)

### Quality Enforcement
- **`@pytest.mark.critical`**: Tests that must never fail
- **`@pytest.mark.golden_path`**: Most common success scenarios
- **`@pytest.mark.regression`**: Tests preventing specific bugs from recurring

### Performance Categories
- **`@pytest.mark.fast`**: Tests under 1 second (unit + contract)
- **`@pytest.mark.medium`**: Tests 1-30 seconds (integration)
- **`@pytest.mark.slow`**: Tests over 30 seconds (bdd + complex integration)

### Environment Categories
- **`@pytest.mark.windows_only`**: Tests requiring Windows environment
- **`@pytest.mark.admin_required`**: Tests requiring administrator privileges
- **`@pytest.mark.network_required`**: Tests requiring network connectivity

## Running Tests

### Quick Development Testing
```bash
# Fast feedback during development
pytest -m "unit and not slow" -v

# Unit tests only
pytest -m unit -v

# BDD scenarios only
pytest -m bdd -v

# Contract tests (critical quality gate)
pytest -m contract --maxfail=1 -v
```

### Quality Gate Testing
```bash
# Pre-commit safety gate
pytest -m "contract or critical" --maxfail=1

# Integration testing
pytest -m integration --integration -v

# Full test suite
pytest -v
```

### Coverage Testing
```bash
# Run with coverage
pytest --cov=src --cov-report=html --cov-fail-under=90
```

## BDD (Behavior-Driven Development)

### Feature Files
Feature files are written in Gherkin syntax and describe user behaviors:

```gherkin
Feature: System Security Assessment
  As an administrator
  I want to assess current system security state
  So that I can make informed baseline establishment decisions

  Scenario: First-time security assessment execution
    Given a Windows system with unknown security state
    When I run the system security assessment
    Then I should see current Essential 8 compliance score
    And I should see user account privilege analysis
```

### Step Definitions
Step definitions implement the Gherkin steps in Python:

```python
@given('a Windows system with unknown security state')
def setup_unknown_security_state(assessment_context):
    assessment_context['system_state'] = 'unknown'

@when('I run the system security assessment')
def run_security_assessment(assessment_context, powershell_executor):
    result = powershell_executor.run_script('assess_system.ps1')
    assessment_context['result'] = result
```

## Contract Testing

Contract tests validate component interface agreements:

```python
@pytest.mark.contract
def test_assessment_output_format_contract(self):
    """CONTRACT: Assessment must provide consistent JSON output format."""
    data = run_assessment()
    
    required_fields = ['assessment_metadata', 'security_scorecard', 'findings_summary']
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"
```

## Integration Testing

Integration tests validate multi-component workflows:

```python
@pytest.mark.integration
def test_powershell_python_integration(self):
    """Test PowerShell backend integrates with Python frontend."""
    executor = PowerShellExecutor()
    result = executor.run_assessment()
    assert result.success
    assert 'essential8_compliance' in result.data
```

## Test Fixtures

### Available Fixtures
- **`project_root`**: Project root directory path
- **`src_directory`**: Source code directory path
- **`powershell_executor`**: PowerShell script execution utility
- **`temp_directory`**: Temporary directory for test isolation
- **`mock_system_state`**: Mock system state for testing
- **`assessment_result_schema`**: JSON schema for assessment validation

### PowerShell Integration
The `powershell_executor` fixture provides seamless PowerShell integration:

```python
def test_powershell_script_execution(powershell_executor):
    result = powershell_executor.run_script_json('test_script.ps1')
    assert result['status'] == 'success'
```

## Framework Status

### ✅ Day 1 Complete - BDD Framework Setup
- [x] Testing dependencies installed and configured
- [x] Project directory structure established
- [x] pytest configuration with custom markers
- [x] Global fixtures and utilities created
- [x] BDD framework operational with pytest-bdd
- [x] Framework validation tests passing
- [x] JSON validation and schema checking working
- [x] PowerShell integration fixtures available

### 🚀 Next Steps - Week 1 Continuation
- [ ] Core BDD scenarios for system assessment (Day 2-3)
- [ ] PowerShell script integration testing (Day 4)
- [ ] Pre-commit integration and validation (Day 5)

## Development Guidelines

### Writing BDD Scenarios
1. **Focus on user behavior**, not implementation details
2. **Use Given-When-Then structure** consistently
3. **Make scenarios readable** by non-technical stakeholders
4. **Keep scenarios focused** on one specific behavior

### Contract Testing Best Practices
1. **Test real component interfaces**, not mocks
2. **Focus on interface agreements**, not implementation
3. **Keep contracts simple** with single assertions
4. **Run contracts first** in CI/CD pipeline

### Integration Testing Guidelines
1. **Use real components** wherever possible
2. **Mock only external systems** (APIs, networks)
3. **Test complete user workflows** end-to-end
4. **Include error conditions** and recovery paths

## Quality Assurance

### Quality Gates (MANDATORY)
- **Contract Tests**: Must pass 100% - zero tolerance
- **Critical Tests**: Must pass 100% - zero tolerance
- **BDD Tests**: Must pass for user-facing features
- **Integration Tests**: 90% pass rate minimum

### Performance Targets
- **Contract Test Suite**: <30 seconds total execution
- **Unit Test Suite**: <1 minute total execution
- **Integration Test Suite**: <5 minutes total execution
- **Full Test Suite**: <10 minutes total execution

---

*This testing framework is designed to ensure quality development of the Family Device Control System admin interface and system assessment tools. All feature development must follow this testing-first approach.*