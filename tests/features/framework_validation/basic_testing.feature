Feature: Testing Framework Validation
  As a developer
  I want to validate that the testing framework works correctly
  So that I can develop reliable BDD tests

  Scenario: Basic BDD scenario execution
    Given the testing framework is set up
    When I run a simple test scenario
    Then the test should execute successfully
    And I should see the expected result

  Scenario: JSON validation works correctly
    Given I have test data in JSON format
    When I validate the JSON against a schema
    Then the validation should succeed for valid data
    And the validation should fail for invalid data