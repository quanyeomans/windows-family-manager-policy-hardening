Feature: Guided System Setup Wizard
  As an administrator
  I want to be guided through system baseline establishment
  So that I can deploy security policies correctly without making mistakes

  Background:
    Given I have administrator privileges on the system
    And the admin interface is accessible via web browser
    And the system assessment has been completed

  Scenario: Successful complete system baseline establishment
    Given the system assessment recommends complete baseline reset
    And I have selected "Complete Baseline Reset" as remediation approach
    And I have backed up essential user data
    When I execute the guided setup wizard
    Then I should see step-by-step progress indicators
    And I should see "Essential 8 Security Controls" deployment progress
    And I should see "User Account Structure" creation progress
    And I should see "Network Security Policies" deployment progress
    And I should see "Application Control Policies" deployment progress
    And I should receive confirmation of successful deployment
    And I should see post-deployment validation results
    And all security policy validation tests should pass

  Scenario: Deployment failure with automatic rollback
    Given the system setup encounters a PowerShell execution error
    When the policy deployment fails during "Network Security Policies" step
    Then I should see clear error information explaining the failure
    And the system should automatically initiate rollback procedures
    And I should see rollback progress indicators
    And I should receive confirmation that rollback completed successfully
    And I should see guidance for manual resolution of the underlying issue
    And the system should be restored to pre-deployment state

  Scenario: Deployment progress tracking with real-time updates
    Given I am executing a baseline deployment
    When the deployment is in progress
    Then I should see real-time progress updates every 5 seconds
    And I should see current step name and progress percentage
    And I should see estimated time remaining
    And I should see detailed log output in a scrollable window
    And I should be able to cancel deployment if needed
    And if I cancel, the system should ask for confirmation before rolling back

  Scenario: Post-deployment validation and verification
    Given the baseline deployment has completed successfully
    When I review the post-deployment validation
    Then I should see Essential 8 Level 1 compliance score above 85%
    And I should see all critical security findings resolved
    And I should see confirmation that all user accounts are properly configured
    And I should see network security policies are active and enforced
    And I should see application control policies are operational
    And I should receive a deployment summary report
    And I should have option to download detailed deployment logs