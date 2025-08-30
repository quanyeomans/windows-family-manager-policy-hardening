Feature: System Security Assessment
  As an administrator
  I want to assess current system security state  
  So that I can make informed baseline establishment decisions

  Background:
    Given I have administrator privileges on a Windows system
    And the system assessment tools are available

  Scenario: First-time security assessment execution
    Given a Windows system with unknown security state
    When I run the system security assessment
    Then I should see current Essential 8 compliance score
    And I should see user account privilege analysis
    And I should see network configuration status  
    And I should receive clear remediation recommendations
    And the assessment should complete within 30 seconds

  Scenario: Assessment identifies critical security gaps
    Given a system with known security violations
    And there are unauthorized administrator accounts
    And there are registry modifications present
    When I run the system security assessment
    Then I should see critical findings highlighted in red
    And I should see specific remediation steps for each finding
    And I should see risk impact analysis
    And I should receive recommendation for complete baseline reset

  Scenario: Assessment on clean system
    Given a freshly installed Windows system
    And no previous family control modifications exist
    When I run the system security assessment  
    Then I should see Essential 8 compliance score above 80%
    And I should see recommendation for in-place policy deployment
    And I should see minimal security findings

  Scenario: Assessment generates structured output
    Given any Windows system state
    When I run the system security assessment
    Then I should receive output in valid JSON format
    And the output should contain assessment metadata
    And the output should contain security scorecard
    And the output should contain findings summary
    And the output should contain detailed findings list
    And the output should contain remediation approach recommendation