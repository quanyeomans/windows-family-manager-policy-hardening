Feature: System Assessment Dashboard
  As an administrator
  I want to view current system security status in an intuitive dashboard
  So that I can quickly understand security risks and required actions

  Background:
    Given I have administrator privileges on the system
    And the admin interface is accessible at localhost:8501
    And the system assessment tools are available

  Scenario: Dashboard loads with system security overview
    Given I navigate to the system assessment dashboard
    When the dashboard loads
    Then I should see an overall security score prominently displayed
    And I should see Essential 8 compliance status with color-coded indicators
    And I should see a summary of security findings by severity (Critical, High, Medium, Low)
    And I should see user account analysis with privilege breakdown
    And I should see network configuration status
    And I should see recent activity timeline
    And the dashboard should load within 5 seconds

  Scenario: Security score visualization and drill-down
    Given the system assessment shows a security score of 43.8/100
    When I view the security scorecard
    Then I should see the score displayed with red/yellow/green color coding
    And I should see "NEEDS ATTENTION" status for scores below 70
    And I should see individual Essential 8 control scores
    And I should be able to click on each control for detailed findings
    And I should see specific recommendations for improving each score
    And I should see impact assessment of each security gap

  Scenario: Critical findings prioritization and action guidance
    Given the system assessment identifies 8 critical security findings
    When I review the critical findings section
    Then I should see critical findings highlighted in red with warning icons
    And I should see specific finding descriptions with technical details
    And I should see recommended actions for each critical finding
    And I should see estimated remediation time for each finding
    And I should see risk impact if findings are not addressed
    And I should have one-click access to remediation workflows

  Scenario: Real-time system assessment execution
    Given I want to refresh the system security assessment
    When I click "Run New Assessment"
    Then I should see a progress indicator showing assessment steps
    And I should see "Analyzing user accounts..." progress message
    And I should see "Checking registry modifications..." progress message
    And I should see "Scanning for bypass tools..." progress message
    And I should see "Validating network configuration..." progress message
    And the assessment should complete within 30 seconds
    And the dashboard should automatically update with new results

  Scenario: Export assessment report functionality
    Given the system assessment is complete
    When I click "Export Assessment Report"
    Then I should be presented with export format options (PDF, JSON, Excel)
    And I should be able to select specific sections to include
    And I should be able to add custom notes to the report
    And when I click "Generate Report", a file should download within 10 seconds
    And the report should contain all selected assessment data
    And the report should be properly formatted and readable