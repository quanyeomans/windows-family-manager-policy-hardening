# Security Policy

## Framework Security

This repository contains development methodology frameworks and does not include executable code that runs in production environments. However, security considerations apply to:

- Template generation scripts
- Framework recommendations for secure development practices
- References to security tools and validation procedures

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x.x   | ✅ Yes    |
| < 1.0   | ❌ No     |

## Reporting Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report security concerns through internal channels:

- **Internal Security Team**: [security@danmcmahon.com.au]
- **Framework Maintainers**: [framework-team@danmcmahon.com.au]
- **Direct Contact**: [dan@danmcmahon.com.au]

Include the following information:
- Description of the potential vulnerability
- Steps to reproduce the issue
- Affected versions or components
- Assessment of potential impact

## Security Considerations for Framework Usage

### Template Security
- **Script Execution**: PROJECT_SETUP.py generates files but does not execute arbitrary code
- **File Paths**: Template system validates file paths to prevent directory traversal
- **Content Sanitization**: Generated content does not include user-provided code execution

### Framework Recommendations
The frameworks include security guidance for:
- **API Key Management**: Never logging or exposing API keys
- **Input Validation**: Sanitizing all user inputs before processing
- **Path Security**: Protecting against directory traversal attacks
- **Error Handling**: Preventing sensitive information leakage through error messages

### Tool Integration Security
Recommended tools include security scanning:
- **bandit**: Static analysis security testing for Python
- **safety**: Dependency vulnerability scanning
- **pylint**: Code quality with security rule enforcement

## Framework Security Updates

Security improvements to the framework methodology will be:
- Documented in CHANGELOG.md with security impact assessment
- Communicated through internal channels for immediate adoption
- Versioned according to impact severity

### Security-Related Changes
- **Critical**: Immediate framework updates, version bump
- **Important**: Next scheduled release with clear migration guidance  
- **Moderate**: Regular update cycle with documentation updates

## Responsible Disclosure

We appreciate security researchers who:
- Report issues through proper internal channels
- Allow reasonable time for investigation and resolution
- Avoid public disclosure until issues are resolved
- Provide clear, actionable information about vulnerabilities

## Security Contact Information

- **Primary Contact**: [security@danmcmahon.com.au]
- **Escalation Contact**: [dan@danmcmahon.com.au]
- **Framework Team**: [framework-maintainers@danmcmahon.com.au]

---

**Response Time Expectations:**
- Initial acknowledgment: 24 hours
- Initial assessment: 72 hours  
- Resolution timeline: Based on severity assessment