# Claude Code Mission Control
*Lightweight AI development orchestration for Windows Family Manager Policy Hardening*

## Current Session 
**Active Work:** [Update each session]  
**Current Phase:** Phase 0 COMPLETE - All custom Windows security policy scripts implemented, tested, and validated  
**Key Files:** src/integrations/policy-management/*, tests/policy-deployment/*, guardrails/product/PHASE1_DEVELOPMENT_PLAN.md  
**Next Steps:** Begin Phase 1 Iteration 1 (Basic Time Awareness) following E2E thin slice methodology

## Quick Decision Tree (Pick ONE)
```
🚨 URGENT BUG     → guardrails/practices/DEBUGGING_IMPLEMENTATION_GUIDE.md
🔒 SECURITY ISSUE → guardrails/practices/SECURITY_IMPLEMENTATION_GUIDE.md  
✨ NEW FEATURE    → guardrails/practices/DEVELOPMENT_IMPLEMENTATION_GUIDE.md
🧹 REFACTORING    → guardrails/practices/DEVELOPMENT_IMPLEMENTATION_GUIDE.md
📊 ANALYSIS       → guardrails/frameworks/DEVELOPMENT_WORKFLOW.md
```

## Critical Rules (Always Apply)
- **Structure First:** Use existing folders before creating new ones - explore guardrails/ completely
- **Evidence Before Claims:** NEVER claim success without test execution results
- **Test First:** Write failing test before implementation
- **File Discipline:** tests/ for testing, src/ for code, guardrails/ for all documentation
- **No Proactive Docs:** Never create .md files unless user explicitly requests

## Application Type Context
**Type:** Hybrid Family Control System (Microsoft Family Safety + Windows Hardening)
**Stack:** PowerShell 7 + Windows Group Policy + Microsoft Cloud Services
**Security Model:** Two-tier (Hard boundaries + Monitored activities)

## Quality Gates (MUST PASS)
```bash
# Run before any commit
powershell -File ./scripts/compliance-check.ps1
# OR manually:
powershell -Command "Invoke-Pester tests/security/ && Test-PolicyCompliance && Invoke-ScriptAnalyzer src/"
```

## Quick Commands
```bash
# Development cycle
powershell -Command "Invoke-Pester tests/ -Tag Contract,Unit"

# Pre-commit safety
powershell -Command "Invoke-Pester tests/ -Tag Contract,Critical"

# Full validation
powershell -File ./scripts/test-all.ps1

# Security audit
powershell -File ./scripts/security-audit.ps1
```

## Recent Lessons (Last 3 Sessions)
1. **VIOLATION CORRECTED:** Claimed implementation success before testing - now requires evidence before status updates
2. **VIOLATION CORRECTED:** Created parallel docs/ structure - moved all content to proper guardrails/ subdirectories
3. **COMPLETED:** Custom Windows policy scripts (S001-S022) implemented with family parameterization and external config

## Reference System
- **Design Principles:** `guardrails/DESIGN_PRINCIPLES.md`
- **Development Practices:** `guardrails/practices/`
- **Frameworks:** `guardrails/frameworks/`
- **Product Spec:** `guardrails/product/cleaned_requirements_spec.md`
- **Solution Architecture:** `guardrails/product/solution_architecture_design.md`
- **Project Setup:** `guardrails/PROJECT_SETUP.md`

## Implementation Status (Phase 0 Complete)

**✅ Custom Windows Security Policies:**
- User Account Security (S001-S007): src/integrations/policy-management/user-account-security/
- Network Security (S008-S014): src/integrations/policy-management/network-security/  
- Application Control (S015-S022): src/integrations/policy-management/application-control/
- All tested with dry-run mode, family parameterization working

**✅ Architecture Complete:**
- External family configuration (keeps sensitive data out of repo)
- Reversible policy deployment (-Reverse flag)
- Comprehensive logging and error handling
- PowerShell compatibility (5.0+) verified

**✅ Testing Framework:**
- Test configuration: tests/policy-deployment/test-config.json
- Test runner: tests/policy-deployment/Test-PolicyScripts.ps1
- All 3 policy scripts validated (41 total policies tested)

**✅ Project Structure Compliance:**
- All documentation moved to guardrails/ subdirectories
- .gitignore updated for family privacy protection
- No parallel organizational systems

**🚀 Ready for Phase 1:**
- Iteration 1: Basic Time Awareness (guardrails/product/iterations/)
- E2E thin slice methodology established
- Daily security contract testing framework ready

---
*Update session context each time. Keep this file under 2KB.*