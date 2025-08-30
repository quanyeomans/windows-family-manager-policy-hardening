# Claude Code Mission Control
*Lightweight AI development orchestration for Windows Family Manager Policy Hardening*

## Current Session 
**Active Work:** Testing Foundation Complete - Ready for Phase 1 Development  
**Current Phase:** Testing Foundation COMPLETE - Professional-grade testing infrastructure established  
**Key Files:** tests/contracts/*, scripts/validate-contracts.ps1, .pre-commit-config.yaml, .github/workflows/*  
**Next Steps:** Begin Phase 1 development with confidence in testing foundation

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
# Contract validation (CRITICAL before any development)
powershell -File ./scripts/validate-contracts.ps1

# Pre-commit validation
powershell -Command "Invoke-Pester tests/contracts/ -Tag Contract"

# Integration testing
pytest tests/integration/ --integration

# BDD scenario validation  
pytest tests/features/ --bdd

# Full test suite
pytest tests/ && powershell -Command "Invoke-Pester tests/security-contracts/"
```

## Recent Lessons (Last 3 Sessions)
1. **TESTING FOUNDATION SUCCESS:** Week 1 established professional-grade testing infrastructure with 17/17 tests passing
2. **CONTRACT TESTING ESSENTIAL:** PowerShell-Python interface contracts prevent breaking changes across language boundaries  
3. **QUALITY AUTOMATION PAYS:** Pre-commit hooks and CI/CD pipeline eliminate manual quality overhead (4.34s validation time)

## Reference System
- **Design Principles:** `guardrails/DESIGN_PRINCIPLES.md`
- **Development Practices:** `guardrails/practices/`
- **Frameworks:** `guardrails/frameworks/`
- **Product Spec:** `guardrails/product/cleaned_requirements_spec.md`
- **Solution Architecture:** `guardrails/product/solution_architecture_design.md`
- **Project Setup:** `guardrails/PROJECT_SETUP.md`

## Implementation Status (Testing Foundation Complete)

**✅ Professional Testing Infrastructure:**
- BDD Scenarios: 23 comprehensive scenarios covering all admin workflows (540+ lines step definitions)
- Contract Testing: 5 PowerShell-Python interface contracts preventing breaking changes
- Integration Testing: Cross-language communication and system-level workflow validation
- Quality Pipeline: Pre-commit hooks + GitHub Actions with matrix testing

**✅ Automated Quality Assurance:**
- Contract validation: 4.34s local execution, 17/17 tests passing
- Pre-commit enforcement: Automated quality gates preventing bad commits  
- CI/CD integration: GitHub Actions with Python 3.11/3.12 + PowerShell 7.4 matrix
- Security validation: Automated security boundary contract enforcement

**✅ Development Infrastructure:**
- Phase 0 Security Policies: All custom Windows policies (S001-S022) implemented and tested
- External configuration: Family parameterization with privacy protection
- Reversible deployment: -Reverse flag with comprehensive rollback capability
- Documentation: All artifacts properly organized in guardrails/ structure

**🚀 Ready for Confident Phase 1 Development:**
- Testing foundation eliminates regression risk
- Interface stability guaranteed through contract validation
- Automated quality enforcement prevents technical debt
- BDD scenarios provide clear development specifications

---
*Update session context each time. Keep this file under 2KB.*