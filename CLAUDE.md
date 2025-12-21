# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BEAR.Security is a PHP security vulnerability scanner for BEAR.Sunday applications with three scanning modes:

| Mode | Tool | Method | Use Case |
|------|------|--------|----------|
| **SAST** | `bear.security-scan` | Regex pattern matching | Fast, local, CI/CD |
| **DAST** | `DastScanner` | HTTP payload injection | Running applications |
| **AI Audit** | `bear-security-audit` | Claude API analysis | Deep context-aware analysis |

All modes provide 100% OWASP Top 10 coverage with multiple output formats (Console, JSON, SARIF, HTML).

## Common Commands

### Testing and Quality Assurance
```bash
# Run unit tests
composer test
# or
vendor/bin/phpunit

# Run single test file
vendor/bin/phpunit tests/ScannerTest.php

# Run single test method
vendor/bin/phpunit --filter testScanDirectory tests/ScannerTest.php

# Generate coverage report
composer coverage

# Run static analysis
composer sa                    # Both PHPStan and Psalm
composer phpstan              # PHPStan only
composer psalm                # Psalm only

# Run Psalm taint analysis (critical for security scanner)
vendor/bin/psalm --taint-analysis

# Coding standards
composer cs                    # Check
composer cs-fix               # Fix
```

### Security Scanning
```bash
# Scan directory
vendor/bin/bear.security-scan src

# Generate SARIF output for GitHub Security
vendor/bin/bear.security-scan src --format=sarif > report.sarif

# Generate OWASP Top 10 checklist
vendor/bin/bear.security-scan src --format=checklist
vendor/bin/bear.security-scan src --format=checklist-html -o report.html
vendor/bin/bear.security-scan src --format=checklist-json > checklist.json

# Exclude patterns
vendor/bin/bear.security-scan src --exclude='/vendor/' --exclude='/tests/'
```

### AI Audit (requires ANTHROPIC_API_KEY)
```bash
# Run AI-powered deep analysis
ANTHROPIC_API_KEY=sk-xxx vendor/bin/bear-security-audit src

# Output formats
vendor/bin/bear-security-audit src --format=json
vendor/bin/bear-security-audit src --format=sarif --output=results.sarif
```

### Build and Maintenance
```bash
# Full build process
composer build

# Clean caches
composer clean
```

## Architecture

### Core Design Pattern

BEAR.Security follows a **pattern-based detection architecture** with extensibility:

```
Scanner (main orchestrator)
  ├── Loads 14 default Detectors (or accepts custom ones)
  ├── Recursively scans PHP files in directory
  ├── Each Detector scans file content with regex patterns
  └── Returns ScanResult with Vulnerability objects
```

### Key Components

**1. Scanner (`src/Scanner.php`)**
- Main entry point for scanning operations
- Manages detector registration and file iteration
- Supports custom detectors via `addDetector()` or constructor injection
- File filtering by extension and exclude patterns

**2. AbstractDetector (`src/Detector/AbstractDetector.php`)**
- Base class for all vulnerability detectors
- Pattern-based detection using regex
- Each detector defines `$patterns` array:
  ```php
  protected array $patterns = [
      'VULNERABILITY_TYPE' => [
          'pattern' => '/regex_pattern/i',
          'severity' => 'CRITICAL|HIGH|MEDIUM|LOW',
          'description' => 'What was detected',
          'recommendation' => 'How to fix',
      ],
  ];
  ```
- Automatically extracts line numbers and code snippets

**3. Detectors (14 total in `src/Detector/`)**
Each detector targets specific OWASP categories:
- SqlInjectionDetector → A03 (Injection)
- XssDetector → A03 (Injection)
- CommandInjectionDetector → A03 (Injection)
- PathTraversalDetector → A01 (Broken Access Control)
- RemoteFileInclusionDetector → A10 (SSRF)
- CsrfDetector → A07 (Auth Failures)
- CryptographicFailuresDetector → A02 (Cryptographic Failures)
- InsecureDeserializationDetector → A08 (Integrity Failures)
- DangerousFunctionDetector → A03 (Injection)
- SessionSecurityDetector → A07 (Auth Failures)
- OpenRedirectDetector → A01 (Broken Access Control)
- XxeDetector → A05 (Security Misconfiguration)
- HeaderInjectionDetector → A05 (Security Misconfiguration)
- WeakRandomDetector → A02 (Cryptographic Failures)

**4. Output Formatters (`src/Output/`)**
- `ConsoleOutput`: Human-readable terminal output with colors
- `JsonOutput`: Structured JSON for CI/CD pipelines
- `SarifOutput`: SARIF 2.1.0 format for GitHub Security tab integration

**5. OWASP Top 10 Reporting (`src/Report/`)**
- `SecurityChecklistReport`: Maps vulnerabilities to OWASP Top 10 categories
- Generates text/JSON/HTML checklist reports
- Calculates compliance score

**6. DAST Components (`src/Dast/`)**
- `DastScanner`: HTTP-based dynamic testing with custom HTTP client injection
- `SecurityTest`/`SecurityWorkflowTest`: Base classes for BEAR.Resource integration
- Payload classes for SQL, XSS, Command Injection, Path Traversal, CSRF, RFI testing
- `SecurityHeadersAnalyzer`: HTTP security header validation
- Supports logging via `setLogFile()` for debugging

**7. AI Auditor (`src/Ai/`)**
- `ClaudeAuditor`: Claude API integration for context-aware analysis
- `PromptBuilder`: Constructs prompts using `SKILL.md` as context
- `FileCollector`: Gathers PHP files for analysis
- `TokenTracker`: Monitors API token usage
- Detects vulnerabilities requiring semantic understanding: IDOR, Mass Assignment, Race Conditions, Timing Attacks

**8. SKILL.md (Project Root)**
- AI auditor's knowledge base for security analysis
- Contains SAST patterns, AI-only detection patterns, and false positive rules
- Used by `PromptBuilder` to construct Claude API prompts
- Editable to customize AI detection behavior

### Important Design Principles

**Pattern Matching Strategy**
- All detectors use regex patterns for static analysis
- Patterns match **dangerous usage**, not just function presence
- Context matters: `$pdo->exec()` vs `shell_exec()`
- Line numbers calculated from match offset

**Extensibility**
Custom detectors can be added:
```php
class CustomDetector extends AbstractDetector
{
    protected array $patterns = [
        'CUSTOM_VULN' => [
            'pattern' => '/pattern/',
            'severity' => 'HIGH',
            'description' => 'Description',
            'recommendation' => 'Fix',
        ],
    ];
}

$scanner->addDetector(new CustomDetector());
```

**SARIF Integration**
- SARIF output follows version 2.1.0 specification
- Each vulnerability mapped to OWASP category and CWE
- Compatible with GitHub Security tab
- Rule IDs normalized to remove suffixes

**OWASP Mapping**
The SecurityChecklistReport categorizes findings:
- Maps vulnerability types to A01-A10 categories
- Uses prefix matching for type detection
- Generates pass/fail status for each category
- A04 (Insecure Design) and A09 (Logging) are PASS by design (BEAR.Sunday ROA + DI)

## Development Notes

### Adding a New Detector

1. Create class in `src/Detector/` extending `AbstractDetector`
2. Define `$patterns` array with vulnerability signatures
3. Register in `Scanner::getDefaultDetectors()` or inject via constructor
4. Add test cases in `tests/` with vulnerable code samples
5. Update OWASP mapping in `SecurityChecklistReport::categorizeVulnerability()` if needed

### Test Structure

- `tests/Fake/VulnerableCode.php`: Intentionally vulnerable code samples
- `tests/Fake/SafeCode.php`: Safe code that should not trigger
- `tests/Fixture/VulnerableApp/`: BEAR.Sunday app for DAST testing
- Detectors tested by verifying they find known vulnerabilities in test files

### Static Analysis Configuration

**Psalm** (`psalm.xml`):
- Level 1 (strictest)
- `runTaintAnalysis="true"` enabled (critical for security scanner)
- Suppresses issues in DAST files due to optional BEAR\Resource dependency

**PHPStan** (`phpstan.neon`):
- Level max
- Ignores VulnerableCode.php (intentionally insecure test code)

### CLI Tools

**`bin/bear.security-scan`** (SAST):
- Parses arguments manually (no external dependencies)
- Searches for autoloader in multiple locations (standalone/vendor/dev)
- Exit codes: 0 = clean, 1 = CRITICAL/HIGH vulnerabilities found

**`bin/bear-security-audit`** (AI):
- Requires `ANTHROPIC_API_KEY` environment variable
- Uses `claude-sonnet-4-20250514` model
- Reports token usage after scan
- Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = error

## BEAR.Sunday Integration

This scanner is optimized for BEAR.Sunday applications:

**Why BEAR.Sunday is Secure by Design:**
- ROA (Resource Oriented Architecture): Clean separation, no global state
- Dependency Injection: No hardcoded dependencies
- PSR-3 Logger via DI: A09 (Logging) covered automatically
- Immutable Resources: Predictable behavior
- Defined Routes: DAST doesn't need auto-crawling

**DAST for BEAR.Sunday:**
- Extends `SecurityTest` or `SecurityWorkflowTest`
- Uses BEAR\Resource for HTTP workflow testing
- Payloads injected into resource requests
- Security headers analyzed from responses

## Key Files to Understand

- `src/Scanner.php`: Main SAST orchestrator
- `src/Detector/AbstractDetector.php`: Pattern-based detection engine
- `src/Dast/DastScanner.php`: HTTP-based dynamic testing
- `src/Ai/ClaudeAuditor.php`: Claude API integration
- `src/Ai/PromptBuilder.php`: AI prompt construction with SKILL.md
- `src/Report/SecurityChecklistReport.php`: OWASP Top 10 mapping logic
- `src/Output/SarifOutput.php`: GitHub Security integration
- `SKILL.md`: AI auditor knowledge base (detection patterns, false positive rules)
- `bin/bear.security-scan`: SAST CLI entry point
- `bin/bear-security-audit`: AI Audit CLI entry point

## Requirements

- PHP 8.1+ (strict types enforced)
- No runtime dependencies for SAST
- ANTHROPIC_API_KEY for AI Audit
- BEAR.Sunday + bear/devtools for DAST (optional)
- Psalm for taint analysis (dev dependency)