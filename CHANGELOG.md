# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-06

### Added
- `@security-ignore` inline comment suppression for false positives
  - `// @security-ignore` - suppresses all types
  - `// @security-ignore TYPE` - suppresses specific type
  - `// @security-ignore TYPE: reason` - with optional reason
- Expanded SafeCode.php test patterns from 6 to 30+ patterns
- Documentation for `@security-ignore` in README.md and SKILL.md

### Changed
- Unified `@security-ignore` to same-line only (like `@phpstan-ignore-line`)
- Optimized AbstractDetector to avoid duplicate `explode()` calls

### Fixed
- Removed dead code in `isIgnored()` method
- Cleaned up Psalm plugin code

## [0.2.0] - 2025-12-30

### Added
- Claude CLI support for AI Auditor (Max plan)
- Psalm taint annotations for Aura.Sql ExtendedPdoInterface
- Comprehensive performance benchmark suite
- DAST CLI improvements and GitHub Pages documentation
- Psalm taint plugin for BEAR.Sunday ResourceObject

## [0.1.2] - 2025-12-29

### Fixed
- CodeRabbit nitpick comments addressed

## [0.1.1] - 2025-12-29

### Fixed
- Minor fixes and improvements

## [0.1.0] - 2025-12-29

### Added
- Initial release
- SAST scanner with 14 vulnerability detectors
- DAST scanner for dynamic testing
- AI Auditor with Claude API integration
- Multiple output formats (Console, JSON, SARIF, HTML)
- OWASP Top 10 coverage reporting
