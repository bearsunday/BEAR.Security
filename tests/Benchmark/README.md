# BEAR.Security Benchmark Suite

Comprehensive benchmark suite for measuring scanner accuracy and performance.

## Structure

```
tests/Benchmark/
├── TruePositives/              # Vulnerabilities that SHOULD be detected
│   ├── Level1_Basic/           # Direct patterns (expected: 100%)
│   ├── Level2_Intermediate/    # Variable-based (expected: 70-90%)
│   ├── Level3_Advanced/        # Obfuscated (expected: 30-60%)
│   └── Level4_AIOnly/          # Context-required (expected: 0-10% SAST)
│
├── FalsePositives/             # Safe code that should NOT trigger
│   └── SafePatterns.php        # Sanitized, escaped, safe patterns
│
├── RealWorld/                  # CVE-based patterns
│   └── CvePatterns.php         # Real vulnerabilities from CVEs
│
├── Scale/                      # Performance testing
│   ├── Generator.php           # Generates test files
│   ├── Small/                  # 10 files, ~50 vulns
│   ├── Medium/                 # 50 files, ~250 vulns
│   └── Large/                  # 200 files, ~1000 vulns
│
└── BenchmarkRunner.php         # Main benchmark script
```

## Vulnerability Levels

| Level | Description | Detection Target | SAST Expected |
|-------|-------------|------------------|---------------|
| 1 | Direct `$_GET`/`$_POST` usage | Any scanner | 100% |
| 2 | Via variables, multi-step | Good scanners | 70-90% |
| 3 | Obfuscated, dynamic calls | Advanced scanners | 30-60% |
| 4 | IDOR, Race Condition, etc. | AI only | 0-10% |

## Usage

```bash
# Run all benchmarks
php tests/Benchmark/BenchmarkRunner.php

# Test specific level
php tests/Benchmark/BenchmarkRunner.php --level=1
php tests/Benchmark/BenchmarkRunner.php --level=4

# Test false positives only
php tests/Benchmark/BenchmarkRunner.php --level=fp

# Scale test
php tests/Benchmark/BenchmarkRunner.php --scale=small
php tests/Benchmark/BenchmarkRunner.php --scale=medium
php tests/Benchmark/BenchmarkRunner.php --scale=large

# Combined
php tests/Benchmark/BenchmarkRunner.php --level=all --scale=medium
```

## Metrics

### Detection Rate (Recall)
```
Detection Rate = True Positives / (True Positives + False Negatives)
```

### Precision
```
Precision = True Positives / (True Positives + False Positives)
```

### F1 Score
```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

## AI-Only Vulnerabilities (Level 4)

These require semantic understanding:

| Vulnerability | Why AI-Only |
|--------------|-------------|
| IDOR | Requires understanding authorization context |
| Mass Assignment | Needs to understand data flow and field protection |
| Race Condition | Requires understanding transaction boundaries |
| Timing Attack | Must recognize cryptographic comparison context |
| Business Logic | Needs domain understanding |

## Adding New Test Cases

1. **True Positive**: Add to appropriate level directory
2. **False Positive**: Add to `FalsePositives/SafePatterns.php`
3. **CVE Pattern**: Add to `RealWorld/CvePatterns.php`

## Expected Results

### Industry Standard Comparison

| Tool | Level 1 | Level 2 | Level 3 | Level 4 | FP Rate |
|------|---------|---------|---------|---------|---------|
| Basic Grep | 80% | 30% | 5% | 0% | High |
| PHPCS Security | 90% | 50% | 20% | 0% | Medium |
| Psalm Taint | 95% | 80% | 40% | 5% | Low |
| BEAR.Security | 100% | 70%+ | 40%+ | 10%* | Low |
| AI Audit | 100% | 90% | 70% | 60%+ | Very Low |

*SAST mode only; AI Audit mode significantly higher
