# Issue: Add @security-ignore suppression comments

## Summary

Add inline suppression comments to ignore specific security rules, with mandatory reason documentation.

## Syntax

```php
// @security-ignore DANGEROUS_EXEC: Using escapeshellarg for sanitization
shell_exec($safe);

// @security-ignore WEAK_HASH_MD5, WEAK_HASH_SHA1: Cache key generation only
$key = md5($content);
```

## Specification

| Item | Spec |
|------|------|
| Format | `// @security-ignore RULE[, RULE...]: reason` |
| Reason | **Required** (colon and text after it) |
| Multiple rules | Comma-separated before colon |
| Scope | Next line only (like PHPStan) |
| Suppress all | **Not supported** (prevent abuse) |
| Min reason length | None |

## Features

### 1. Basic Suppression (SAST)
```php
// @security-ignore DANGEROUS_EXEC: PDO exec method, not shell
$pdo->exec($sql);
```

### 2. Multiple Rules
```php
// @security-ignore SQL_INJECTION, XSS: Test fixture with intentional vulnerabilities
$query = "SELECT * FROM " . $_GET['table'];
```

### 3. Suppression Count Report
Add `--report-ignores` option to output suppression statistics:
```
Suppression Report:
  DANGEROUS_EXEC: 3
  WEAK_HASH_MD5: 2
  Total: 5
```

### 4. AI Audit: Validate Suppressions

AI does NOT ignore `@security-ignore`. Instead, AI **validates** whether the suppression reason is appropriate.

**AI behavior:**
1. Detect `@security-ignore` comment and its reason
2. Analyze whether the reason is valid for the code context
3. Report if the suppression seems inappropriate

**Example - Inappropriate suppression:**
```php
// @security-ignore SQL_INJECTION: Not user input
$pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
```

AI should report:
```
INVALID_SUPPRESSION at line 42:
  Rule: SQL_INJECTION
  Reason given: "Not user input"
  Problem: $_GET['id'] is clearly user input. Suppression is inappropriate.
  Recommendation: Use prepared statements instead of suppressing.
```

**Example - Valid suppression:**
```php
// @security-ignore WEAK_HASH_MD5: Cache key for content deduplication, not security
$cacheKey = 'file_' . md5($fileContent);
```

AI should accept this suppression (MD5 for cache keys is acceptable).

## Implementation

### SAST (AbstractDetector)

```php
// In AbstractDetector::detect()
private function isLineSuppressed(string $content, int $lineNumber, string $ruleId): ?string
{
    $lines = explode("\n", $content);
    $prevLine = $lines[$lineNumber - 2] ?? '';

    // Match: // @security-ignore RULE1, RULE2: reason
    if (preg_match('/@security-ignore\s+([^:]+):\s*(.+)/', $prevLine, $matches)) {
        $rules = array_map('trim', explode(',', $matches[1]));
        $reason = trim($matches[2]);

        if (in_array($ruleId, $rules) && $reason !== '') {
            return $reason; // Suppressed with valid reason
        }
    }

    return null; // Not suppressed
}
```

### AI Audit (SKILL.md addition)

```markdown
## Suppression Comment Validation

When analyzing code, look for `// @security-ignore RULE: reason` comments.

**Your task:** Validate whether the suppression is appropriate.

### Valid suppressions (accept):
- MD5/SHA1 for cache keys, checksums, non-security purposes
- shell_exec with proper escapeshellarg() sanitization
- Test fixtures with intentional vulnerabilities

### Invalid suppressions (report):
- Claiming input is "not user input" when it clearly is ($_GET, $_POST, etc.)
- Security-critical operations with weak justification
- Suppressions that hide real vulnerabilities

### Report format for invalid suppressions:
- Location (file:line)
- Rule being suppressed
- Reason given by developer
- Why the reason is invalid
- Recommended fix
```

### Validation Errors (SAST)

```
ERROR: @security-ignore without reason at src/Foo.php:42
  // @security-ignore DANGEROUS_EXEC
                                     ^ missing ": reason"
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--report-ignores` | Show suppression count by rule |
| `--no-ignore` | Disable all suppressions (for strict audit) |

## Test Cases

```php
// Valid - SAST skips, AI accepts
// @security-ignore DANGEROUS_EXEC: Escaped with escapeshellarg
shell_exec($safe);

// Invalid - missing reason (SAST error)
// @security-ignore DANGEROUS_EXEC
shell_exec($cmd);

// Invalid - inappropriate reason (AI reports)
// @security-ignore SQL_INJECTION: Safe query
$pdo->query("SELECT * FROM " . $_GET['table']);
```

## References

- PHPStan: `// @phpstan-ignore identifier (reason)`
- Psalm: `/** @psalm-suppress IssueType */`
- ESLint: `// eslint-disable-next-line rule-name`
