<?php

declare(strict_types=1);

namespace BEAR\Security\Output;

use BEAR\Security\ScanResult;
use BEAR\Security\VulnerabilityInterface;

use function implode;
use function sprintf;
use function str_replace;
use function str_starts_with;
use function strtolower;
use function strtoupper;

use const PHP_EOL;

/**
 * Console output formatter with Psalm-style structure
 */
final class ConsoleOutput implements OutputInterface
{
    private const RESET = "\033[0m";
    private const RED = "\033[0;31m";
    private const GREEN = "\033[0;32m";
    private const BOLD = "\033[1m";
    private const BG_RED = "\033[41m";
    private const WHITE = "\033[0;37m";
    private const DOCS_URL = 'https://bearsunday.github.io/BEAR.Security/issues/en/';

    public function __construct(private bool $useColors = true)
    {
    }

    public function format(ScanResult $result): string
    {
        $output = PHP_EOL;

        // Vulnerabilities first (like Psalm)
        if ($result->hasVulnerabilities()) {
            $output .= $this->formatVulnerabilities($result);
        }

        // Summary at the end
        $output .= $this->formatSummary($result);

        return $output;
    }

    private function formatSummary(ScanResult $result): string
    {
        $output = PHP_EOL;

        $count = $result->getVulnerabilityCount();
        $files = $result->getFilesScanned();
        $time = $result->getScanTime();

        if ($count === 0) {
            $output .= $this->color('No security issues found!', self::GREEN) . PHP_EOL;
        } else {
            $critical = $result->getCriticalCount();
            $high = $result->getHighCount();
            $medium = $result->getMediumCount();
            $low = $result->getLowCount();

            $parts = [];
            if ($critical > 0) {
                $parts[] = $this->color("{$critical} critical", self::RED);
            }

            if ($high > 0) {
                $parts[] = $this->color("{$high} high", self::RED);
            }

            if ($medium > 0) {
                $parts[] = $this->color("{$medium} medium", self::RED);
            }

            if ($low > 0) {
                $parts[] = $this->color("{$low} low", self::RED);
            }

            $output .= sprintf(
                "%d issues found: %s\n",
                $count,
                implode(', ', $parts),
            );
        }

        $output .= sprintf("Scanned %d endpoints in %.2fs", $files, $time) . PHP_EOL;

        return $output;
    }

    private function formatVulnerabilities(ScanResult $result): string
    {
        $output = '';

        $severityOrder = [
            VulnerabilityInterface::SEVERITY_CRITICAL,
            VulnerabilityInterface::SEVERITY_HIGH,
            VulnerabilityInterface::SEVERITY_MEDIUM,
            VulnerabilityInterface::SEVERITY_LOW,
        ];

        foreach ($severityOrder as $severity) {
            $vulnerabilities = $result->getVulnerabilitiesBySeverity($severity);
            foreach ($vulnerabilities as $vuln) {
                $output .= $this->formatVulnerability($vuln);
            }
        }

        return $output;
    }

    private function formatVulnerability(VulnerabilityInterface $vuln): string
    {
        $severity = strtoupper($vuln->getSeverity());
        $severityLabel = $this->formatSeverityLabel($severity);
        $type = $vuln->getType();

        // Main line: ERROR: Type - file:line - description
        $output = sprintf(
            "%s: %s - %s:%d - %s\n",
            $severityLabel,
            $type,
            $vuln->getFile(),
            $vuln->getLine(),
            $vuln->getDescription(),
        );

        // Documentation link
        $docUrl = self::DOCS_URL . $this->typeToSlug($type);
        $output .= sprintf("  see %s\n", $docUrl);

        // Recommendation
        $output .= $this->color(
            sprintf("  %s\n", $vuln->getRecommendation()),
            self::GREEN,
        );

        $output .= PHP_EOL;

        return $output;
    }

    /** Convert vulnerability type to URL slug (e.g., "SQL_INJECTION_DIRECT_VARIABLE" -> "sql-injection") */
    private function typeToSlug(string $type): string
    {
        // SCREAMING_SNAKE_CASE to kebab-case
        $slug = strtolower(str_replace('_', '-', $type));

        // Known document slugs (main categories)
        $prefixes = [
            'sql-injection',
            'command-injection',
            'cryptographic-failures',
            'csrf',
            'dangerous-function',
            'header-injection',
            'insecure-deserialization',
            'open-redirect',
            'path-traversal',
            'remote-file-inclusion',
            'session-security',
            'weak-random',
            'xss',
            'xxe',
        ];

        foreach ($prefixes as $prefix) {
            if (str_starts_with($slug, $prefix)) {
                return $prefix;
            }
        }

        return $slug;
    }

    private function formatSeverityLabel(string $severity): string
    {
        return match ($severity) {
            'CRITICAL' => $this->styledLabel('CRITICAL', self::BG_RED . self::WHITE . self::BOLD),
            'HIGH' => $this->styledLabel('HIGH', self::RED . self::BOLD),
            'MEDIUM' => $this->styledLabel('MEDIUM', self::RED . self::BOLD),
            default => $this->styledLabel('LOW', self::RED . self::BOLD),
        };
    }

    private function color(string $text, string $color): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return $color . $text . self::RESET;
    }

    /** Apply multiple styles in a single sequence (avoids nested RESET issues) */
    private function styledLabel(string $text, string $styles): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return $styles . $text . self::RESET;
    }
}
