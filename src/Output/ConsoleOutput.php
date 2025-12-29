<?php

declare(strict_types=1);

namespace BEAR\Security\Output;

use BEAR\Security\ScanResult;
use BEAR\Security\VulnerabilityInterface;

use function explode;
use function implode;
use function preg_replace;
use function sprintf;
use function strtolower;
use function strtoupper;

use const PHP_EOL;

/**
 * Console output formatter with Psalm-style colors
 */
final class ConsoleOutput implements OutputInterface
{
    private const RESET = "\033[0m";
    private const RED = "\033[0;31m";
    private const YELLOW = "\033[0;33m";
    private const GREEN = "\033[0;32m";
    private const CYAN = "\033[0;36m";
    private const GRAY = "\033[0;90m";
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
                $parts[] = $this->color("{$medium} medium", self::YELLOW);
            }

            if ($low > 0) {
                $parts[] = "{$low} low";
            }

            $output .= sprintf(
                "%d issues found: %s\n",
                $count,
                implode(', ', $parts),
            );
        }

        $output .= $this->color(
            sprintf("Scanned %d endpoints in %.2fs", $files, $time),
            self::GRAY,
        ) . PHP_EOL;

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
        $output .= $this->color(sprintf("  see %s\n", $docUrl), self::GRAY);

        // Recommendation
        $output .= $this->color(
            sprintf("  %s\n", $vuln->getRecommendation()),
            self::CYAN,
        );

        // Code snippet with context
        $snippet = $vuln->getCodeSnippet();
        if ($snippet !== '') {
            foreach (explode("\n", $snippet) as $line) {
                $output .= $this->color("    {$line}\n", self::GRAY);
            }
        }

        $output .= PHP_EOL;

        return $output;
    }

    /** Convert vulnerability type to URL slug (e.g., "SqlInjection" -> "sql-injection") */
    private function typeToSlug(string $type): string
    {
        // Insert hyphen before uppercase letters, then lowercase
        $slug = (string) preg_replace('/([a-z])([A-Z])/', '$1-$2', $type);

        return strtolower($slug);
    }

    private function formatSeverityLabel(string $severity): string
    {
        return match ($severity) {
            'CRITICAL' => $this->color($this->bold('CRITICAL'), self::BG_RED . self::WHITE),
            'HIGH' => $this->color($this->bold('HIGH'), self::RED),
            'MEDIUM' => $this->color($this->bold('MEDIUM'), self::YELLOW),
            default => $this->color('LOW', self::GRAY),
        };
    }

    private function color(string $text, string $color): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return $color . $text . self::RESET;
    }

    private function bold(string $text): string
    {
        if (! $this->useColors) {
            return $text;
        }

        return self::BOLD . $text . self::RESET;
    }
}
