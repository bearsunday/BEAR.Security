<?php

declare(strict_types=1);

namespace BEAR\Security\Report;

use RuntimeException;

use function basename;
use function file_exists;
use function file_get_contents;
use function is_string;
use function preg_replace_callback;
use function realpath;
use function sprintf;
use function str_starts_with;

/**
 * Simple template renderer with placeholder substitution
 */
final class TemplateRenderer
{
    private string $templateDir;

    public function __construct(?string $templateDir = null)
    {
        $this->templateDir = $templateDir ?? dirname(__DIR__, 2) . '/templates';
    }

    /**
     * Render a template with variables
     *
     * @param array<string, string|int|float> $variables
     */
    public function render(string $templateName, array $variables = []): string
    {
        // Prevent directory traversal attacks
        $templateName = basename($templateName);
        $templatePath = $this->templateDir . '/' . $templateName;

        if (! file_exists($templatePath)) {
            throw new RuntimeException(sprintf('Template not found: %s', $templateName));
        }

        // Validate the resolved path is within template directory
        $realTemplatePath = realpath($templatePath);
        $realTemplateDir = realpath($this->templateDir);

        if ($realTemplatePath === false || $realTemplateDir === false) {
            throw new RuntimeException(sprintf('Template not found: %s', $templateName));
        }

        if (! str_starts_with($realTemplatePath, $realTemplateDir)) {
            throw new RuntimeException(sprintf('Invalid template path: %s', $templateName));
        }

        $content = file_get_contents($templatePath);
        if (! is_string($content)) {
            throw new RuntimeException(sprintf('Failed to read template: %s', $templateName));
        }

        return $this->substitute($content, $variables);
    }

    /**
     * Substitute placeholders in content
     *
     * @param array<string, string|int|float> $variables
     */
    public function substitute(string $content, array $variables): string
    {
        return (string) preg_replace_callback(
            '/\{\{(\w+)\}\}/',
            static fn (array $matches): string => isset($variables[$matches[1]])
                ? (string) $variables[$matches[1]]
                : $matches[0],
            $content,
        );
    }

    /**
     * Get template directory
     */
    public function getTemplateDir(): string
    {
        return $this->templateDir;
    }
}
