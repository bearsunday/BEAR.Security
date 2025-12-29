<?php

declare(strict_types=1);

namespace BEAR\Security;

use BEAR\Security\Report\TemplateRenderer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(TemplateRenderer::class)]
class TemplateRendererTest extends TestCase
{
    private TemplateRenderer $renderer;

    protected function setUp(): void
    {
        $this->renderer = new TemplateRenderer();
    }

    public function testSubstitute(): void
    {
        $content = 'Hello, {{name}}! You have {{count}} messages.';
        $variables = ['name' => 'John', 'count' => 5];

        $result = $this->renderer->substitute($content, $variables);

        $this->assertSame('Hello, John! You have 5 messages.', $result);
    }

    public function testSubstituteWithMissingVariable(): void
    {
        $content = 'Hello, {{name}}! Your status: {{status}}';
        $variables = ['name' => 'John'];

        $result = $this->renderer->substitute($content, $variables);

        // Missing variable should remain as placeholder
        $this->assertSame('Hello, John! Your status: {{status}}', $result);
    }

    public function testSubstituteWithNoVariables(): void
    {
        $content = 'Static content without placeholders.';

        $result = $this->renderer->substitute($content, []);

        $this->assertSame('Static content without placeholders.', $result);
    }

    public function testGetTemplateDir(): void
    {
        $templateDir = $this->renderer->getTemplateDir();

        $this->assertStringEndsWith('/templates', $templateDir);
    }

    public function testCustomTemplateDir(): void
    {
        $customDir = '/custom/templates';
        $renderer = new TemplateRenderer($customDir);

        $this->assertSame($customDir, $renderer->getTemplateDir());
    }

    public function testRenderThrowsExceptionForMissingTemplate(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Template not found: nonexistent.html');

        $this->renderer->render('nonexistent.html');
    }

    public function testRenderPreventsDirectoryTraversal(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Template not found');

        $this->renderer->render('../../../etc/passwd');
    }

    public function testRenderExistingTemplate(): void
    {
        // Check if templates directory exists
        $templateDir = $this->renderer->getTemplateDir();
        if (! is_dir($templateDir)) {
            $this->markTestSkipped('Templates directory does not exist');
        }

        $templates = glob($templateDir . '/*.html');
        if ($templates === false || $templates === []) {
            $this->markTestSkipped('No templates available');
        }

        $templateName = basename($templates[0]);
        $result = $this->renderer->render($templateName, ['title' => 'Test']);

        $this->assertNotEmpty($result);
    }
}
