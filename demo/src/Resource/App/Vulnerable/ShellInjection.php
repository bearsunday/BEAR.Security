<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: Direct shell command execution
 *
 * Expected: TaintedShell detection
 */
class ShellInjection extends ResourceObject
{
    public function onGet(string $filename): static
    {
        // VULNERABLE: Shell injection via shell_exec
        $this->body['content'] = shell_exec('cat ' . $filename);

        return $this;
    }

    public function onPost(string $command): static
    {
        // VULNERABLE: Direct command execution
        $this->body['result'] = exec($command);

        return $this;
    }
}
