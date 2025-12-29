<?php

declare(strict_types=1);

namespace BEAR\Security\Demo\Resource\App\Vulnerable;

use BEAR\Resource\ResourceObject;

/**
 * VULNERABLE: Server-Side Request Forgery (SSRF)
 *
 * Expected: TaintedSSRF or similar detection
 */
class Ssrf extends ResourceObject
{
    public function onGet(): static
    {
        $url = $_GET['url'] ?? '';

        // VULNERABLE: SSRF via file_get_contents
        $this->body['content'] = file_get_contents($url);

        return $this;
    }

    public function onPost(): static
    {
        $url = $_POST['api_url'] ?? '';

        // VULNERABLE: SSRF via curl
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $this->body['response'] = curl_exec($ch);
        curl_close($ch);

        return $this;
    }
}
