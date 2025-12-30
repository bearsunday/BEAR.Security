<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\TruePositives\Level3_Advanced;

/**
 * Level 3: Advanced Vulnerabilities
 *
 * Obfuscated patterns, dynamic function calls, complex data flows.
 * Detection difficulty: Hard
 * Expected detection rate: 30-60%
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class AdvancedVulnerabilities
{
    // =========================================================================
    // Dynamic Function Calls
    // =========================================================================

    public function dynamicFunctionExec(): void
    {
        $func = 'exe' . 'c';
        $func($_GET['cmd']);
    }

    public function dynamicFunctionViaVariable(): void
    {
        $functions = ['system', 'exec', 'shell_exec'];
        $fn = $functions[array_rand($functions)];
        $fn($_POST['command']);
    }

    public function dynamicFunctionViaClosure(): void
    {
        $executor = fn($cmd) => shell_exec($cmd);
        $executor($_GET['input']);
    }

    public function dynamicFunctionViaCallUserFunc(): void
    {
        call_user_func('system', $_GET['cmd']);
    }

    public function dynamicFunctionViaCallUserFuncArray(): void
    {
        call_user_func_array('exec', [$_POST['command'], &$output]);
    }

    // =========================================================================
    // Obfuscated Patterns
    // =========================================================================

    public function obfuscatedEval(): void
    {
        $e = 'e'; $v = 'v'; $a = 'a'; $l = 'l';
        $func = $e . $v . $a . $l;
        $func($_POST['code']);
    }

    public function obfuscatedViaBase64(): void
    {
        $func = base64_decode('c3lzdGVt'); // 'system'
        $func($_GET['cmd']);
    }

    public function obfuscatedViaRot13(): void
    {
        $func = str_rot13('flfgrz'); // 'system'
        $func($_POST['input']);
    }

    public function obfuscatedViaReverse(): void
    {
        $func = strrev('metsys'); // 'system'
        $func($_GET['cmd']);
    }

    public function obfuscatedViaCharCode(): void
    {
        // chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) = 'system'
        $func = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
        $func($_POST['command']);
    }

    // =========================================================================
    // Complex Data Flow
    // =========================================================================

    public function complexFlowViaClass(): void
    {
        $handler = new class {
            public function process(string $data): void
            {
                eval($data);
            }
        };
        $handler->process($_POST['code']);
    }

    public function complexFlowViaCallback(): void
    {
        $data = $_GET['data'];
        array_map(function($item) {
            echo $item; // XSS
        }, explode(',', $data));
    }

    public function complexFlowViaGenerator(): void
    {
        $gen = (function() {
            yield $_GET['sql'];
        })();

        $pdo = new \PDO('sqlite::memory:');
        foreach ($gen as $query) {
            $pdo->query($query);
        }
    }

    public function complexFlowViaTrait(): void
    {
        $obj = new class {
            use VulnerableTrait;
        };
        $obj->execute($_POST['cmd']);
    }

    // =========================================================================
    // Indirect SQL Injection
    // =========================================================================

    public function sqlViaJsonDecode(): void
    {
        $json = $_POST['filter'];
        $filter = json_decode($json, true);
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM users WHERE " . $filter['field'] . " = '" . $filter['value'] . "'");
    }

    public function sqlViaExtract(): void
    {
        extract($_GET); // Creates variables from GET params
        /** @var string $table */
        /** @var string $id */
        $query = "SELECT * FROM $table WHERE id = $id";
    }

    public function sqlViaParse(): void
    {
        parse_str($_SERVER['QUERY_STRING'], $params);
        $sql = "SELECT * FROM logs WHERE action = '" . $params['action'] . "'";
    }

    public function sqlViaObjectProperty(): void
    {
        $request = new \stdClass();
        $request->id = $_GET['id'];
        $pdo = new \PDO('sqlite::memory:');
        $pdo->query("SELECT * FROM users WHERE id = " . $request->id);
    }

    // =========================================================================
    // XSS via Complex Patterns
    // =========================================================================

    public function xssViaOutputBuffer(): void
    {
        ob_start();
        echo $_GET['content'];
        $output = ob_get_clean();
        echo $output;
    }

    public function xssViaHereDoc(): void
    {
        $name = $_POST['name'];
        echo <<<HTML
        <div class="profile">
            <h1>{$name}</h1>
        </div>
        HTML;
    }

    public function xssViaSprintf(): void
    {
        $format = $_GET['format'];
        $data = $_GET['data'];
        echo sprintf($format, $data);
    }

    public function xssViaArrayReduce(): void
    {
        $items = $_POST['items'];
        $html = array_reduce($items, fn($carry, $item) => $carry . "<li>$item</li>", '');
        echo "<ul>$html</ul>";
    }

    // =========================================================================
    // File Operations via Complex Paths
    // =========================================================================

    public function pathViaRealpath(): void
    {
        $file = $_GET['file'];
        $path = realpath("/uploads/" . $file);
        if ($path) {
            include($path); // realpath resolves symlinks but doesn't validate
        }
    }

    public function pathViaGlob(): void
    {
        $pattern = $_GET['pattern'];
        $files = glob("/data/" . $pattern);
        foreach ($files as $file) {
            include($file);
        }
    }

    public function pathViaSplFileInfo(): void
    {
        $file = new \SplFileInfo($_GET['path']);
        include($file->getRealPath());
    }

    // =========================================================================
    // Serialization via Complex Patterns
    // =========================================================================

    public function deserializeViaGzUncompress(): void
    {
        $compressed = $_POST['data'];
        $data = gzuncompress(base64_decode($compressed));
        $obj = unserialize($data);
    }

    public function deserializeViaMagicMethod(): void
    {
        $data = $_COOKIE['state'];
        $obj = unserialize($data);
        // Object's __wakeup or __destruct will be called
    }

    // =========================================================================
    // Second-Order Vulnerabilities
    // =========================================================================

    public function secondOrderSql(): void
    {
        // First: data stored in DB
        $pdo = new \PDO('sqlite::memory:');
        $stmt = $pdo->prepare("INSERT INTO cache (data) VALUES (?)");
        $stmt->execute([$_POST['data']]);

        // Later: data retrieved and used unsafely
        $cached = $pdo->query("SELECT data FROM cache")->fetchColumn();
        $pdo->query("SELECT * FROM users WHERE " . $cached);
    }

    public function secondOrderXss(): void
    {
        // Stored in session
        $_SESSION['nickname'] = $_POST['nickname'];

        // Later displayed
        echo "Welcome back, " . $_SESSION['nickname'];
    }

    // =========================================================================
    // Prototype Pollution (PHP equivalent)
    // =========================================================================

    public function prototypePollutionViaArrayMerge(): void
    {
        $defaults = ['role' => 'user', 'active' => true];
        $userInput = json_decode($_POST['settings'], true);
        $config = array_merge($defaults, $userInput);
        // User can set 'role' => 'admin'
    }

    public function prototypePollutionViaRecursive(): void
    {
        $config = ['db' => ['host' => 'localhost']];
        $this->mergeRecursive($config, $_POST);
    }

    private function mergeRecursive(array &$target, array $source): void
    {
        foreach ($source as $key => $value) {
            if (is_array($value) && isset($target[$key]) && is_array($target[$key])) {
                $this->mergeRecursive($target[$key], $value);
            } else {
                $target[$key] = $value;
            }
        }
    }

    // =========================================================================
    // ReDoS Patterns
    // =========================================================================

    public function redosVulnerable(): bool
    {
        $input = $_POST['email'];
        // Vulnerable regex with catastrophic backtracking
        return (bool) preg_match('/^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]+)+$/', $input);
    }

    public function redosNestedQuantifiers(): bool
    {
        $input = $_GET['data'];
        return (bool) preg_match('/^(a+)+$/', $input);
    }

    public function redosFromUserPattern(): bool
    {
        $pattern = $_POST['pattern'];
        $subject = $_POST['subject'];
        return (bool) preg_match('/' . $pattern . '/', $subject);
    }
}

trait VulnerableTrait
{
    public function execute(string $cmd): void
    {
        system($cmd);
    }
}
