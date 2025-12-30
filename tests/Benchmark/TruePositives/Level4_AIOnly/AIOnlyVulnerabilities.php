<?php

declare(strict_types=1);

namespace BEAR\Security\Tests\Benchmark\TruePositives\Level4_AIOnly;

/**
 * Level 4: AI-Only Detectable Vulnerabilities
 *
 * These require semantic understanding and context awareness.
 * Pattern-based SAST cannot detect these.
 * Detection difficulty: Requires AI
 * Expected SAST detection rate: 0-10%
 * Expected AI detection rate: 60-90%
 *
 * @phpstan-ignore-file
 * @psalm-suppress all
 */
class AIOnlyVulnerabilities
{
    private \PDO $pdo;

    public function __construct()
    {
        $this->pdo = new \PDO('sqlite::memory:');
    }

    // =========================================================================
    // IDOR (Insecure Direct Object Reference)
    // =========================================================================

    /**
     * IDOR: No authorization check - user can access any order
     * AI should detect: accessing order by ID without checking ownership
     */
    public function getOrder(int $orderId): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM orders WHERE id = ?");
        $stmt->execute([$orderId]);
        return $stmt->fetch(\PDO::FETCH_ASSOC) ?: [];
    }

    /**
     * IDOR: User can delete any document
     */
    public function deleteDocument(int $documentId): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM documents WHERE id = ?");
        return $stmt->execute([$documentId]);
    }

    /**
     * IDOR: Horizontal privilege escalation - can view other users' profiles
     */
    public function getUserProfile(int $userId): array
    {
        // Should check if current user can view this profile
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        return $stmt->fetch(\PDO::FETCH_ASSOC) ?: [];
    }

    /**
     * IDOR: Sequential ID exposure in API
     */
    public function getInvoice(string $invoiceId): array
    {
        // Invoice IDs are sequential: INV-0001, INV-0002...
        // Easy to enumerate
        $stmt = $this->pdo->prepare("SELECT * FROM invoices WHERE invoice_id = ?");
        $stmt->execute([$invoiceId]);
        return $stmt->fetch(\PDO::FETCH_ASSOC) ?: [];
    }

    // =========================================================================
    // Mass Assignment
    // =========================================================================

    /**
     * Mass Assignment: All POST data used to update user
     * AI should detect: role/is_admin could be set by attacker
     */
    public function updateUser(int $userId, array $data): bool
    {
        $fields = [];
        $values = [];
        foreach ($data as $key => $value) {
            $fields[] = "$key = ?";
            $values[] = $value;
        }
        $values[] = $userId;

        $sql = "UPDATE users SET " . implode(', ', $fields) . " WHERE id = ?";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute($values);
    }

    /**
     * Mass Assignment via object hydration
     */
    public function createAccount(array $postData): void
    {
        $account = new Account();
        foreach ($postData as $property => $value) {
            if (property_exists($account, $property)) {
                $account->$property = $value;
            }
        }
        // $postData could contain 'balance' or 'credit_limit'
        $account->save();
    }

    /**
     * Mass Assignment: No whitelist on allowed fields
     */
    public function updateSettings(array $settings): void
    {
        foreach ($settings as $key => $value) {
            $_SESSION['settings'][$key] = $value;
        }
        // Attacker could set settings['is_admin'] = true
    }

    // =========================================================================
    // Race Conditions (TOCTOU)
    // =========================================================================

    /**
     * Race Condition: Check-then-act without transaction
     * AI should detect: balance check and update are not atomic
     */
    public function withdraw(int $userId, float $amount): bool
    {
        // Check balance
        $stmt = $this->pdo->prepare("SELECT balance FROM accounts WHERE user_id = ?");
        $stmt->execute([$userId]);
        $balance = (float) $stmt->fetchColumn();

        // Time gap here allows race condition
        if ($balance >= $amount) {
            // Update balance
            $stmt = $this->pdo->prepare("UPDATE accounts SET balance = balance - ? WHERE user_id = ?");
            return $stmt->execute([$amount, $userId]);
        }

        return false;
    }

    /**
     * Race Condition: Coupon code reuse
     */
    public function applyCoupon(string $code, int $orderId): bool
    {
        // Check if coupon is valid and not used
        $stmt = $this->pdo->prepare("SELECT id, discount FROM coupons WHERE code = ? AND used = 0");
        $stmt->execute([$code]);
        $coupon = $stmt->fetch();

        if ($coupon) {
            // Apply discount
            $this->pdo->prepare("UPDATE orders SET discount = ? WHERE id = ?")->execute([$coupon['discount'], $orderId]);

            // Mark as used (race: multiple requests can pass the check before this)
            $this->pdo->prepare("UPDATE coupons SET used = 1 WHERE id = ?")->execute([$coupon['id']]);

            return true;
        }

        return false;
    }

    /**
     * Race Condition: File-based lock bypass
     */
    public function processFile(string $filename): void
    {
        $lockFile = "/tmp/{$filename}.lock";

        if (!file_exists($lockFile)) {
            touch($lockFile);
            // Process file... (race window between check and touch)
            $this->doProcessing($filename);
            unlink($lockFile);
        }
    }

    private function doProcessing(string $filename): void
    {
        // Processing logic
    }

    // =========================================================================
    // Timing Attacks
    // =========================================================================

    /**
     * Timing Attack: String comparison reveals length
     */
    public function verifyApiKey(string $providedKey): bool
    {
        $storedKey = $this->getStoredApiKey();
        return $providedKey === $storedKey; // Vulnerable to timing attack
    }

    /**
     * Timing Attack: Early return reveals user existence
     */
    public function authenticate(string $username, string $password): bool
    {
        $stmt = $this->pdo->prepare("SELECT password_hash FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $hash = $stmt->fetchColumn();

        if (!$hash) {
            return false; // Fast return reveals user doesn't exist
        }

        return password_verify($password, $hash);
    }

    /**
     * Timing Attack: Token comparison
     */
    public function verifyResetToken(string $token): bool
    {
        $storedToken = $_SESSION['reset_token'] ?? '';
        return $token === $storedToken; // Should use hash_equals()
    }

    private function getStoredApiKey(): string
    {
        return 'secret_api_key_12345';
    }

    // =========================================================================
    // Business Logic Flaws
    // =========================================================================

    /**
     * Business Logic: Negative quantity allows refund abuse
     */
    public function addToCart(int $productId, int $quantity): void
    {
        // No validation that quantity is positive
        $price = $this->getProductPrice($productId);
        $total = $price * $quantity; // Negative quantity = negative total
        $_SESSION['cart'][] = [
            'product_id' => $productId,
            'quantity' => $quantity,
            'total' => $total,
        ];
    }

    /**
     * Business Logic: Price manipulation via client-side data
     */
    public function checkout(array $cartData): void
    {
        // Trust client-provided prices
        $total = array_sum(array_column($cartData, 'price'));
        $this->processPayment($total);
    }

    /**
     * Business Logic: Missing step in workflow
     */
    public function approveRefund(int $refundId): bool
    {
        // Directly approves without manager review for large amounts
        $stmt = $this->pdo->prepare("UPDATE refunds SET status = 'approved' WHERE id = ?");
        return $stmt->execute([$refundId]);
    }

    /**
     * Business Logic: Discount stacking
     */
    public function applyDiscount(float $total, array $discounts): float
    {
        foreach ($discounts as $discount) {
            $total -= $discount; // Multiple discounts can make total negative
        }
        return $total;
    }

    private function getProductPrice(int $productId): float
    {
        return 99.99;
    }

    private function processPayment(float $amount): void
    {
        // Payment processing
    }

    // =========================================================================
    // Authorization Bypass
    // =========================================================================

    /**
     * Authorization: Missing role check for admin function
     */
    public function deleteUser(int $userId): bool
    {
        // No check if current user is admin
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = ?");
        return $stmt->execute([$userId]);
    }

    /**
     * Authorization: Vertical privilege escalation
     */
    public function changeUserRole(int $userId, string $newRole): bool
    {
        // Any authenticated user can change roles
        $stmt = $this->pdo->prepare("UPDATE users SET role = ? WHERE id = ?");
        return $stmt->execute([$newRole, $userId]);
    }

    /**
     * Authorization: Function-level access control missing
     */
    public function exportAllUserData(): array
    {
        // Should require admin role
        $stmt = $this->pdo->query("SELECT * FROM users");
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    // =========================================================================
    // Information Disclosure
    // =========================================================================

    /**
     * Info Disclosure: Verbose error messages
     */
    public function login(string $email, string $password): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user) {
            return ['error' => "No account found for email: $email"];
        }

        if (!password_verify($password, $user['password'])) {
            return ['error' => 'Incorrect password for this account'];
        }

        return ['user' => $user];
    }

    /**
     * Info Disclosure: Stack trace in production
     */
    public function processRequest(array $data): void
    {
        try {
            $this->doSomethingRisky($data);
        } catch (\Exception $e) {
            echo "Error: " . $e->getMessage() . "\n" . $e->getTraceAsString();
        }
    }

    private function doSomethingRisky(array $data): void
    {
        throw new \RuntimeException('Database connection failed: host=db.internal password=secret123');
    }

    // =========================================================================
    // Cryptographic Issues (Context Required)
    // =========================================================================

    /**
     * Crypto: ECB mode for sensitive data
     */
    public function encryptSensitiveData(string $data): string
    {
        $key = 'secret_key_12345';
        return openssl_encrypt($data, 'AES-128-ECB', $key); // ECB mode is insecure
    }

    /**
     * Crypto: Predictable IV
     */
    public function encryptWithPredictableIV(string $data): string
    {
        $key = 'secret_key_12345';
        $iv = str_repeat("\0", 16); // Null IV is predictable
        return openssl_encrypt($data, 'AES-128-CBC', $key, 0, $iv);
    }

    /**
     * Crypto: Key derived from password without proper KDF
     */
    public function deriveKey(string $password): string
    {
        return hash('sha256', $password); // Should use PBKDF2, bcrypt, or Argon2
    }
}

class Account
{
    public int $id;
    public string $name;
    public string $email;
    public float $balance = 0;
    public float $credit_limit = 0;
    public string $role = 'user';

    public function save(): void
    {
        // Save to database
    }
}
