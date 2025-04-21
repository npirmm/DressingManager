<?php
// src/Models/EmailVerification.php

namespace App\Models;

use App\Core\Database;
use PDO;
use PDOException;
use DateTime;
use DateInterval;

class EmailVerification {
    private PDO $db;
    private string $tableName = 'email_verifications';

    public function __construct() {
        $this->db = Database::getInstance();
    }

    /**
     * Create a new verification token for an email address.
     * Deletes any existing tokens for the same email first.
     *
     * @param string $email The email address to verify.
     * @param string $token The secure verification token.
     * @param int $expiresInMinutes How many minutes the token should be valid for (e.g., 60 for 1 hour).
     * @return bool True on success, false on failure.
     */
    public function createToken(string $email, string $token, int $expiresInMinutes = 60): bool {
        // Delete existing tokens for this email to prevent clutter/confusion
        $this->deleteTokensForEmail($email);

        $sql = "INSERT INTO {$this->tableName} (email, token, created_at)
                VALUES (:email, :token, NOW())"; // Use NOW() for created_at

        // Note: `expires_at` is not in the table definition provided earlier.
        // We will use `created_at` + interval for validation.
        // If you added an expires_at column, calculate and bind it here:
        // $expires = (new DateTime())->add(new DateInterval("PT{$expiresInMinutes}M"))->format('Y-m-d H:i:s');

        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':token', $token); // Store the raw token for simplicity (hashing adds complexity)
            // If storing hashed token: $hashedToken = password_hash($token, PASSWORD_DEFAULT); $stmt->bindParam(':token', $hashedToken);

            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error creating email verification token for $email: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Find a verification record by token.
     *
     * @param string $token The token to search for.
     * @return array|false Token data array or false if not found.
     */
    public function findByToken(string $token): array|false {
        // If storing hashed tokens, you can't search by raw token directly.
        // You'd need a separate 'selector' column like in remember_tokens.
        // Since we store the raw token (simpler for now):
        $sql = "SELECT * FROM {$this->tableName} WHERE token = :token";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result ?: false;
        } catch (PDOException $e) {
            error_log("Error finding email verification token: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete a token record by the token string.
     *
     * @param string $token The token to delete.
     * @return bool True on success or if token didn't exist, false on failure.
     */
    public function deleteToken(string $token): bool {
        $sql = "DELETE FROM {$this->tableName} WHERE token = :token";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting email verification token: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all verification tokens for a specific email address.
     *
     * @param string $email The email address.
     * @return bool True on success, false on failure.
     */
    public function deleteTokensForEmail(string $email): bool {
        $sql = "DELETE FROM {$this->tableName} WHERE email = :email";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':email', $email);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting tokens for email $email: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all expired tokens based on the created_at time.
     *
     * @param int $validityMinutes How long tokens are considered valid.
     * @return int|false Number of deleted rows or false on failure.
     */
    public function deleteExpiredTokens(int $validityMinutes = 60): int|false {
        $expiryTime = (new DateTime())->sub(new DateInterval("PT{$validityMinutes}M"))->format('Y-m-d H:i:s');
        $sql = "DELETE FROM {$this->tableName} WHERE created_at < :expiry_time";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':expiry_time', $expiryTime);
            $stmt->execute();
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Error deleting expired email verification tokens: " . $e->getMessage());
            return false;
        }
    }
}