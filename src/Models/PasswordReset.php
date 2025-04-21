<?php
// src/Models/PasswordReset.php

namespace App\Models;

use App\Core\Database;
use PDO;
use PDOException;
use DateTime;
use DateInterval;

class PasswordReset {
    private PDO $db;
    private string $tableName = 'password_resets';

    public function __construct() {
        $this->db = Database::getInstance();
    }

    /**
     * Create a new password reset token for an email address.
     * Deletes any existing tokens for the same email first.
     *
     * @param string $email The user's email address.
     * @param string $token The secure reset token.
     * @return bool True on success, false on failure.
     */
    public function createToken(string $email, string $token): bool {
        // Delete existing tokens for this email
        $this->deleteTokensForEmail($email);

        // Store the raw token (easier lookup). Hashing adds complexity.
        $sql = "INSERT INTO {$this->tableName} (email, token, created_at) VALUES (:email, :token, NOW())";

        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':token', $token);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error creating password reset token for $email: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Find a password reset record by token.
     *
     * @param string $token The token to search for.
     * @return array|false Token data array or false if not found.
     */
    public function findByToken(string $token): array|false {
        $sql = "SELECT * FROM {$this->tableName} WHERE token = :token";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':token', $token);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result ?: false;
        } catch (PDOException $e) {
            error_log("Error finding password reset token: " . $e->getMessage());
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
            error_log("Error deleting password reset token: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all password reset tokens for a specific email address.
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
            error_log("Error deleting password reset tokens for email $email: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all expired tokens based on the created_at time.
     *
     * @param int $validityMinutes How long tokens are considered valid (e.g., 60).
     * @return int|false Number of deleted rows or false on failure.
     */
	public function deleteExpiredTokens(int $validityMinutes = 60): int|false {
		// Calculate expiry time based on UTC now
		$expiryTime = (new DateTime('now', new \DateTimeZone('UTC')))->sub(new DateInterval("PT{$validityMinutes}M"))->format('Y-m-d H:i:s');
		$sql = "DELETE FROM {$this->tableName} WHERE created_at < :expiry_time";
		try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':expiry_time', $expiryTime);
            $stmt->execute();
            return $stmt->rowCount();
        } catch (PDOException $e) {
            error_log("Error deleting expired password reset tokens: " . $e->getMessage());
            return false;
        }
    }
}