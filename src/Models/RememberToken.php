<?php
// src/Models/RememberToken.php

namespace App\Models;

use App\Core\Database;
use PDO;
use PDOException;
use DateTime; // Use DateTime for easier date manipulation

class RememberToken {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    /**
     * Find a token record by its selector.
     * Only returns the token if it has not expired.
     *
     * @param string $selector The public selector string.
     * @return array|false Token data array or false if not found or expired.
     */
    public function findBySelector(string $selector): array|false {
        $sql = "SELECT * FROM remember_tokens WHERE selector = :selector AND expires_at > NOW()";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':selector', $selector);
            $stmt->execute();
            $token = $stmt->fetch(PDO::FETCH_ASSOC);
            return $token ?: false;
        } catch (PDOException $e) {
            error_log("Error finding token by selector: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Insert a new remember token into the database.
     *
     * @param int $userId The user ID.
     * @param string $selector The public selector.
     * @param string $hashedValidator The hashed validator.
     * @param DateTime $expiresAt The expiration DateTime object.
     * @return bool True on success, false on failure.
     */
    public function insertToken(int $userId, string $selector, string $hashedValidator, DateTime $expiresAt): bool {
        $sql = "INSERT INTO remember_tokens (user_id, selector, hashed_validator, expires_at, created_at)
                VALUES (:user_id, :selector, :hashed_validator, :expires_at, NOW())";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':selector', $selector);
            $stmt->bindParam(':hashed_validator', $hashedValidator);
            // Format DateTime object to MySQL TIMESTAMP format
            $formattedExpires = $expiresAt->format('Y-m-d H:i:s');
            $stmt->bindParam(':expires_at', $formattedExpires);

            return $stmt->execute();
        } catch (PDOException $e) {
            // Check for duplicate selector error (should be rare with random selectors)
            if ($e->getCode() == 23000) {
                 error_log("Attempted to insert remember token with duplicate selector: " . $selector);
             } else {
                error_log("Error inserting remember token: " . $e->getMessage());
             }
            return false;
        }
    }

    /**
     * Delete a token by its selector.
     *
     * @param string $selector The selector of the token to delete.
     * @return bool True on success, false on failure.
     */
    public function deleteBySelector(string $selector): bool {
        $sql = "DELETE FROM remember_tokens WHERE selector = :selector";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':selector', $selector);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting token by selector: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all remember tokens associated with a specific user ID.
     * Useful for "logout everywhere" or when user changes password.
     *
     * @param int $userId The user ID.
     * @return bool True on success, false on failure.
     */
    public function deleteByUserId(int $userId): bool {
        $sql = "DELETE FROM remember_tokens WHERE user_id = :user_id";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting tokens by user ID: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete all expired tokens from the table.
     * This can be run periodically (e.g., via a cron job or triggered occasionally).
     *
     * @return int|false The number of deleted rows or false on failure.
     */
    public function deleteExpiredTokens(): int|false {
        $sql = "DELETE FROM remember_tokens WHERE expires_at <= NOW()";
        try {
            $stmt = $this->db->query($sql); // Simple query as no parameters needed
            return $stmt->rowCount(); // Returns the number of affected rows
        } catch (PDOException $e) {
            error_log("Error deleting expired tokens: " . $e->getMessage());
            return false;
        }
    }

     /**
     * Update the validator for a given selector.
     * Used for token rotation security enhancement.
     *
     * @param string $selector The selector to update.
     * @param string $newHashedValidator The new hashed validator.
     * @param DateTime $newExpiresAt The potentially updated expiration date.
     * @return bool True on success, false otherwise.
     */
     public function updateValidator(string $selector, string $newHashedValidator, DateTime $newExpiresAt): bool {
         $sql = "UPDATE remember_tokens
                 SET hashed_validator = :hashed_validator, expires_at = :expires_at
                 WHERE selector = :selector";
         try {
             $stmt = $this->db->prepare($sql);
             $stmt->bindParam(':hashed_validator', $newHashedValidator);
             $formattedExpires = $newExpiresAt->format('Y-m-d H:i:s');
             $stmt->bindParam(':expires_at', $formattedExpires);
             $stmt->bindParam(':selector', $selector);
             return $stmt->execute();
         } catch (PDOException $e) {
             error_log("Error updating token validator: " . $e->getMessage());
             return false;
         }
     }

}