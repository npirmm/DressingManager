<?php
// src/Models/User.php

namespace App\Models;

use App\Core\Database; // Use the Database connection class
use PDO;
use PDOException;

/**
 * User Model
 * Handles database operations related to the users table.
 */
class User {
    private PDO $db;

    public function __construct() {
        // Get the database connection instance
        $this->db = Database::getInstance();
    }

    /**
     * Count the total number of users in the database.
     * Used to check if the initial setup is needed.
     *
     * @return int Number of users.
     */
    public function countUsers(): int {
        try {
            $stmt = $this->db->query("SELECT COUNT(*) FROM users");
            return (int) $stmt->fetchColumn();
        } catch (PDOException $e) {
            error_log("Error counting users: " . $e->getMessage());
            // In a real app, handle this more gracefully
            return -1; // Indicate an error
        }
    }

    /**
     * Create a new user in the database.
     * Handles password hashing.
     *
     * @param string $name User's name.
     * @param string $email User's email (should be validated beforehand).
     * @param string $password Plain text password (will be hashed).
     * @param int $roleId The ID of the role for the user.
     * @param bool $isVerified Set email as verified (useful for initial admin).
     * @return int|false The ID of the newly created user, or false on failure.
     */
    public function createUser(string $name, string $email, string $password, int $roleId, bool $isVerified = false): int|false {
        // Hash the password securely
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        if ($hashedPassword === false) {
            error_log("Password hashing failed.");
            return false;
        }

        // Set email verification timestamp if needed
        $verifiedAt = $isVerified ? date('Y-m-d H:i:s') : null;

        $sql = "INSERT INTO users (name, email, password, role_id, email_verified_at, created_at, updated_at)
                VALUES (:name, :email, :password, :role_id, :verified_at, NOW(), NOW())";

        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $stmt->bindParam(':verified_at', $verifiedAt);

            if ($stmt->execute()) {
                return (int) $this->db->lastInsertId();
            } else {
                error_log("Failed to execute user creation statement.");
                return false;
            }
        } catch (PDOException $e) {
            // Check for duplicate email error (SQLSTATE[23000] Integrity constraint violation: 1062 Duplicate entry)
            if ($e->getCode() == 23000) {
                error_log("Attempted to create user with duplicate email: " . $email);
            } else {
                error_log("Error creating user: " . $e->getMessage());
            }
            return false;
        }
    }

    /**
     * Find a user by their email address.
     *
     * @param string $email The email to search for.
     * @return array|false User data as an associative array, or false if not found.
     */
    public function findUserByEmail(string $email): array|false {
        $sql = "SELECT u.*, r.name as role_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.email = :email";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            return $user ?: false; // Return the user array or false if no row found
        } catch (PDOException $e) {
            error_log("Error finding user by email: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Find a user by their ID.
     * Includes the role name.
     *
     * @param int $id The user ID to search for.
     * @return array|false User data as an associative array, or false if not found.
     */
    public function findUserById(int $id): array|false {
        $sql = "SELECT u.*, r.name as role_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = :id";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':id', $id, PDO::PARAM_INT);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            return $user ?: false; // Return the user array or false if no row found
        } catch (PDOException $e) {
            error_log("Error finding user by ID ($id): " . $e->getMessage());
            return false;
        }
    }

    /**
     * Mark a user's email address as verified by setting the timestamp.
     *
     * @param int $userId The ID of the user to update.
     * @return bool True on success, false on failure.
     */
    public function markEmailAsVerified(int $userId): bool {
        // Check if already verified to avoid unnecessary updates
        // $user = $this->findUserById($userId);
        // if ($user && $user['email_verified_at'] !== null) {
        //     return true; // Already verified
        // }

        $sql = "UPDATE users SET email_verified_at = NOW() WHERE id = :id AND email_verified_at IS NULL";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
            $stmt->execute();
            // Check if any row was actually updated (returns true even if 0 rows affected if query runs)
            return $stmt->rowCount() > 0;
        } catch (PDOException $e) {
            error_log("Error marking email as verified for user ID $userId: " . $e->getMessage());
            return false;
        }
    }
    // --- We will add more methods later ---
    // (e.g., findById, updateProfile, updatePassword, enable2FA, setRememberToken, etc.)
}