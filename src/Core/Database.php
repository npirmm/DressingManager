<?php
// src/Core/Database.php

namespace App\Core; // Using a namespace is good practice

use PDO;
use PDOException;

/**
 * Database Connection Handler using PDO.
 * Implements a Singleton pattern to ensure only one connection instance.
 */
class Database {
    private static ?PDO $instance = null; // Stores the single instance (nullable)
    private string $dsn;
    private string $username;
    private string $password;
    private array $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Throw exceptions on errors
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Fetch results as associative arrays
        PDO::ATTR_EMULATE_PREPARES   => false, // Use native prepared statements
    ];

    /**
     * Private constructor to prevent direct instantiation.
     */
    private function __construct() {
        // Load configuration from the global scope (defined in config/database.php)
        // In a more advanced setup, configuration would be injected or loaded differently.
        $this->dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_DATABASE . ";charset=" . DB_CHARSET;
        $this->username = DB_USERNAME;
        $this->password = DB_PASSWORD;

        try {
            self::$instance = new PDO($this->dsn, $this->username, $this->password, $this->options);
        } catch (PDOException $e) {
            // In a real app, log this error securely and show a generic error message
            // Never expose detailed connection errors to the public
            error_log("Database Connection Error: " . $e->getMessage()); // Log error
            die("Database connection failed. Please check configuration or contact support."); // Halt execution
        }
    }

    /**
     * Get the singleton PDO database connection instance.
     *
     * @return PDO The PDO database connection instance.
     */
    public static function getInstance(): PDO {
        if (self::$instance === null) {
            new self(); // Call private constructor to create instance if it doesn't exist
        }
        return self::$instance;
    }

    /**
     * Prevent cloning of the instance.
     */
    private function __clone() {}

    /**
     * Prevent unserialization of the instance.
     */
    public function __wakeup() {
        throw new \Exception("Cannot unserialize a singleton.");
    }
}