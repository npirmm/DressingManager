<?php
// config/database.php

/**
 * Database configuration settings.
 *
 * IMPORTANT SECURITY NOTE:
 * Never commit real database credentials directly into version control.
 * Use environment variables (e.g., via $_ENV, getenv(), or libraries like DotEnv)
 * or secure configuration management practices for production environments.
 * For local development, this direct configuration is acceptable but be mindful.
 */

define('DB_HOST', '127.0.0.1');      // Or your MariaDB host (e.g., localhost)
define('DB_PORT', '3306');          // Default MariaDB port
define('DB_DATABASE', 'dressing_manager_db'); // Your database name
define('DB_USERNAME', 'YOUR_DB_USER'); // Your database username
define('DB_PASSWORD', 'YOUR_DB_PASSWORD'); // Your database password
define('DB_CHARSET', 'utf8mb4');