<?php
// public/index.php

/**
 * Dressing Manager - Front Controller
 */

// Start the session
// Note: Session settings could be further configured in app.php if needed
if (session_status() == PHP_SESSION_NONE) {
    // Configure session cookie parameters for security
    session_set_cookie_params([
        'lifetime' => 0, // 0 = until browser closes
        'path' => '/',
        'domain' => '', // Leave empty for current domain
        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', // Send only over HTTPS
        'httponly' => true, // Prevent JavaScript access
        'samesite' => 'Lax' // CSRF protection measure
    ]);
    session_name(defined('SESSION_NAME') ? SESSION_NAME : 'PHPSESSID'); // Use custom session name from config
    session_start();
}


// --- Configuration Loading ---
// Use absolute paths for reliability, __DIR__ gives the directory of the current file (public)
require_once __DIR__ . '/../config/app.php';
require_once __DIR__ . '/../config/database.php';

// --- Autoloading (Basic Example) ---
// For a real app, use Composer's autoloader (PSR-4 standard)
// This basic example requires manual includes or a simple autoloader function
spl_autoload_register(function ($class) {
    // Basic autoloader assuming App\Namespace\ClassName maps to src/Namespace/ClassName.php
    $prefix = 'App\\';
    $base_dir = __DIR__ . '/../src/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        // No, move to the next registered autoloader
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    // If the file exists, require it
    if (file_exists($file)) {
        require $file;
    }
});


// --- Database Connection ---
// We can now use the Database class thanks to the autoloader
use App\Core\Database;

try {
    $pdo = Database::getInstance();
    // Database connection is ready ($pdo can be passed to Models/Controllers)
    // echo "Database connection successful!"; // For testing only
} catch (\Exception $e) {
    // Error already handled within Database class constructor (logged, generic message shown)
    exit; // Stop script execution if DB connection failed critically
}


// --- Routing (Very Basic Placeholder) ---
// This section will grow significantly to handle different URLs (/login, /profile, /items, etc.)
// We will replace this with a more robust Router class later.

echo "<h1>Welcome to " . APP_NAME . "</h1>";
echo "<p>Basic setup complete. Database connected.</p>";

// TODO: Check if initial admin user exists. If not, redirect to setup page.
// TODO: Implement actual routing based on requested URL (e.g., $_SERVER['REQUEST_URI'])
// TODO: Instantiate controllers and call methods based on the route.

// --- End of Script ---