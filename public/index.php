<?php
// public/index.php

/**
 * Dressing Manager - Front Controller
 */

// Start the session (Make sure session settings are appropriate)
if (session_status() == PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'domain' => '',
        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true, 'samesite' => 'Lax'
    ]);
    session_name(defined('SESSION_NAME') ? SESSION_NAME : 'PHPSESSID');
    session_start();
}

// --- Configuration Loading ---
require_once __DIR__ . '/../config/app.php';
require_once __DIR__ . '/../config/database.php';

// --- Autoloading (Basic PSR-4 simulation) ---
spl_autoload_register(function ($class) {
    $prefix = 'App\\';
    $base_dir = __DIR__ . '/../src/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) { return; }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) { require $file; }
});

// --- Use Statements ---
use App\Core\Database;
use App\Models\User;
use App\Controllers\AuthController;

// --- Database Connection ---
try {
    $pdo = Database::getInstance(); // Ensure connection is attempted
} catch (\Exception $e) {
    exit; // Stop script execution if DB connection failed critically
}

// --- Basic Routing ---
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$appBasePath = parse_url(APP_URL, PHP_URL_PATH) ?? ''; // Get base path from APP_URL if nested
$route = '/';
if ($appBasePath && strpos($requestUri, $appBasePath) === 0) {
    $route = substr($requestUri, strlen($appBasePath));
} else {
    $route = $requestUri;
}
if (empty($route)) {
    $route = '/'; // Default route
}

$requestMethod = $_SERVER['REQUEST_METHOD'];

// --- Instantiate necessary classes ---
$userModel = new User();
$authController = new AuthController();

// --- Route Definitions ---
$userCount = $userModel->countUsers(); // Check if initial setup is needed

// Special case: Force setup if no users exist, regardless of requested route (except for the setup POST itself)
if ($userCount === 0 && $route !== '/setup') {
    // If GET request, show setup form. If POST, let it proceed to handleSetup below.
    if ($requestMethod === 'GET') {
        $authController->showSetupForm();
        exit;
    }
}
if ($userCount === 0 && $route === '/setup' && $requestMethod === 'POST') {
    $authController->handleSetup();
    exit;
}

// --- Normal Routing (if users exist or setup is being handled) ---
if ($userCount > 0) {
    switch ($route) {
        case '/':
        case '/login':
            if ($requestMethod === 'GET') {
                 // If logged in, redirect to dashboard (implement later)
                 if (isset($_SESSION['user_id'])) {
                     // Temp: Just show a welcome message
                     require __DIR__ . '/../src/Views/layouts/header.php';
                     echo '<div class="container mt-5">';
                     echo '<h1>' . APP_NAME . '</h1>';
                      if (isset($_SESSION['success_message'])) {
                         echo '<div class="alert alert-success">' . htmlspecialchars($_SESSION['success_message']) . '</div>';
                         unset($_SESSION['success_message']);
                     }
                     echo '<p>You are logged in as ' . htmlspecialchars($_SESSION['user_name']) . ' (' . htmlspecialchars($_SESSION['user_role_name']) . ').</p>';
                     // Add logout link later
                     echo '<a href="' . APP_URL . '/logout" class="btn btn-secondary">Logout</a>'; // Add logout route later
                     echo '</div>';
                     require __DIR__ . '/../src/Views/layouts/footer.php';

                 } else {
                    $authController->showLoginForm();
                 }
            } elseif ($requestMethod === 'POST' && ($route === '/login' || $route === '/')) { // Allow login POST to / or /login
                 // Prevent logged-in users from accessing login POST
                 if (isset($_SESSION['user_id'])) {
                    header("Location: " . APP_URL . "/"); // Redirect home if already logged in
                    exit;
                 }
                $authController->handleLogin();
            } else {
                // Handle 405 Method Not Allowed
                http_response_code(405);
                echo "405 Method Not Allowed";
            }
            break;

        case '/setup': // Should not be accessible if users exist
             header("Location: " . APP_URL . "/login"); // Redirect to login
             exit;

        case '/logout': // Placeholder for logout
            if ($requestMethod === 'GET') {
                // Clear session data
                $_SESSION = array(); // Clear all session variables
                if (ini_get("session.use_cookies")) { // Delete the session cookie
                    $params = session_get_cookie_params();
                    setcookie(session_name(), '', time() - 42000,
                        $params["path"], $params["domain"],
                        $params["secure"], $params["httponly"]
                    );
                }
                session_destroy(); // Destroy the session
                header("Location: " . APP_URL . "/login"); // Redirect to login page
                exit;
            } else {
                http_response_code(405); echo "405 Method Not Allowed";
            }
            break;

        // Add more routes here later (e.g., /dashboard, /profile, /items, ...)

        default:
            // Handle 404 Not Found
            http_response_code(404);
            require __DIR__ . '/../src/Views/layouts/header.php';
            echo '<div class="container mt-5"><h1>404 - Page Not Found</h1><p>The requested page could not be found.</p><a href="'.APP_URL.'/">Go Home</a></div>';
            require __DIR__ . '/../src/Views/layouts/footer.php';
            break;
    }
} elseif ($userCount === -1) {
     // Handle database error during user count
     require __DIR__ . '/../src/Views/layouts/header.php';
     echo '<div class="container mt-5 alert alert-danger">Error connecting to the user database. Cannot proceed.</div>';
     require __DIR__ . '/../src/Views/layouts/footer.php';
}


// --- End of Script ---