<?php
// public/index.php

/**
 * Dressing Manager - Front Controller
 */

// Start the session (Important: Must be called before any output)
if (session_status() == PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0, // Expires when browser closes
        'path' => '/',
        'domain' => '', // Current domain
        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', // Only over HTTPS
        'httponly' => true, // Prevent JS access
        'samesite' => 'Lax' // CSRF mitigation
    ]);
    // Use session name from config if defined, otherwise default
    session_name(defined('SESSION_NAME') ? SESSION_NAME : 'PHPSESSID');
    session_start();
}

// --- Configuration Loading ---
require_once __DIR__ . '/../config/app.php';
require_once __DIR__ . '/../config/database.php';

// --- Autoloading (Basic PSR-4 Simulation) ---
spl_autoload_register(function ($class) {
    // Project-specific namespace prefix
    $prefix = 'App\\';
    // Base directory for the namespace prefix
    $base_dir = __DIR__ . '/../src/';
    // Does the class use the namespace prefix?
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        // No, move to the next registered autoloader
        return;
    }
    // Get the relative class name
    $relative_class = substr($class, $len);
    // Replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    // If the file exists, require it
    if (file_exists($file)) {
        require $file;
    } else {
         error_log("Autoloader failed to load class: " . $class . " (tried file: " . $file . ")");
    }
});

// --- Use Statements (Declare classes we'll use) ---
use App\Core\Database;
use App\Models\User;
use App\Models\RememberToken; 
use App\Controllers\AuthController;
use App\Controllers\UserController; // Added for profile page
use App\Utils\Auth;         // Added for checking login status
use App\Utils\Security;     // Added for CSRF token in logout form on home page
use DateTime;             // <-- Make sure this is included
use DateInterval;    

// --- Database Connection ---
try {
    $pdo = Database::getInstance(); // Ensure connection is attempted & ready
} catch (\PDOException $e) {
    // Database class handles logging and basic error message.
    // No need to display header/footer if DB is down.
    exit; // Stop script execution
} catch (\Exception $e) {
     // Catch other potential exceptions from Database class
     error_log("Error initializing Database: " . $e->getMessage());
     echo "A critical application error occurred. Please try again later.";
     exit;
}


// --- Simple Routing Logic ---
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Handle cases where the app is in a subfolder
$appBasePath = rtrim(parse_url(APP_URL, PHP_URL_PATH) ?? '', '/');
$route = '/';
if (!empty($appBasePath) && strpos($requestUri, $appBasePath) === 0) {
    $route = substr($requestUri, strlen($appBasePath));
} else {
    $route = $requestUri;
}
// Ensure route starts with / and handle empty route
$route = '/' . ltrim($route, '/');

$requestMethod = $_SERVER['REQUEST_METHOD'];

// --- Instantiate Controllers ---
$userModel = new User(); // Needed to check user count
$authController = new AuthController();
$userController = new UserController(); // For profile route

// --- Initial Setup Check ---
// This check runs before standard routing if no users exist
$userCount = $userModel->countUsers();

if ($userCount === 0) {
    // Only allow access to the setup routes if no users exist
    if ($route === '/setup' && $requestMethod === 'GET') {
        $authController->showSetupForm();
        exit;
    } elseif ($route === '/setup' && $requestMethod === 'POST') {
        $authController->handleSetup();
        exit;
    } else {
        // Redirect any other request to the setup page (GET)
        // Avoid infinite redirect loop if setup itself fails critically
         if ($route !== '/setup') {
             header("Location: " . APP_URL . '/setup');
             exit;
         } else {
              // If we are already on /setup GET but user count is 0, let showSetupForm handle it
              // This case might occur if redirection happens before controller instantiation somehow
              $authController->showSetupForm();
              exit;
         }
    }
} elseif ($userCount === -1) {
    // Handle database error during user count
    // Render a simple error page without full layout
    http_response_code(500);
    echo "<h1>Application Error</h1><p>Could not verify application status due to a database issue. Please try again later.</p>";
    exit;
}

// ********************************************************************
// --- Remember Me Cookie Check (Add this block BEFORE standard routing) ---
// ********************************************************************
if (!Auth::isLoggedIn() && isset($_COOKIE['remember_me'])) {
    error_log("Remember me cookie found, attempting auto-login."); // Debug logging
    list($selector, $validator) = explode(':', $_COOKIE['remember_me'], 2);

    if ($selector && $validator) {
        $tokenModel = new RememberToken(); // Instantiate locally or ensure it's available
        $userModel = new User(); // Ensure UserModel is available

        $tokenData = $tokenModel->findBySelector($selector);

        if ($tokenData && password_verify($validator, $tokenData['hashed_validator'])) {
            // Token is valid! Log the user in.
            error_log("Remember me token VALID for selector: " . $selector); // Debug logging

            $user = $userModel->findUserById($tokenData['user_id']); // Need findUserById method in User model

            if ($user && empty($user['deleted_at'])) { // Check if user exists and is active
                 // Regenerate session ID
                 session_regenerate_id(true);
                 // Regenerate CSRF token
                 Security::generateCsrfToken('csrf_token');

                 // Store user data in session (similar to handleLogin)
                 $_SESSION['user_id'] = $user['id'];
                 $_SESSION['user_name'] = $user['name'];
                 $_SESSION['user_email'] = $user['email'];
                 $_SESSION['user_role_id'] = $user['role_id'];
                 $_SESSION['user_role_name'] = $user['role_name']; // Assuming findUserById returns role_name
                 $_SESSION['last_login'] = time();

                 // --- Security Enhancement: Token Rotation (Optional but Recommended) ---
                 // Generate a new validator, update DB, and reissue cookie
                 try {
                     $newValidator = bin2hex(random_bytes(32));
                     $newHashedValidator = password_hash($newValidator, PASSWORD_DEFAULT);
                     $expires = new DateTime($tokenData['expires_at']); // Use existing expiry

                     if ($tokenModel->updateValidator($selector, $newHashedValidator, $expires)) {
                         $newCookieValue = $selector . ':' . $newValidator;
                         setcookie('remember_me', $newCookieValue, [
                             'expires' => $expires->getTimestamp(), 'path' => '/', 'domain' => '',
                             'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
                             'httponly' => true, 'samesite' => 'Lax'
                         ]);
                         error_log("Remember me token ROTATED for selector: " . $selector); // Debug logging
                     } else {
                          error_log("Failed to UPDATE remember token validator during rotation for selector: " . $selector);
                          // If update fails, maybe delete the token for safety?
                          // $tokenModel->deleteBySelector($selector);
                          // setcookie('remember_me', '', ['expires' => time() - 3600, ...]); // Clear cookie
                     }
                 } catch (\Exception $e) {
                      error_log("Error rotating remember me token: " . $e->getMessage());
                 }
                 // --- End Token Rotation ---

                 // Redirect to the current page (or intended URL) to refresh state
                 // Avoids potential issues if routing continues directly after setting session
                  header("Location: " . $_SERVER['REQUEST_URI']); // Redirect to the same URL
                 exit;

            } else {
                 // User associated with token not found or is inactive
                 error_log("User (ID: {$tokenData['user_id']}) not found or inactive for valid remember token (Selector: $selector). Cleaning up.");
                 $tokenModel->deleteBySelector($selector);
                 setcookie('remember_me', '', ['expires' => time() - 3600, 'path' => '/', 'domain' => '', 'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', 'httponly' => true, 'samesite' => 'Lax']);
                 unset($_COOKIE['remember_me']);
            }

        } else {
             // Invalid token (not found, expired, or validator mismatch)
             error_log("Remember me token INVALID or expired for selector: " . $selector . ". Clearing cookie."); // Debug logging
             $tokenModel->deleteBySelector($selector); // Delete from DB if found but invalid
             setcookie('remember_me', '', ['expires' => time() - 3600, 'path' => '/', 'domain' => '', 'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', 'httponly' => true, 'samesite' => 'Lax']);
             unset($_COOKIE['remember_me']);
        }
    } else {
        // Cookie format is wrong, clear it
         error_log("Remember me cookie format invalid. Clearing cookie."); // Debug logging
         setcookie('remember_me', '', ['expires' => time() - 3600, 'path' => '/', 'domain' => '', 'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', 'httponly' => true, 'samesite' => 'Lax']);
         unset($_COOKIE['remember_me']);
    }
}
// ********************************************************************
// --- End Remember Me Cookie Check ---
// ********************************************************************


// --- Standard Routing (if users exist) ---
switch ($route) {
    case '/':
        if ($requestMethod === 'GET') {
            if (Auth::isLoggedIn()) {
                // User is logged in - Show simple welcome/dashboard placeholder
                // The main navigation and user info are in the header layout
                require __DIR__ . '/../src/Views/layouts/header.php';
                echo '<div class="container mt-3">'; // Use mt-3 since header adds padding-top

                // Display success message from session (e.g., after login)
                 if (isset($_SESSION['success_message'])) {
                    echo '<div class="alert alert-success alert-dismissible fade show" role="alert">'
                         . htmlspecialchars($_SESSION['success_message'])
                         . '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>';
                    unset($_SESSION['success_message']);
                 }
                // Display error message from session (e.g., failed logout CSRF)
                 if (isset($_SESSION['error_message'])) {
                     echo '<div class="alert alert-danger alert-dismissible fade show" role="alert">'
                         . htmlspecialchars($_SESSION['error_message'])
                         . '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>';
                     unset($_SESSION['error_message']);
                 }


                echo '<h2>Welcome to your Dressing Manager Dashboard!</h2>';
                echo '<p>This is the main application area (content to be added).</p>';
                echo '<hr>';
                echo '<p>Logged in as: ' . htmlspecialchars(Auth::role()) . '</p>';

                // Example: Show logout form directly on this page as well (redundant with header, but for clarity)
                /*
                echo '<h4>Logout:</h4>';
                echo '<form action="' . APP_URL . '/logout" method="POST" style="display: inline;">';
                echo Security::csrfInput('csrf_token');
                echo '<button type="submit" class="btn btn-warning">Logout Here Too</button>';
                echo '</form>';
                */

                echo '</div>'; // Close container
                require __DIR__ . '/../src/Views/layouts/footer.php';
            } else {
                // User not logged in, redirect to login page
                header("Location: " . APP_URL . '/login');
                exit;
            }
        } else {
            // Handle other methods (POST, PUT, etc.) to '/' if needed, otherwise 405
            http_response_code(405);
            echo "405 Method Not Allowed on /";
        }
        break;

    case '/login':
        if ($requestMethod === 'GET') {
            $authController->showLoginForm();
        } elseif ($requestMethod === 'POST') {
            $authController->handleLogin();
        } else {
            http_response_code(405); echo "405 Method Not Allowed";
        }
        break;

    case '/logout': // Logout must be POST due to CSRF
        if ($requestMethod === 'POST') {
            $authController->logout(); // Handles CSRF validation inside
        } else {
            http_response_code(405); echo "405 Method Not Allowed (Logout requires POST)";
        }
        break; // exit() is called within logout()

    case '/profile': // New route for user profile
        if ($requestMethod === 'GET') {
            // Auth::checkAuthentication(); // Authentication check is now inside the controller method
            $userController->showProfile();
        }
        // Add POST handler later for profile updates
        // elseif ($requestMethod === 'POST') { $userController->handleProfileUpdate(); }
        else {
            http_response_code(405); echo "405 Method Not Allowed";
        }
        break;

    case '/setup': // This route should only be accessible when userCount is 0 (handled above)
        // If we reach here, it means users exist, so setup is forbidden.
        $_SESSION['error_message'] = "Setup is already complete.";
        header("Location: " . APP_URL . '/login');
        exit;

    // --- Add more application routes here as needed ---
    // Example:
    // case '/items':
    //     if ($requestMethod === 'GET') { $itemController->listItems(); }
    //     break;
    // case '/item/create':
    //      if ($requestMethod === 'GET') { $itemController->showCreateForm(); }
    //      elseif ($requestMethod === 'POST') { $itemController->handleCreateItem(); }
    //      break;

    default:
        // Handle 404 Not Found for any other route
        http_response_code(404);
        // Load a simple 404 view using the standard layout
        require __DIR__ . '/../src/Views/layouts/header.php';
        echo '<div class="container mt-5 text-center">';
        echo '<h1>404 - Page Not Found</h1>';
        echo '<p>Sorry, the page you are looking for does not exist.</p>';
        echo '<a href="' . APP_URL . '/" class="btn btn-primary">Go to Homepage</a>';
        echo '</div>';
        require __DIR__ . '/../src/Views/layouts/footer.php';
        break;
}

// --- End of Script ---