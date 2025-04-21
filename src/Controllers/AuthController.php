<?php
// src/Controllers/AuthController.php

namespace App\Controllers;

use App\Models\User;
use App\Utils\Security; // <-- Pour la protection CSRF
use App\Utils\Auth;     // <-- Pour vérifier l'état de connexion si besoin

/**
 * AuthController
 * Handles user authentication related actions: setup, login, logout.
 */
class AuthController {
    private User $userModel;

    public function __construct() {
        $this->userModel = new User();
    }

    /**
     * Show the initial setup form to create the first Superadmin.
     * This should only be accessible if no users exist in the database.
     */
    public function showSetupForm(): void {
        // Basic check: If users already exist, redirect to login
        // This check also happens in index.php before routing here
        if ($this->userModel->countUsers() > 0) {
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // Load the view for the setup form
        $this->loadView('auth/setup', ['pageTitle' => 'Initial Admin Setup']);
    }

    /**
     * Handle the submission of the initial setup form.
     */
    public function handleSetup(): void {
        // --- CSRF Token Validation ---
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken)) {
            error_log("CSRF token validation failed for setup form.");
            $_SESSION['error_message'] = "Invalid request. Please try submitting the form again.";
            $this->redirect(APP_URL . '/setup'); // Redirect back to the form
            exit;
        }
        // --- End CSRF Validation ---

        // Double check: Only proceed if no users exist
        if ($this->userModel->countUsers() > 0) {
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // --- Basic Input Validation ---
        $name = $_POST['name'] ?? '';
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $passwordConfirm = $_POST['password_confirmation'] ?? '';
        $errors = [];

        if (empty($name)) $errors[] = "Name is required.";
        if (empty($email)) $errors[] = "Email is required.";
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email format.";
        if (empty($password)) $errors[] = "Password is required.";
        elseif (strlen($password) < 8) $errors[] = "Password must be at least 8 characters long.";
        if ($password !== $passwordConfirm) $errors[] = "Passwords do not match.";

        // --- Process Registration ---
        if (empty($errors)) {
            // Attempt to create the user (Role ID 1 is Superadmin), email verified
            $userId = $this->userModel->createUser($name, $email, $password, 1, true);

            if ($userId !== false) {
                // Optional: Regenerate CSRF token after successful action
                // Security::generateCsrfToken('csrf_token'); // Refresh token
                $_SESSION['success_message'] = "Superadmin account created successfully! You can now log in.";
                $this->redirect(APP_URL . '/login');
                exit;
            } else {
                 // Check for duplicate email error more reliably
                 if ($this->userModel->findUserByEmail($email)) {
                      $errors[] = "An account with this email already exists. (This check might be redundant if DB constraints are solid)";
                 } else {
                      $errors[] = "An error occurred during registration. Please check logs or try again.";
                 }
            }
        }

        // --- Show Form Again with Errors ---
        $this->loadView('auth/setup', [
            'pageTitle' => 'Initial Admin Setup',
            'errors' => $errors,
            'old_name' => $name,
            'old_email' => $email
            // CSRF token is automatically handled by Security::csrfInput() in the view
        ]);
    }


    /**
     * Show the login form.
     */
    public function showLoginForm(): void {
        // If already logged in, redirect to home/dashboard
        if (Auth::isLoggedIn()) {
            $this->redirect(APP_URL . '/');
            exit;
        }

        // Check for messages from redirects (e.g., after setup, logout)
        $successMessage = $_SESSION['success_message'] ?? null;
        $errorMessage = $_SESSION['error_message'] ?? null;
        $loggedOut = isset($_GET['logged_out']) && $_GET['logged_out'] === '1'; // Check logout query param

        // Clear messages after retrieving them
        unset($_SESSION['success_message'], $_SESSION['error_message']);

        $this->loadView('auth/login', [
            'pageTitle' => 'Login',
            'successMessage' => $loggedOut ? 'You have been logged out successfully.' : $successMessage,
            'errorMessage' => $errorMessage
        ]);
    }

    /**
     * Handle the login form submission.
     */
     public function handleLogin(): void {
         // If already logged in, prevent re-login attempt
         if (Auth::isLoggedIn()) {
             $this->redirect(APP_URL . '/');
             exit;
         }

        // --- CSRF Token Validation ---
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken)) {
            error_log("CSRF token validation failed for login form.");
            $_SESSION['error_message'] = "Invalid request. Please try submitting the form again.";
            $this->redirect(APP_URL . '/login');
            exit;
        }
        // --- End CSRF Validation ---

        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $errors = [];

        if (empty($email)) $errors[] = "Email is required.";
        if (empty($password)) $errors[] = "Password is required.";

        if (empty($errors)) {
            $user = $this->userModel->findUserByEmail($email);

            if ($user && password_verify($password, $user['password'])) {
                // Password is correct!

                // Check if email is verified
                if (empty($user['email_verified_at'])) {
                    $_SESSION['error_message'] = "Your email address is not verified. Please check your inbox or contact support.";
                    $this->redirect(APP_URL . '/login');
                    exit;
                }

                // --- Start Session ---
                session_regenerate_id(true); // Regenerate session ID for security
                Security::generateCsrfToken('csrf_token'); // Regenerate CSRF token for the new session state

                // Store user data in session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_role_id'] = $user['role_id'];
                $_SESSION['user_role_name'] = $user['role_name'];
                $_SESSION['last_login'] = time();

                // TODO: Implement 2FA check here if $user['two_factor_enabled'] is true
                // TODO: Implement Remember Me functionality here

                // Redirect to home/dashboard
                $_SESSION['success_message'] = "Welcome back, " . htmlspecialchars($user['name']) . "!";
                // TODO: Redirect to intended URL if stored?
                $this->redirect(APP_URL . '/');
                exit;

            } else {
                // Invalid email or password
                // Do not reveal which one was wrong
                $errors[] = "Invalid credentials provided.";
                $_SESSION['error_message'] = "Invalid credentials provided.";
            }
        } else {
             $_SESSION['error_message'] = implode(' ', $errors);
        }

        // --- Show Form Again with Errors ---
        // Redirect back to login form GET route to show errors via session message
        // This prevents issues with form resubmission on refresh
        $_SESSION['old_email'] = $email; // Store email to repopulate field
        $this->redirect(APP_URL . '/login');
        exit;
        /* Alternative (less ideal): Load view directly with errors
           $this->loadView('auth/login', [
               'pageTitle' => 'Login',
               'errors' => $errors, // Pass specific errors if needed by view logic
               'old_email' => $email,
               'errorMessage' => $_SESSION['error_message'] ?? implode(' ', $errors)
           ]);
        */
    }

    /**
     * Handle user logout. Validates CSRF token.
     */
    public function logout(): void {
        // --- CSRF Token Validation ---
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken, 'csrf_token')) {
            error_log("CSRF token validation failed for logout.");
            $_SESSION['error_message'] = "Invalid logout request.";
            // Redirect back to home or login? Home might be confusing if they intended to log out.
            $this->redirect(APP_URL . '/login');
            exit;
        }
        // --- End CSRF Validation ---

        // Clear session data
        $_SESSION = array();
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();

        // Redirect to login page with a query parameter indicator
        $this->redirect(APP_URL . '/login?logged_out=1');
        exit;
    }


    // --- Helper Methods ---

    /**
     * Helper function to load a view.
     * Includes header and footer layouts automatically.
     *
     * @param string $viewName The name of the view file (e.g., 'auth/login').
     * @param array $data Data to pass to the view (extracted into variables).
     */
    private function loadView(string $viewName, array $data = []): void {
        extract($data); // Make data available as variables ($pageTitle, $errors, etc.)
        $viewPath = __DIR__ . '/../Views/' . $viewName . '.php';

        if (file_exists($viewPath)) {
            $headerPath = __DIR__ . '/../Views/layouts/header.php';
            if (file_exists($headerPath)) { require $headerPath; }

            require $viewPath; // Include the main view content

            $footerPath = __DIR__ . '/../Views/layouts/footer.php';
            if (file_exists($footerPath)) { require $footerPath; }
        } else {
            error_log("View file not found: " . $viewPath);
            // Display a user-friendly error page in production
            echo "Error: Could not load the requested page content.";
        }
    }

     /**
      * Helper function for redirection.
      *
      * @param string $url The URL to redirect to.
      */
     private function redirect(string $url): void {
         header("Location: " . $url);
         exit; // Stop script execution after sending the redirect header
     }

} // End Class AuthController