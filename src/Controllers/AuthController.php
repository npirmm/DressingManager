<?php
// src/Controllers/AuthController.php

namespace App\Controllers;

use App\Models\User;
use App\Models\RememberToken; // <-- Add RememberToken model
use App\Models\EmailVerification; // <-- Add EmailVerification model
use App\Utils\Security;
use App\Utils\Auth;
use DateTime;              // <-- Add DateTime class
use DateInterval;          // <-- Add DateInterval for expiration

/**
 * AuthController
 * Handles user authentication related actions: setup, login, logout.
 */
class AuthController {
    private User $userModel;
    private RememberToken $tokenModel; // <-- Add property for token model
    private EmailVerification $verificationModel; // <-- Add property

    public function __construct() {
        $this->userModel = new User();
        $this->tokenModel = new RememberToken(); // <-- Instantiate token model
        $this->verificationModel = new EmailVerification(); // <-- Instantiate
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
         if (Auth::isLoggedIn()) { $this->redirect(APP_URL . '/'); exit; }

        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken)) {
            error_log("CSRF token validation failed for login form.");
            $_SESSION['error_message'] = "Invalid request. Please try submitting the form again.";
            $this->redirect(APP_URL . '/login');
            exit;
        }

        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']) && $_POST['remember'] === '1'; // <-- Check remember me
        $errors = [];

        if (empty($email)) $errors[] = "Email is required.";
        if (empty($password)) $errors[] = "Password is required.";

        if (empty($errors)) {
            $user = $this->userModel->findUserByEmail($email);

            if ($user && password_verify($password, $user['password'])) {
                 // Password is correct!

                 // Check if email is verified
                 if (empty($user['email_verified_at'])) {
                      error_log("Login attempt failed - Email not verified for: " . $email);
                     // Provide a more helpful message and potentially a resend link
                     $_SESSION['error_message'] = "Votre adresse e-mail n'est pas encore vérifiée. Veuillez cliquer sur le lien dans l'e-mail de vérification qui vous a été envoyé.";
                     // TODO: Add a link/button here or on login page: <a href="/resend-verification?email=...">Renvoyer l'email</a>
                     $this->redirect(APP_URL . '/login');
                     exit;
                 }

                 session_regenerate_id(true);
                 Security::generateCsrfToken('csrf_token');

                 $_SESSION['user_id'] = $user['id'];
                 $_SESSION['user_name'] = $user['name'];
                 $_SESSION['user_email'] = $user['email'];
                 $_SESSION['user_role_id'] = $user['role_id'];
                 $_SESSION['user_role_name'] = $user['role_name'];
                 $_SESSION['last_login'] = time();

                 // --- Handle Remember Me ---
                 if ($remember) {
                     $this->createRememberMeCookie($user['id']); // <-- Call helper method
                 } else {
                      // Ensure any previous remember me cookie is cleared if box not checked
                      $this->clearRememberMeCookie();
                      // Optionally clear server-side tokens for this user if desired on normal login
                      // $this->tokenModel->deleteByUserId($user['id']);
                 }
                 // --------------------------

                 // TODO: 2FA Check
                 $_SESSION['success_message'] = "Welcome back, " . htmlspecialchars($user['name']) . "!";
                 $this->redirect(APP_URL . '/');
                 exit;

            } else {
                 $errors[] = "Invalid credentials provided.";
                 $_SESSION['error_message'] = "Invalid credentials provided.";
            }
        } else {
             $_SESSION['error_message'] = implode(' ', $errors);
        }

        $_SESSION['old_email'] = $email;
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
     * Handle user logout. Validates CSRF token and clears Remember Me.
     */
    public function logout(): void {
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken, 'csrf_token')) {
            error_log("CSRF token validation failed for logout.");
            $_SESSION['error_message'] = "Invalid logout request.";
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // --- Clear Remember Me ---
        $this->clearRememberMeCookie(); // Delete cookie
        if (Auth::id()) { // Check if user ID exists in session before clearing tokens
             $this->tokenModel->deleteByUserId(Auth::id()); // Delete server-side tokens
        }
        // -----------------------

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

/**
     * Handle the email verification link click.
     */
    public function verifyEmail(): void {
        $token = $_GET['token'] ?? null;

        if (!$token) {
            $_SESSION['error_message'] = "Lien de vérification invalide ou manquant.";
            $this->redirect(APP_URL . '/login');
            exit;
        }

        $tokenData = $this->verificationModel->findByToken($token);

        if (!$tokenData) {
            $_SESSION['error_message'] = "Ce lien de vérification n'est pas valide. Il a peut-être expiré ou déjà été utilisé.";
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // Check if token has expired (e.g., older than 60 minutes)
        $validityMinutes = 60; // Should match the duration used when creating
        $createdAt = new DateTime($tokenData['created_at']);
        $expiresAt = (clone $createdAt)->add(new DateInterval("PT{$validityMinutes}M"));
        $now = new DateTime();

        if ($now > $expiresAt) {
             error_log("Email verification token expired for email: " . $tokenData['email'] . " (Token: $token)");
            // Clean up the expired token
             $this->verificationModel->deleteToken($token);
            $_SESSION['error_message'] = "Le lien de vérification a expiré. Veuillez en demander un nouveau.";
            // TODO: Add a way to request a new token
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // Token is valid and not expired. Find the user.
        $user = $this->userModel->findUserByEmail($tokenData['email']);

        if (!$user) {
            // Should not normally happen if token exists, but good check
            error_log("User not found for valid verification token: " . $tokenData['email']);
             $this->verificationModel->deleteToken($token); // Clean up
            $_SESSION['error_message'] = "Utilisateur associé à ce lien introuvable.";
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // Mark email as verified in the users table
        if ($this->userModel->markEmailAsVerified($user['id'])) {
            // Delete the token now that it's used
            $this->verificationModel->deleteToken($token);

            $_SESSION['success_message'] = "Votre adresse e-mail a été vérifiée avec succès ! Vous pouvez maintenant vous connecter.";
            $this->redirect(APP_URL . '/login');
            exit;
        } else {
            error_log("Failed to update email_verified_at for user ID: " . $user['id']);
            $_SESSION['error_message'] = "Une erreur est survenue lors de la vérification de votre e-mail. Veuillez réessayer ou contacter le support.";
            $this->redirect(APP_URL . '/login');
            exit;
        }
    }


    // --- Helper Methods ---

    /**
     * Helper function to load a view.
     * Includes header and footer layouts automatically.
     *
     * @param string $viewName The name of the view file (e.g., 'auth/login').
     * @param array $data Data to pass to the view (extracted into variables).
     * Creates a persistent "Remember Me" cookie and database token.
     * @param int $userId The ID of the user to remember.
     */
    private function createRememberMeCookie(int $userId): void {
        try {
            $selector = bin2hex(random_bytes(16)); // 32 chars hex
            $validator = bin2hex(random_bytes(32)); // 64 chars hex
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT); // Hash the validator for DB storage
            $cookieValue = $selector . ':' . $validator; // Combine for cookie

            $expires = new DateTime();
            $expires->add(new DateInterval('P30D')); // Cookie and token valid for 30 days

            // Store token in database
            if ($this->tokenModel->insertToken($userId, $selector, $hashedValidator, $expires)) {
                // Set the cookie
                setcookie(
                    'remember_me',                     // Cookie name
                    $cookieValue,                      // Value: selector:validator
                    [
                        'expires' => $expires->getTimestamp(), // Expiration timestamp
                        'path' => '/',                     // Available on entire domain
                        'domain' => '',                    // Current domain
                        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', // HTTPS only
                        'httponly' => true,                 // Not accessible via JavaScript
                        'samesite' => 'Lax'                 // Mitigate CSRF
                    ]
                );
                 error_log("Remember me cookie SET for user ID: " . $userId); // Debug logging
            } else {
                error_log("Failed to insert remember token into database for user ID: " . $userId);
            }
        } catch (\Exception $e) {
            error_log("Error creating remember me cookie: " . $e->getMessage());
        }
    }

    /**
     * Clears the "Remember Me" cookie.
     * Corresponding DB tokens should be cleared separately if needed (e.g., on logout).
     */
    private function clearRememberMeCookie(): void {
        // Check if the cookie exists before trying to delete it
        if (isset($_COOKIE['remember_me'])) {
             error_log("Clearing remember_me cookie."); // Debug logging
             // Set the cookie with an expiration date in the past
             setcookie(
                 'remember_me',
                 '', // Empty value
                 [
                     'expires' => time() - 3600, // Expire one hour ago
                     'path' => '/',
                     'domain' => '',
                     'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
                     'httponly' => true,
                     'samesite' => 'Lax'
                 ]
             );
             // Also unset it from the current request's $_COOKIE array
             unset($_COOKIE['remember_me']);
        }
    }
	
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