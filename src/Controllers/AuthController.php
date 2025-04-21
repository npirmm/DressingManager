<?php
// src/Controllers/AuthController.php

namespace App\Controllers;

use App\Models\User; // Use the User model

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
        // (This check should ideally happen *before* routing to this method)
        if ($this->userModel->countUsers() > 0) {
            $this->redirect(APP_URL . '/login'); // Use a helper function later
            exit;
        }

        // Load the view for the setup form
        $this->loadView('auth/setup', ['pageTitle' => 'Initial Admin Setup']);
    }

    /**
     * Handle the submission of the initial setup form.
     */
    public function handleSetup(): void {
        // Double check: Only proceed if no users exist
        if ($this->userModel->countUsers() > 0) {
            $this->redirect(APP_URL . '/login');
            exit;
        }

        // --- Basic Input Validation ---
        // We'll add more robust validation later (e.g., CSRF, length, email format)
        $name = $_POST['name'] ?? '';
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $passwordConfirm = $_POST['password_confirmation'] ?? '';
        $errors = [];

        if (empty($name)) $errors[] = "Name is required.";
        if (empty($email)) $errors[] = "Email is required.";
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Invalid email format.";
        if (empty($password)) $errors[] = "Password is required.";
        elseif (strlen($password) < 8) $errors[] = "Password must be at least 8 characters long."; // Example rule
        if ($password !== $passwordConfirm) $errors[] = "Passwords do not match.";

        // --- Process Registration ---
        if (empty($errors)) {
            // Attempt to create the user (Role ID 1 is Superadmin)
            // Set email as verified for the first admin
            $userId = $this->userModel->createUser($name, $email, $password, 1, true);

            if ($userId !== false) {
                // Success! Set a success message (using sessions) and redirect to login
                $_SESSION['success_message'] = "Superadmin account created successfully! You can now log in.";
                $this->redirect(APP_URL . '/login');
                exit;
            } else {
                // Check if it was a duplicate email error
                 if ($this->userModel->findUserByEmail($email)) {
                     $errors[] = "An account with this email already exists (This shouldn't happen in setup if checks are correct).";
                 } else {
                     $errors[] = "An error occurred during registration. Please try again.";
                 }
            }
        }

        // --- Show Form Again with Errors (or if validation failed) ---
        $this->loadView('auth/setup', [
            'pageTitle' => 'Initial Admin Setup',
            'errors' => $errors,
            'old_name' => $name, // Repopulate form fields
            'old_email' => $email
        ]);
    }


    /**
     * Show the login form.
     */
    public function showLoginForm(): void {
        // If already logged in, redirect to dashboard/home (implement later)
        // if (isset($_SESSION['user_id'])) {
        //     $this->redirect(APP_URL . '/dashboard');
        //     exit;
        // }

        // Check for success/error messages from redirects (e.g., after setup)
        $successMessage = $_SESSION['success_message'] ?? null;
        $errorMessage = $_SESSION['error_message'] ?? null;
        unset($_SESSION['success_message'], $_SESSION['error_message']); // Clear messages after displaying

        $this->loadView('auth/login', [
            'pageTitle' => 'Login',
            'successMessage' => $successMessage,
            'errorMessage' => $errorMessage
        ]);
    }

    /**
     * Handle the login form submission.
     * (Basic version - no 2FA or Remember Me yet)
     */
     public function handleLogin(): void {
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $errors = [];

        if (empty($email)) $errors[] = "Email is required.";
        if (empty($password)) $errors[] = "Password is required.";

        if (empty($errors)) {
            $user = $this->userModel->findUserByEmail($email);

            if ($user && password_verify($password, $user['password'])) {
                // Password is correct!

                // Check if email is verified (important!)
                if (empty($user['email_verified_at'])) {
                    $_SESSION['error_message'] = "Your email address is not verified. Please check your inbox or contact support.";
                    $this->redirect(APP_URL . '/login');
                    exit;
                }

                // --- Start Session ---
                // Regenerate session ID upon login for security (prevents session fixation)
                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_role_id'] = $user['role_id'];
                $_SESSION['user_role_name'] = $user['role_name']; // Get role name from JOIN in findUserByEmail
                $_SESSION['last_login'] = time(); // Store login time if needed

                // TODO: Implement 2FA check here if $user['two_factor_enabled'] is true
                // TODO: Implement Remember Me functionality here

                // Redirect to a protected area (e.g., dashboard)
                // For now, just redirect to a simple success page or back to index
                 $_SESSION['success_message'] = "Welcome back, " . htmlspecialchars($user['name']) . "!";
                $this->redirect(APP_URL . '/'); // Redirect to home/dashboard later
                exit;

            } else {
                // Invalid email or password
                $errors[] = "Invalid credentials provided.";
            }
        }

        // --- Show Form Again with Errors ---
        $this->loadView('auth/login', [
            'pageTitle' => 'Login',
            'errors' => $errors,
            'old_email' => $email, // Repopulate email field
            'errorMessage' => implode(' ', $errors) // Display general error
        ]);
    }

    /**
     * Helper function to load a view.
     * In a real app, this would be part of a BaseController or a View class.
     *
     * @param string $viewName The name of the view file (e.g., 'auth/login').
     * @param array $data Data to pass to the view.
     */
    private function loadView(string $viewName, array $data = []): void {
        // Make data available as variables in the view's scope
        extract($data);

        // Construct the full path to the view file
        $viewPath = __DIR__ . '/../Views/' . $viewName . '.php';

        if (file_exists($viewPath)) {
            // Include a basic header/layout structure (optional but recommended)
            $headerPath = __DIR__ . '/../Views/layouts/header.php';
            if (file_exists($headerPath)) {
                require $headerPath;
            }

            // Include the actual view content
            require $viewPath;

            // Include a basic footer/layout structure (optional but recommended)
            $footerPath = __DIR__ . '/../Views/layouts/footer.php';
            if (file_exists($footerPath)) {
                require $footerPath;
            }
        } else {
            // Handle view not found error
            error_log("View file not found: " . $viewPath);
            echo "Error: Could not load the requested page content.";
        }
    }

     /**
      * Helper function for redirection.
      * Use this instead of direct header() calls for consistency.
      *
      * @param string $url The URL to redirect to.
      */
     private function redirect(string $url): void {
         header("Location: " . $url);
         exit; // Important to stop script execution after redirect
     }
}