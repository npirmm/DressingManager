<?php
// src/Utils/Auth.php

namespace App\Utils;

/**
 * Authentication Utility Class
 * Provides helper methods for checking authentication status.
 */
class Auth {

    /**
     * Check if a user is currently logged in via session.
     *
     * @return bool True if logged in, false otherwise.
     */
    public static function isLoggedIn(): bool {
        return isset($_SESSION['user_id']);
    }

    /**
     * If the user is not logged in, redirect them to the login page.
     * Typically used at the beginning of controller actions for protected routes.
     *
     * @param string $redirectTo URL to redirect to if not logged in. Defaults to APP_URL/login.
     */
    public static function checkAuthentication(?string $redirectTo = null): void {
        if (!self::isLoggedIn()) {
            $loginUrl = $redirectTo ?? (defined('APP_URL') ? APP_URL . '/login' : '/login');
            // Store intended URL? (Optional, for redirecting back after login)
            // $_SESSION['intended_url'] = $_SERVER['REQUEST_URI'];
             $_SESSION['error_message'] = "Please log in to access this page.";
            header("Location: " . $loginUrl);
            exit;
        }
    }

    /**
     * Get the logged-in user's ID.
     *
     * @return int|null User ID or null if not logged in.
     */
    public static function id(): ?int {
        return $_SESSION['user_id'] ?? null;
    }

    /**
     * Get the logged-in user's role name.
     *
     * @return string|null Role name or null if not logged in.
     */
    public static function role(): ?string {
         return $_SESSION['user_role_name'] ?? null;
     }

     // Add more helper methods as needed (e.g., user(), email(), etc.)
}