<?php
// src/Utils/Security.php

namespace App\Utils;

/**
 * Security Utilities Class
 * Provides helper methods for common security tasks like CSRF protection.
 */
class Security {

    /**
     * Generate a CSRF token and store it in the session.
     * If a token already exists in the session, it returns the existing one.
     *
     * @param string $formKey A unique key for the form (optional, can add specificity). Default 'csrf_token'.
     * @return string The generated CSRF token.
     */
    public static function generateCsrfToken(string $formKey = 'csrf_token'): string {
        if (empty($_SESSION[$formKey])) {
            try {
                $_SESSION[$formKey] = bin2hex(random_bytes(32)); // Generate a strong random token
            } catch (\Exception $e) {
                // Handle error if random_bytes fails (highly unlikely)
                error_log("CSRF token generation failed: " . $e->getMessage());
                // Fallback or throw an exception
                $_SESSION[$formKey] = 'fallback_csrf_token_' . uniqid();
            }
        }
        return $_SESSION[$formKey];
    }

    /**
     * Validate a submitted CSRF token against the one stored in the session.
     * It's recommended to unset the token after successful validation for one-time use per request,
     * but for simplicity here, we keep it valid for the session duration unless explicitly regenerated.
     * Consider regenerating the token on key actions like login/logout.
     *
     * @param string $submittedToken The token received from the form submission.
     * @param string $formKey The key used when generating the token. Default 'csrf_token'.
     * @return bool True if the token is valid, false otherwise.
     */
    public static function validateCsrfToken(string $submittedToken, string $formKey = 'csrf_token'): bool {
        if (!isset($_SESSION[$formKey])) {
            error_log("CSRF validation failed: No token found in session for key: " . $formKey);
            return false; // No token in session
        }

        if (!hash_equals($_SESSION[$formKey], $submittedToken)) {
             error_log("CSRF validation failed: Submitted token mismatch for key: " . $formKey);
            return false; // Tokens do not match (use hash_equals for timing attack resistance)
        }

        // Optional: Unset the token after validation for one-time use (stricter)
        // unset($_SESSION[$formKey]);

        return true; // Token is valid
    }

    /**
     * Generate hidden HTML input field for CSRF token.
     *
     * @param string $formKey The key used when generating the token. Default 'csrf_token'.
     * @return string HTML input field string.
     */
    public static function csrfInput(string $formKey = 'csrf_token'): string {
        $token = self::generateCsrfToken($formKey);
        return '<input type="hidden" name="' . $formKey . '" value="' . $token . '">';
    }
}