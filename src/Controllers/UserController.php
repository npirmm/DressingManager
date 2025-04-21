<?php
// src/Controllers/UserController.php

namespace App\Controllers;

use App\Models\User; // We might need the model later for updates
use App\Utils\Auth; // We'll create this utility next

/**
 * UserController
 * Handles user profile related actions.
 */
class UserController {

    /**
     * Show the user profile page.
     * Access restricted to logged-in users.
     */
    public function showProfile(): void {
        Auth::checkAuthentication(); // Ensure user is logged in

        // Retrieve user data from the session (set during login)
        $userData = [
            'id' => $_SESSION['user_id'] ?? null,
            'name' => $_SESSION['user_name'] ?? 'N/A',
            'email' => $_SESSION['user_email'] ?? 'N/A',
            'role_name' => $_SESSION['user_role_name'] ?? 'N/A',
            // Add other relevant info later if needed (e.g., 2FA status)
        ];

        // Load the profile view and pass user data
        $this->loadView('user/profile', [
            'pageTitle' => 'My Profile',
            'user' => $userData
        ]);
    }

    // We will add methods like updateProfile, updatePassword, setup2FA later

    /**
     * Helper function to load a view (Could be inherited from a BaseController later).
     * @param string $viewName The name of the view file (e.g., 'user/profile').
     * @param array $data Data to pass to the view.
     */
    private function loadView(string $viewName, array $data = []): void {
         extract($data);
         $viewPath = __DIR__ . '/../Views/' . $viewName . '.php';
         if (file_exists($viewPath)) {
             $headerPath = __DIR__ . '/../Views/layouts/header.php';
             // Modify header to include navigation for logged-in users
             if (file_exists($headerPath)) { require $headerPath; }

             require $viewPath;

             $footerPath = __DIR__ . '/../Views/layouts/footer.php';
             if (file_exists($footerPath)) { require $footerPath; }
         } else {
             error_log("View file not found: " . $viewPath);
             echo "Error: Could not load the requested page content.";
         }
    }

     /**
     * Helper function for redirection (Could be inherited).
     * @param string $url The URL to redirect to.
     */
     private function redirect(string $url): void {
         header("Location: " . $url);
         exit;
     }
}