<?php
// src/Controllers/UserController.php

namespace App\Controllers;

use App\Models\User;
use App\Models\EmailVerification; // <-- Add EmailVerification model
use App\Utils\Auth;
use App\Utils\Mailer;         // <-- Add Mailer utility
use DateTime;                // <-- Add DateTime

/**
 * UserController
 * Handles user profile related actions.
 */
class UserController {
    private User $userModel;
    private EmailVerification $verificationModel; // <-- Add property
    private Mailer $mailer;                       // <-- Add property

    public function __construct() {
        $this->userModel = new User();
        $this->verificationModel = new EmailVerification(); // <-- Instantiate
        try {
             $this->mailer = new Mailer(); // <-- Instantiate Mailer
        } catch (\Exception $e) {
             // Handle mailer configuration errors gracefully
             error_log("Failed to initialize Mailer in UserController: " . $e->getMessage());
             // Maybe disable email features or set a flag?
             $this->mailer = null; // Indicate mailer is unavailable
        }
    }
    /**
     * Show the user profile page.
     * Access restricted to logged-in users.
     */
    public function showProfile(): void {
        Auth::checkAuthentication();

        // Retrieve user data - Fetch fresh data from DB instead of only session?
        $user = $this->userModel->findUserById(Auth::id());

        if (!$user) {
             // Should not happen if Auth::checkAuthentication passed, but defensive check
              $_SESSION['error_message'] = "User not found.";
             $this->redirect(APP_URL . '/logout'); // Force logout
             exit;
        }

        $this->loadView('user/profile', [
            'pageTitle' => 'My Profile',
            'user' => $user // Pass full user data array
        ]);
    }

    /**
     * Send an email verification link to the specified user.
     *
     * @param int $userId The ID of the user.
     * @param string $email The email address to verify.
     * @param string $userName The user's name for personalization.
     * @return bool True if email was sent successfully, false otherwise.
     */
    public function sendVerificationEmail(int $userId, string $email, string $userName): bool {
        if (!$this->mailer) {
            error_log("Mailer is not available. Cannot send verification email to $email.");
            return false; // Mailer failed to initialize
        }

        // Clean up any old expired tokens first (good practice)
        $this->verificationModel->deleteExpiredTokens();

        try {
            $token = bin2hex(random_bytes(32)); // Generate a secure random token
            $validityMinutes = 60; // Token valid for 1 hour

            if ($this->verificationModel->createToken($email, $token, $validityMinutes)) {
                $verificationLink = APP_URL . '/verify-email?token=' . $token;

                // Render the email body using the template
                $htmlBody = $this->mailer->renderView('auth/verify_email', [
                    'userName' => $userName,
                    'verificationLink' => $verificationLink,
                    'validityMinutes' => $validityMinutes
                ]);
                $plainBody = "Bonjour $userName,\n\nVeuillez vérifier votre adresse e-mail en visitant le lien suivant (valide $validityMinutes minutes) :\n$verificationLink\n\nSi vous n'avez pas initié cette demande, ignorez cet e-mail.";

                // Send the email
                if ($this->mailer->send($email, 'Vérifiez votre adresse e-mail', $htmlBody, $plainBody)) {
                    error_log("Verification email sent to $email for user ID $userId.");
                    return true;
                } else {
                     error_log("Failed sending verification email to $email using Mailer::send().");
                    // The error is already logged within Mailer::send()
                    return false;
                }
            } else {
                error_log("Failed to create verification token in database for email $email.");
                return false;
            }
        } catch (\Exception $e) {
            error_log("Error sending verification email for $email: " . $e->getMessage());
            return false;
        }
    }

    // --- Future methods for user creation/update would call sendVerificationEmail ---
    // Example (Pseudo-code):
    // public function handleAdminCreateUser() {
    //    ... validate input ...
    //    $newUser = $userModel->createUser(...);
    //    if ($newUser) {
    //        $this->sendVerificationEmail($newUser['id'], $newUser['email'], $newUser['name']);
    //        $_SESSION['success_message'] = "User created. Verification email sent.";
    //    }
    //    ... redirect ...
    // }
    // public function handleProfileUpdate() {
    //     ... validate input ...
    //     if ($newEmail !== $currentUserEmail) {
    //         // Update user email in DB (set email_verified_at to NULL)
    //         $userModel->updateEmail($userId, $newEmail);
    //         $this->sendVerificationEmail($userId, $newEmail, $userName);
    //          $_SESSION['success_message'] = "Profile updated. Please check your new email address for verification.";
    //     }
    //     ... redirect ...
    // }

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