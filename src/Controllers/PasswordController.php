<?php
// src/Controllers/PasswordController.php

namespace App\Controllers;

use App\Models\User;
use App\Models\PasswordReset;
use App\Models\RememberToken; // For clearing tokens on reset
use App\Utils\Mailer;
use App\Utils\Security;
use DateTime;
use DateInterval;

class PasswordController {
    private User $userModel;
    private PasswordReset $passwordResetModel;
    private RememberToken $rememberTokenModel;
    private Mailer $mailer;

    public function __construct() {
        $this->userModel = new User();
        $this->passwordResetModel = new PasswordReset();
        $this->rememberTokenModel = new RememberToken();
        try {
             $this->mailer = new Mailer();
        } catch (\Exception $e) {
             error_log("Failed to initialize Mailer in PasswordController: " . $e->getMessage());
             $this->mailer = null;
        }
    }

    /**
     * Show the form to request a password reset link.
     */
    public function showForgotPasswordForm(): void {
        $this->loadView('auth/forgot-password', ['pageTitle' => 'Mot de passe oublié']);
    }

    /**
     * Handle the submission of the forgot password form.
     */
    public function handleForgotPassword(): void {
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedToken)) {
            $_SESSION['error_message'] = "Requête invalide. Veuillez réessayer.";
            $this->redirect(APP_URL . '/forgot-password'); exit;
        }

        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);

        if (!$email) {
            $_SESSION['error_message'] = "Veuillez fournir une adresse e-mail valide.";
            $_SESSION['old_email'] = $_POST['email'] ?? ''; // Preserve input
            $this->redirect(APP_URL . '/forgot-password'); exit;
        }

        // Clean up expired tokens before proceeding
        $this->passwordResetModel->deleteExpiredTokens();

        $user = $this->userModel->findUserByEmail($email);

        if ($user) {
            // User found, generate token and send email
            if (!$this->mailer) {
                 $_SESSION['error_message'] = "Le service d'envoi d'e-mails n'est pas disponible actuellement. Veuillez réessayer plus tard.";
                 $this->redirect(APP_URL . '/forgot-password'); exit;
            }

            try {
                $token = bin2hex(random_bytes(32));
                if ($this->passwordResetModel->createToken($email, $token)) {
                    $resetLink = APP_URL . '/reset-password?token=' . $token;
                    $validityMinutes = 60;

                    $htmlBody = $this->mailer->renderView('auth/password_reset', [
                        'userName' => $user['name'],
                        'resetLink' => $resetLink,
                        'validityMinutes' => $validityMinutes
                    ]);
                     $plainBody = "Bonjour {$user['name']},\n\nVous recevez cet e-mail car nous avons reçu une demande de réinitialisation de mot de passe pour votre compte.\n\nCliquez sur le lien suivant (valide $validityMinutes minutes) pour réinitialiser votre mot de passe :\n$resetLink\n\nSi vous n'avez pas demandé de réinitialisation, aucune action n'est requise.";


                    if ($this->mailer->send($email, 'Réinitialisation de votre mot de passe', $htmlBody, $plainBody)) {
                         $_SESSION['success_message'] = "Si un compte avec cet e-mail existe, un lien de réinitialisation a été envoyé.";
                         $this->redirect(APP_URL . '/forgot-password'); exit; // Show success on the same page
                    } else {
                        $_SESSION['error_message'] = "Impossible d'envoyer l'e-mail de réinitialisation. Veuillez réessayer.";
                        error_log("Failed to send password reset email to $email using Mailer::send().");
                    }
                } else {
                     $_SESSION['error_message'] = "Impossible de générer le lien de réinitialisation. Veuillez réessayer.";
                      error_log("Failed to create password reset token in DB for $email.");
                }
            } catch (\Exception $e) {
                 error_log("Error handling forgot password for $email: " . $e->getMessage());
                 $_SESSION['error_message'] = "Une erreur inattendue est survenue. Veuillez réessayer.";
            }

        } else {
             error_log("Password reset requested for non-existent email: $email");
            // IMPORTANT: Do NOT reveal if the email exists or not for security. Show the same generic success message.
             $_SESSION['success_message'] = "Si un compte avec cet e-mail existe, un lien de réinitialisation a été envoyé.";
             $this->redirect(APP_URL . '/forgot-password'); exit;
        }

        // Redirect back if errors occurred before sending message
        $this->redirect(APP_URL . '/forgot-password'); exit;
    }

    /**
     * Show the password reset form if the token is valid.
     */
    public function showResetForm(): void {
        $token = $_GET['token'] ?? null;

        if (!$token) {
            $_SESSION['error_message'] = "Lien de réinitialisation invalide ou manquant.";
            $this->redirect(APP_URL . '/login'); exit;
        }

        $tokenData = $this->passwordResetModel->findByToken($token);

        if (!$tokenData) {
            $_SESSION['error_message'] = "Ce lien de réinitialisation n'est pas valide. Il a peut-être expiré ou déjà été utilisé.";
            $this->redirect(APP_URL . '/login'); exit;
        }

		// Check expiry (e.g., 60 minutes) using UTC
		$validityMinutes = 60;
		// Create DateTime object from DB timestamp, specifying it's UTC
		$createdAt = new DateTime($tokenData['created_at'], new \DateTimeZone('UTC'));
		$expiresAt = (clone $createdAt)->add(new DateInterval("PT{$validityMinutes}M"));
		// Get current time explicitly in UTC
		$now = new DateTime('now', new \DateTimeZone('UTC'));

		if ($now > $expiresAt) {
			error_log("Password reset token expired for email: " . $tokenData['email'] . " (Token: $token) - Compared in UTC");
			$this->passwordResetModel->deleteToken($token); // Clean up
			$_SESSION['error_message'] = "Le lien de réinitialisation a expiré. Veuillez refaire une demande.";
			$this->redirect(APP_URL . '/forgot-password'); exit;
		}

        // Token is valid, show the form
        $this->loadView('auth/reset-password', [
            'pageTitle' => 'Réinitialiser le mot de passe',
            'token' => $token,
            'email' => $tokenData['email'] // Pass email to prefill read-only field
        ]);
    }

    /**
     * Handle the submission of the password reset form.
     */
    public function handleResetPassword(): void {
        $submittedCsrfToken = $_POST['csrf_token'] ?? '';
        if (!Security::validateCsrfToken($submittedCsrfToken)) {
            $_SESSION['error_message'] = "Requête invalide. Veuillez réessayer.";
            $this->redirect(APP_URL . '/login'); exit;
        }

        $token = $_POST['token'] ?? null;
        $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $password = $_POST['password'] ?? '';
        $passwordConfirm = $_POST['password_confirmation'] ?? '';
        $errors = [];

        if (!$token || !$email) {
             $_SESSION['error_message'] = "Informations de réinitialisation manquantes.";
             $this->redirect(APP_URL . '/login'); exit;
        }

        // --- Validate Token Again (Crucial!) ---
         $tokenData = $this->passwordResetModel->findByToken($token);
         if (!$tokenData || $tokenData['email'] !== $email) {
             $_SESSION['error_message'] = "Lien de réinitialisation invalide ou ne correspondant pas à l'e-mail.";
             $this->redirect(APP_URL . '/login'); exit;
         }
		 // Check expiry again using UTC
		 $validityMinutes = 60;
		 $createdAt = new DateTime($tokenData['created_at'], new \DateTimeZone('UTC')); // Specify UTC
		 $expiresAt = (clone $createdAt)->add(new DateInterval("PT{$validityMinutes}M"));
		 $now = new DateTime('now', new \DateTimeZone('UTC')); // Specify UTC

		 if ($now > $expiresAt) {
			  $this->passwordResetModel->deleteToken($token); // Clean up
			  $_SESSION['error_message'] = "Le lien de réinitialisation a expiré. Veuillez refaire une demande.";
			  $this->redirect(APP_URL . '/forgot-password'); exit;
         }
         // --- End Token Validation ---


        // --- Validate Passwords ---
        if (empty($password)) $errors[] = "Password is required.";
        elseif (strlen($password) < 8) $errors[] = "Password must be at least 8 characters long.";
        if ($password !== $passwordConfirm) $errors[] = "Passwords do not match.";

        if (empty($errors)) {
            // Find user by email associated with the valid token
            $user = $this->userModel->findUserByEmail($email);

            if ($user) {
                // Update password
                if ($this->userModel->updatePassword($user['id'], $password)) {
                    // Password updated successfully!
                    // Delete the reset token
                    $this->passwordResetModel->deleteToken($token);

                     // SECURITY: Invalidate other sessions and remember me tokens
                     $this->rememberTokenModel->deleteByUserId($user['id']);
                     // If using DB sessions, delete those too. For file sessions, logout below handles it.

                    // Log user out of current session (if somehow logged in) before redirecting
                     if (isset($_SESSION['user_id'])) {
                         // Clear session data
                         $_SESSION = array();
                         if (ini_get("session.use_cookies")) {
                             $params = session_get_cookie_params();
                             setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
                         }
                         session_destroy();
                         // Start a new clean session just to pass the success message
                          if (session_status() == PHP_SESSION_NONE) session_start();
                     }


                    $_SESSION['success_message'] = "Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.";
                    $this->redirect(APP_URL . '/login');
                    exit;
                } else {
                    $errors[] = "Impossible de mettre à jour le mot de passe. Veuillez réessayer.";
                    error_log("Failed to update password via reset for user ID: " . $user['id']);
                }
            } else {
                 // Should not happen if token was valid, indicates inconsistency
                 $errors[] = "Utilisateur associé à ce lien introuvable.";
                 error_log("User ($email) not found during password reset despite valid token ($token).");
                  $this->passwordResetModel->deleteToken($token); // Clean up inconsistent token
            }
        }

        // --- Show Form Again with Errors ---
        // Pass necessary data back to the view
        $this->loadView('auth/reset-password', [
            'pageTitle' => 'Réinitialiser le mot de passe',
            'token' => $token,
            'email' => $email,
            'errors' => $errors // Pass errors to display
        ]);

    }


    // Helper methods
private function loadView(string $viewName, array $data = []): void {
    // die("Reached loadView method in PasswordController. View: " . $viewName); // <-- TEST E
     extract($data);
     $viewPath = __DIR__ . '/../Views/' . $viewName . '.php';
     // die("View path: " . $viewPath . " | File exists: " . (file_exists($viewPath) ? 'Yes' : 'No')); // <-- TEST F (Amélioré)

     if (file_exists($viewPath)) {
          // die("View file exists. Trying to load header..."); // <-- TEST G
         $headerPath = __DIR__ . '/../Views/layouts/header.php';
         if (file_exists($headerPath)) {
             // die("Header file exists. Requiring header: " . $headerPath); // <-- TEST G-2
             require $headerPath;
             // die("Header loaded successfully."); // <-- TEST H
         } else {
              die("Header file NOT found: " . $headerPath); // Stoppe si header manque
         }

         // die("Trying to load main view: " . $viewPath); // <-- TEST I
         require $viewPath;
         // die("Main view (forgot-password.php) loaded successfully."); // <-- TEST J

         // die("Trying to load footer..."); // <-- TEST K
         $footerPath = __DIR__ . '/../Views/layouts/footer.php';
         if (file_exists($footerPath)) {
             // die("Footer file exists. Requiring footer: " . $footerPath); // <-- TEST K-2
             require $footerPath;
             // die("Footer loaded successfully."); // <-- TEST L
         } else {
             die("Footer file NOT found: " . $footerPath); // Stoppe si footer manque
         }
     } else {
         error_log("View file not found: " . $viewPath);
         echo "Error: Could not load the requested page content.";
         die("View file NOT found: " . $viewPath); // <-- TEST M
     }
    // die("Finished loadView method."); // <-- TEST N
}

private function redirect(string $url): void {
     header("Location: " . $url);
     exit;
 }
}