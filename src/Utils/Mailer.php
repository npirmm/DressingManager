<?php
// src/Utils/Mailer.php

namespace App\Utils;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPMailer\PHPMailer\SMTP; // Required for verbose debug output

class Mailer {
    private PHPMailer $mailer;
    private array $config;

    public function __construct() {
        // Load mail configuration
        $configPath = __DIR__ . '/../../config/mail.php';
        if (!file_exists($configPath)) {
            throw new \Exception("Mail configuration file not found: $configPath");
        }
        $this->config = require $configPath;

        $this->mailer = new PHPMailer(true); // Enable exceptions

        $this->configureMailer();
    }

    /**
     * Configure the PHPMailer instance based on the loaded configuration.
     */
    private function configureMailer(): void {
        try {
            // Server settings
            if ($this->config['driver'] === 'smtp') {
                $this->mailer->isSMTP();
                $this->mailer->Host = $this->config['smtp']['host'];
                $this->mailer->Port = $this->config['smtp']['port'];

                if (!empty($this->config['smtp']['username'])) {
                    $this->mailer->SMTPAuth = true;
                    $this->mailer->Username = $this->config['smtp']['username'];
                    $this->mailer->Password = $this->config['smtp']['password'];
                } else {
                     $this->mailer->SMTPAuth = false;
                }

                if ($this->config['smtp']['encryption'] === 'tls') {
                    $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                } elseif ($this->config['smtp']['encryption'] === 'ssl') {
                    $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
                } else {
                    $this->mailer->SMTPSecure = false; // No encryption
                    $this->mailer->SMTPAutoTLS = false; // Disable auto-TLS if encryption is explicitly off
                }

                // Enable verbose debug output (Comment out in production)
                // $this->mailer->SMTPDebug = SMTP::DEBUG_SERVER;
                // $this->mailer->Debugoutput = function($str, $level) { error_log("SMTP Debug Level $level; Message: $str"); };

            } elseif ($this->config['driver'] === 'log') {
                 // Special configuration for logging driver will be handled in send()
                 // No specific PHPMailer server settings needed here.
            }
            // Add other drivers like 'sendmail' if needed

            // Set default sender
            $this->mailer->setFrom($this->config['from']['address'], $this->config['from']['name']);

            // Set content type and character set
            $this->mailer->isHTML(true); // Send HTML emails by default
            $this->mailer->CharSet = 'UTF-8';

        } catch (PHPMailerException $e) {
            error_log("PHPMailer Configuration Error: {$this->mailer->ErrorInfo}");
            // Rethrow or handle more gracefully depending on application needs
            throw new \RuntimeException("Failed to configure mailer: " . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Send an email.
     *
     * @param string $to Email address of the recipient.
     * @param string $subject Subject of the email.
     * @param string $htmlBody HTML content of the email.
     * @param string|null $plainBody Plain text alternative content (optional but recommended).
     * @return bool True if email was sent successfully, false otherwise.
     */
    public function send(string $to, string $subject, string $htmlBody, ?string $plainBody = null): bool {
        try {
            // Handle 'log' driver specifically
            if ($this->config['driver'] === 'log') {
                return $this->logEmail($to, $subject, $htmlBody, $plainBody);
            }

            // --- Standard Sending via PHPMailer ---
            // Recipients
            $this->mailer->addAddress($to);
            // $this->mailer->addReplyTo('info@example.com', 'Information');
            // $this->mailer->addCC('cc@example.com');
            // $this->mailer->addBCC('bcc@example.com');

            // Content
            $this->mailer->Subject = $subject;
            $this->mailer->Body    = $htmlBody;
            if ($plainBody) {
                $this->mailer->AltBody = $plainBody;
            } else {
                // Auto-generate plain text from HTML if not provided
                $this->mailer->AltBody = strip_tags(str_replace("<br>", "\n", $htmlBody));
            }

            $this->mailer->send();
             error_log("Email sent successfully to: $to | Subject: $subject"); // Log success
            return true;

        } catch (PHPMailerException $e) {
            error_log("Message could not be sent. Mailer Error: {$this->mailer->ErrorInfo}");
            return false;
        } catch (\Exception $e) { // Catch other potential errors
            error_log("An unexpected error occurred during email sending: " . $e->getMessage());
            return false;
        } finally {
             // Clear addresses and attachments for the next email in case the instance is reused
             $this->mailer->clearAddresses();
             $this->mailer->clearAttachments(); // If attachments were used
        }
    }

    /**
     * Handles logging email details instead of sending.
     *
     * @param string $to
     * @param string $subject
     * @param string $htmlBody
     * @param string|null $plainBody
     * @return bool True on successful logging, false otherwise.
     */
    private function logEmail(string $to, string $subject, string $htmlBody, ?string $plainBody = null): bool {
         $logPath = $this->config['log_path'] ?? __DIR__ . '/../storage/logs/mail.log';
         $logDir = dirname($logPath);

         if (!is_dir($logDir)) {
             if (!mkdir($logDir, 0775, true)) { // Create directory recursively
                 error_log("Failed to create mail log directory: " . $logDir);
                 return false;
             }
         }

         $logContent = sprintf(
             "[%s] === EMAIL ===\nTO: %s\nSUBJECT: %s\n--- HTML BODY ---\n%s\n--- PLAIN BODY ---\n%s\n=== END EMAIL ===\n\n",
             date('Y-m-d H:i:s'),
             $to,
             $subject,
             $htmlBody,
             $plainBody ?: strip_tags(str_replace("<br>", "\n", $htmlBody))
         );

         // Append to the log file
         if (file_put_contents($logPath, $logContent, FILE_APPEND | LOCK_EX) === false) {
             error_log("Failed to write to mail log file: " . $logPath);
             return false;
         }

         error_log("Email logged successfully to: " . $logPath); // Log confirmation
         return true;
     }

     /**
      * Renders an email view template.
      *
      * @param string $viewName View name relative to Views/emails/ (e.g., 'auth/verify_email').
      * @param array $data Data to pass to the view.
      * @return string Rendered HTML content.
      * @throws \InvalidArgumentException If view file not found.
      */
     public function renderView(string $viewName, array $data = []): string {
         extract($data);
         $viewPath = __DIR__ . '/../Views/emails/' . $viewName . '.php';

         if (!file_exists($viewPath)) {
             throw new \InvalidArgumentException("Email view template not found: $viewPath");
         }

         ob_start();
         require $viewPath;
         return ob_get_clean();
     }
}