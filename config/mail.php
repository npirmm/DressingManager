<?php
// config/mail.php

/**
 * Email Configuration Settings
 *
 * Choose one method: 'smtp' or potentially 'gmail_oauth' (more complex setup).
 *
 * SECURITY WARNING: Avoid committing real credentials. Use environment variables
 * (e.g., $_ENV['SMTP_PASSWORD']) in production.
 * getenv('VAR_NAME') is another way to read environment variables.
 */

return [
    // General settings
    'driver' => 'smtp', // 'smtp' is the most common driver. Others could be 'sendmail', 'log', etc.
    'from' => [
        'address' => getenv('MAIL_FROM_ADDRESS') ?: 'no-reply@test.com', // Default if env var not set
        'name' => getenv('MAIL_FROM_NAME') ?: APP_NAME, // Use APP_NAME defined in config/app.php
    ],

    // SMTP Driver Settings (used if 'driver' is 'smtp')
    'smtp' => [
        'host' => getenv('SMTP_HOST') ?: 'sandbox.smtp.mailtrap.io', // Example: Mailtrap for testing
        'port' => getenv('SMTP_PORT') ?: 587,               // Example: Mailtrap port (can be 587 for TLS, 465 for SSL, 25, 2525)
        'encryption' => getenv('SMTP_ENCRYPTION') ?: 'tls', // 'tls', 'ssl', or null (or false)
        'username' => getenv('SMTP_USERNAME') ?: 'YOURUSERNAME', // Your SMTP username
        'password' => getenv('SMTP_PASSWORD') ?: 'YOURPASSWORD', // Your SMTP password
    ],

    // Gmail Specific (Using App Password - Less Secure than OAuth2)
    // If using Gmail, set driver='smtp', host='smtp.gmail.com', port=587, encryption='tls'
    // And use your Gmail address as username and an App Password as password.
    // See: https://support.google.com/accounts/answer/185833
    // Using OAuth2 is more secure but requires more setup (client ID, secret, refresh tokens).

    // Log Driver Settings (used if 'driver' is 'log') - useful for debugging without sending emails
    'log_channel' => 'mail', // Name of the log channel (if using a logging library)
    'log_path' => __DIR__ . '/../storage/logs/mail.log', // Path to log file (ensure storage/logs is writable)
];
