<?php
// config/app.php

/**
 * General Application Settings
 */

define('APP_NAME', 'Dressing Manager');
define('APP_URL', 'http://localhost/dressing-manager'); // IMPORTANT: Set this to your actual app URL (without trailing slash)
define('APP_ENV', 'development'); // Set to 'production' in production environment
define('SESSION_NAME', 'dressing_session'); // Name for the session cookie

// Error Reporting (Development vs Production)
if (APP_ENV === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
    // Consider setting up proper logging to a file in production
}

// Default Timezone
date_default_timezone_set('Europe/Paris'); // Set to your relevant timezone