<!DOCTYPE html>
<html lang="fr"> <?php // Set language to French ?>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($pageTitle) ? htmlspecialchars($pageTitle) . ' - ' : ''; echo APP_NAME; ?></title>

    <!-- Bootstrap CSS (CDN) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">

    <!-- Optional: Your custom CSS -->
    <!-- <link href="<?php echo APP_URL; ?>/css/style.css" rel="stylesheet"> -->

    <style>
        /* Simple styling for alerts */
        .alert { margin-top: 1rem; }
        body { background-color: #f8f9fa; }
        .auth-container { max-width: 450px; margin: 5rem auto; padding: 2rem; background-color: #fff; border-radius: 0.5rem; box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">