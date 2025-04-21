<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation de votre mot de passe</title>
    <style>/* ... (styles similaires à l'email de vérification) ... */
        body { font-family: sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .button { display: inline-block; padding: 10px 20px; background-color: #0d6efd; color: #ffffff; text-decoration: none; border-radius: 4px; font-size: 16px; }
        .button:hover { background-color: #0b5ed7; }
        p { margin-bottom: 15px; }
        small { color: #777; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Réinitialisation de mot de passe pour <?php echo defined('APP_NAME') ? htmlspecialchars(APP_NAME) : 'notre application'; ?></h2>

        <p>Bonjour <?php echo isset($userName) ? htmlspecialchars($userName) : ''; ?>,</p>

        <p>Vous recevez cet e-mail car nous avons reçu une demande de réinitialisation de mot de passe pour votre compte.</p>

        <p>Cliquez sur le bouton ci-dessous pour réinitialiser votre mot de passe :</p>

        <p style="text-align: center;">
            <a href="<?php echo htmlspecialchars($resetLink ?? '#'); ?>" class="button">Réinitialiser le mot de passe</a>
        </p>

        <p>Ce lien de réinitialisation expirera dans <?php echo htmlspecialchars($validityMinutes ?? 60); ?> minutes.</p>

        <p>Si vous n'avez pas demandé de réinitialisation de mot de passe, aucune action n'est requise.</p>

        <hr>
        <p><small>Ceci est un message automatique, veuillez ne pas y répondre.</small></p>
    </div>
</body>
</html>