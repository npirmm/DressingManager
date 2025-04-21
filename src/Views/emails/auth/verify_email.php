<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérifiez votre adresse e-mail</title>
    <style>
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
        <h2>Vérification de votre adresse e-mail pour <?php echo defined('APP_NAME') ? htmlspecialchars(APP_NAME) : 'notre application'; ?></h2>

        <p>Bonjour <?php echo isset($userName) ? htmlspecialchars($userName) : ''; ?>,</p>

        <p>Merci de vous être enregistré ou d'avoir mis à jour votre e-mail. Veuillez cliquer sur le bouton ci-dessous pour vérifier votre adresse e-mail :</p>

        <p style="text-align: center;">
            <a href="<?php echo htmlspecialchars($verificationLink ?? '#'); ?>" class="button">Vérifier l'adresse e-mail</a>
        </p>

        <p>Si vous ne parvenez pas à cliquer sur le bouton, veuillez copier et coller le lien suivant dans votre navigateur :<br>
        <a href="<?php echo htmlspecialchars($verificationLink ?? '#'); ?>"><?php echo htmlspecialchars($verificationLink ?? ''); ?></a></p>

        <p>Ce lien de vérification expirera dans <?php echo htmlspecialchars($validityMinutes ?? 60); ?> minutes.</p>

        <p>Si vous n'avez pas créé de compte ou modifié votre e-mail, aucune action n'est requise.</p>

        <hr>
        <p><small>Ceci est un message automatique, veuillez ne pas y répondre.</small></p>
    </div>
</body>
</html>