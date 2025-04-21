<?php use App\Utils\Security; ?>
<div class="auth-container">
    <h2 class="text-center mb-4">Réinitialiser le mot de passe</h2>

    <?php // Display messages from session ?>
    <?php if (isset($_SESSION['error_message'])): ?>
        <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?></div>
    <?php endif; ?>
    <?php if (!empty($errors)): // Display specific validation errors ?>
         <div class="alert alert-danger" role="alert">
             <strong>Erreur !</strong>
             <ul>
                 <?php foreach ($errors as $error): ?>
                     <li><?php echo htmlspecialchars($error); ?></li>
                 <?php endforeach; ?>
             </ul>
         </div>
     <?php endif; ?>


    <form action="<?php echo APP_URL; ?>/reset-password" method="POST">
        <?php echo Security::csrfInput(); ?>

        <?php // Hidden fields for token and email ?>
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token ?? ''); ?>">
        <input type="hidden" name="email" value="<?php echo htmlspecialchars($email ?? ''); ?>">

        <div class="mb-3">
            <label for="email_display" class="form-label">Adresse e-mail</label>
            <input type="email" class="form-control" id="email_display" value="<?php echo htmlspecialchars($email ?? ''); ?>" disabled readonly>
        </div>

        <div class="mb-3">
            <label for="password" class="form-label">Nouveau mot de passe</label>
            <input type="password" class="form-control <?php echo isset($errors) && (in_array("Password is required.", $errors) || in_array("Password must be at least 8 characters long.", $errors) || in_array("Passwords do not match.", $errors)) ? 'is-invalid' : ''; ?>" id="password" name="password" required>
            <div class="form-text">Doit contenir au moins 8 caractères.</div>
        </div>

        <div class="mb-3">
            <label for="password_confirmation" class="form-label">Confirmer le nouveau mot de passe</label>
            <input type="password" class="form-control <?php echo isset($errors) && in_array("Passwords do not match.", $errors) ? 'is-invalid' : ''; ?>" id="password_confirmation" name="password_confirmation" required>
        </div>

        <div class="d-grid">
            <button type="submit" class="btn btn-primary">Réinitialiser le mot de passe</button>
        </div>
    </form>
</div>