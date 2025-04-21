<?php use App\Utils\Security; ?>
<div class="auth-container">
    <h2 class="text-center mb-4">Mot de passe oublié</h2>
    <p class="text-center text-muted">Entrez votre adresse e-mail et nous vous enverrons un lien pour réinitialiser votre mot de passe.</p>

    <?php // Display messages from session ?>
    <?php if (isset($_SESSION['success_message'])): ?>
        <div class="alert alert-success" role="alert"><?php echo htmlspecialchars($_SESSION['success_message']); unset($_SESSION['success_message']); ?></div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error_message'])): ?>
        <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?></div>
    <?php endif; ?>

    <form action="<?php echo APP_URL; ?>/forgot-password" method="POST">
        <?php echo Security::csrfInput(); ?>

        <div class="mb-3">
            <label for="email" class="form-label">Adresse e-mail</label>
            <input type="email" class="form-control <?php echo isset($_SESSION['error_message']) ? 'is-invalid' : ''; ?>" id="email" name="email" value="<?php echo isset($_SESSION['old_email']) ? htmlspecialchars($_SESSION['old_email']) : ''; unset($_SESSION['old_email']); ?>" required autofocus>
        </div>

        <div class="d-grid">
            <button type="submit" class="btn btn-primary">Envoyer le lien de réinitialisation</button>
        </div>

        <div class="mt-3 text-center">
            <a href="<?php echo APP_URL; ?>/login">Retour à la connexion</a>
        </div>
    </form>
</div>