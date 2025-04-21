<?php use App\Utils\Security; ?>

<div class="auth-container">
    <h2 class="text-center mb-4"><?php echo htmlspecialchars($pageTitle); ?></h2>
    <p class="text-center text-muted">Create the first Superadministrator account.</p>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger" role="alert">
            <strong>Error!</strong>
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form action="<?php echo APP_URL; ?>/setup" method="POST">
        <?php echo Security::csrfInput(); // <-- Add CSRF hidden field ?>

        <div class="mb-3">
            <label for="name" class="form-label">Full Name</label>
            <input type="text" class="form-control <?php echo isset($errors) && !empty($errors) && !isset($old_name) ? '' : (isset($errors) && in_array("Name is required.", $errors) ? 'is-invalid' : ''); ?>" id="name" name="name" value="<?php echo isset($old_name) ? htmlspecialchars($old_name) : ''; ?>" required>
        </div>

        <div class="mb-3">
            <label for="email" class="form-label">Email Address</label>
            <input type="email" class="form-control <?php echo isset($errors) && !empty($errors) && !isset($old_email) ? '' : (isset($errors) && (in_array("Email is required.", $errors) || in_array("Invalid email format.", $errors) || in_array("An account with this email already exists (This shouldn't happen in setup if checks are correct).", $errors)) ? 'is-invalid' : ''); ?>" id="email" name="email" value="<?php echo isset($old_email) ? htmlspecialchars($old_email) : ''; ?>" required>
        </div>

        <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control <?php echo isset($errors) && !empty($errors) && (in_array("Password is required.", $errors) || in_array("Password must be at least 8 characters long.", $errors) || in_array("Passwords do not match.", $errors)) ? 'is-invalid' : ''; ?>" id="password" name="password" required>
             <div class="form-text">Must be at least 8 characters long.</div>
        </div>

        <div class="mb-3">
            <label for="password_confirmation" class="form-label">Confirm Password</label>
            <input type="password" class="form-control <?php echo isset($errors) && !empty($errors) && in_array("Passwords do not match.", $errors) ? 'is-invalid' : ''; ?>" id="password_confirmation" name="password_confirmation" required>
        </div>

        <div class="d-grid">
            <button type="submit" class="btn btn-primary">Create Admin Account</button>
        </div>
    </form>
</div>