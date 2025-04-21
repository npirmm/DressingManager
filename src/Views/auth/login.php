<div class="auth-container">
    <h2 class="text-center mb-4"><?php echo htmlspecialchars($pageTitle); ?></h2>

    <?php // Display success message from session (e.g., after setup) ?>
    <?php if (isset($successMessage)): ?>
        <div class="alert alert-success" role="alert">
            <?php echo htmlspecialchars($successMessage); ?>
        </div>
    <?php endif; ?>

    <?php // Display error message from session or login attempt ?>
    <?php if (isset($errorMessage)): ?>
        <div class="alert alert-danger" role="alert">
            <?php echo htmlspecialchars($errorMessage); ?>
        </div>
    <?php endif; ?>
     <?php // Display validation errors from direct form submission ?>
     <?php if (!empty($errors) && !isset($errorMessage)): // Avoid double display if general error message is set ?>
        <div class="alert alert-danger" role="alert">
            <strong>Error!</strong>
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>


    <form action="<?php echo APP_URL; ?>/login" method="POST">
         <?php // TODO: Add CSRF token here later ?>

        <div class="mb-3">
            <label for="email" class="form-label">Email Address</label>
            <input type="email" class="form-control <?php echo (isset($errors) && !empty($errors)) || isset($errorMessage) ? 'is-invalid' : ''; ?>" id="email" name="email" value="<?php echo isset($old_email) ? htmlspecialchars($old_email) : ''; ?>" required autofocus>
        </div>

        <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control <?php echo (isset($errors) && !empty($errors)) || isset($errorMessage) ? 'is-invalid' : ''; ?>" id="password" name="password" required>
        </div>

        <div class="mb-3 form-check">
            <?php // TODO: Add "Remember Me" functionality ?>
            <!-- <input type="checkbox" class="form-check-input" id="remember" name="remember"> -->
            <!-- <label class="form-check-label" for="remember">Remember Me</label> -->
        </div>

        <div class="d-grid">
            <button type="submit" class="btn btn-primary">Login</button>
        </div>

        <div class="mt-3 text-center">
             <?php // TODO: Add Forgot Password link later ?>
            <!-- <a href="<?php echo APP_URL; ?>/forgot-password">Forgot Password?</a> -->
        </div>
    </form>
</div>