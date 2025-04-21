<?php
// src/Views/user/profile.php
// Ensure Auth check has happened in the controller before loading this view.
?>

<div class="container mt-5">
    <h1><?php echo htmlspecialchars($pageTitle); ?></h1>
    <hr>

    <?php if (isset($_SESSION['success_message'])): ?>
        <div class="alert alert-success" role="alert">
            <?php echo htmlspecialchars($_SESSION['success_message']); unset($_SESSION['success_message']); ?>
        </div>
    <?php endif; ?>
    <?php if (isset($_SESSION['error_message'])): ?>
        <div class="alert alert-danger" role="alert">
            <?php echo htmlspecialchars($_SESSION['error_message']); unset($_SESSION['error_message']); ?>
        </div>
    <?php endif; ?>


    <div class="card">
        <div class="card-header">
            User Information
        </div>
        <div class="card-body">
            <dl class="row">
                <dt class="col-sm-3">User ID:</dt>
                <dd class="col-sm-9"><?php echo htmlspecialchars($user['id'] ?? 'N/A'); ?></dd>

                <dt class="col-sm-3">Name:</dt>
                <dd class="col-sm-9"><?php echo htmlspecialchars($user['name'] ?? 'N/A'); ?></dd>

                <dt class="col-sm-3">Email Address:</dt>
                <dd class="col-sm-9"><?php echo htmlspecialchars($user['email'] ?? 'N/A'); ?></dd>

                <dt class="col-sm-3">Role:</dt>
                <dd class="col-sm-9"><?php echo htmlspecialchars($user['role_name'] ?? 'N/A'); ?></dd>

                <?php // Add more fields later: Email Verified?, 2FA Status? ?>
            </dl>

            <hr>
            <p>Future actions:</p>
            <ul>
                <li>Change Password</li>
                <li>Enable/Disable Two-Factor Authentication</li>
                <li>View Login History (if implemented)</li>
            </ul>
            <?php // Buttons or links for actions will go here later ?>
             <a href="<?php echo APP_URL; ?>/" class="btn btn-secondary">Back to Home</a>
        </div>
    </div>
</div>