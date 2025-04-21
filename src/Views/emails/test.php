<!DOCTYPE html><html><head><title>Test Email</title></head><body>
<h1>Hello <?php echo htmlspecialchars($name ?? 'There'); ?>!</h1>
<p>This is a test email rendered from a template.</p>
<p>Application URL: <?php echo APP_URL; ?></p>
</body></html>