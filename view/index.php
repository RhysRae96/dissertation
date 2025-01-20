<?php
include 'header.php';

if (isset($_SESSION['message'])) {
    echo '<p class="flash-message">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']);
}

if (isset($_GET['logout']) && $_GET['logout'] == 1) {
    echo '<p class="flash-message success">You have successfully logged out.</p>';
}

if (isset($_SESSION['error_message'])): ?>
    <div class="alert alert-error">
        <p><?php echo $_SESSION['error_message']; ?></p>
        <button class="close-btn" onclick="this.parentElement.style.display='none';">&times;</button>
    </div>
<?php
    unset($_SESSION['error_message']);
endif;
?>
<?php if (isset($_SESSION['warning_message'])): ?>
    <p class="flash-message warning"><?php echo htmlspecialchars($_SESSION['warning_message']); ?></p>
    <?php unset($_SESSION['warning_message']); ?>
<?php endif; ?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Homepage</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <main>
        <h1>Welcome to the dissertation website following the OWASP authentication guidelines</h1>
        <p class="welcome">Explore the features that make our platform secure.</p>

        <!-- Feature Section -->
        <div class="feature-section">
            <div class="feature-card">
                <img src="../public/images/qr.png" alt="Secure Authentication" class="feature-image">
                <h3>Secure Authentication</h3>
                <p>Experience a safe and secure login process with multi-factor authentication.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/passwordrecovery.png" alt="Password Recovery" class="feature-image">
                <h3>Password Recovery</h3>
                <p>Forgot your password? Easily reset it with our secure recovery system.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/breached.png" alt="Breached Password Alerts" class="feature-image">
                <h3>Breached Password Alerts</h3>
                <p>Stay safe with alerts for compromised passwords detected in data breaches.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/username.png" alt="User-Friendly Design" class="feature-image">
                <h3>Usernames</h3>
                <p>Login with either your username or email address.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/userid.png" alt="Advanced Security" class="feature-image">
                <h3>User IDs</h3>
                <p>User IDs are randomly generated to prevent predicatable or sequential IDs.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/password.png" alt="Account Management" class="feature-image">
                <h3>Passwords</h3>
                <p>Controls set in place such as minimum password length.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/change.png" alt="Account Management" class="feature-image">
                <h3>Securely change presonal information</h3>
                <p>Manage your account details and preferences with ease.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/blocked.png" alt="Account Management" class="feature-image">
                <h3>Account timeout</h3>
                <p>Accounts are timed out when too incorrect login attempts are made to prevent login throttling.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/captcha.png" alt="Account Management" class="feature-image">
                <h3>Captcha</h3>
                <p>Prevents automated login attempts.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/email.png" alt="Account Management" class="feature-image">
                <h3>Email</h3>
                <p>Changes such as password and email are automatically sent to the users email address.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/logs.png" alt="Account Management" class="feature-image">
                <h3>Logs</h3>
                <p>Admins can monitor users actions to detect attacks and failures.</p>
            </div>
            <div class="feature-card">
                <img src="../public/images/hash.png" alt="Account Management" class="feature-image">
                <h3>Hashed Passwords</h3>
                <p>Passwords are hashed and stored securley to prevent breaches.</p>
            </div>
        </div>
    </main>
</body>
</html>

