<?php
include 'header.php';

// Start the session if it's not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$error_message = '';
if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

if (isset($_SESSION['message'])) {
    echo '<p class="flash-message" style="color: green;">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']); // Clear the message after displaying
}

$isMfaEnabled = isset($_SESSION['mfa_required']) ? $_SESSION['mfa_required'] : false;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Login</h2>

            <!-- Display error message if it exists -->
            <?php if (!empty($error_message)): ?>
                <p class="flash-message error"><?php echo htmlspecialchars($error_message); ?></p>
            <?php endif; ?>

            <form action="../controller/AuthController.php" method="post">
    <input type="hidden" name="action" value="login">

    <label for="username">Username or Email:</label>
    <input type="text" id="username" name="username" required>

    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required>

    <!-- Conditionally show the MFA field -->
<?php if ($isMfaEnabled && $isMfaEnabled === true): ?>
    <label for="totp_code">Authentication Code:</label>
    <input type="text" id="totp_code" name="totp_code" >
<?php endif; ?>

    <!-- Google reCAPTCHA v2 Widget -->
    <div class="g-recaptcha" data-sitekey="6Lcl-bIqAAAAAOKnD2ImtrjsO9Hln7IP5xJx0U4O"></div>

<button type="submit">Log In</button>
            </form>
                        <!-- Password Recovery Link -->
                        <div class="password-recovery">
                <p><a href="password_recovery_request.php">Forgot your password?</a></p>
            </div>
        </div>
    </div>
</body>
</html>

<!-- Add the Google reCAPTCHA API script -->
<script src="https://www.google.com/recaptcha/api.js" async defer></script>

<!-- KEYS 
 SITE KEY: 6Lcl-bIqAAAAAOKnD2ImtrjsO9Hln7IP5xJx0U4O
 SECRET KEY: 6Lcl-bIqAAAAAMRSWnmm_cR9wgOuYUCOM98TVT15
