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

            <form action="../controller/authController.php" method="post">
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


                <button type="submit">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
