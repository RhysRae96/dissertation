<?php
require_once "../model/User.php";
include('header.php');

// Start the session if it's not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect to login if the user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user = new User();
$userData = $user->getUserByID($_SESSION['user_id']);
$isMfaEnabled = $userData['is_mfa_enabled'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Factor Authentication</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <?php if ($isMfaEnabled): ?>
                <h2 class="form-title">MFA Already Enabled</h2>
                <p class="form-text">You have already enabled Multi-Factor Authentication.<a href="index.php">Return to Home</a></p>
                <form action="../controller/authController.php" method="post" class="form-content">
                    <input type="hidden" name="action" value="disable_mfa">
                    <button type="submit" class="form-button">Disable MFA</button>
                </form>
            <?php else: ?>
                <h2 class="form-title">Enable Multi-Factor Authentication</h2>
                <p class="form-text">Scan this QR code with your Google Authenticator app:</p>
                <div class="qr-code-container">
                    <?php
                    $secret = $user->generateTotpSecret();
                    $qrCodeUrl = $user->getQrCodeUrl($_SESSION['username'], $secret);
                    ?>
                    <img src="<?php echo $qrCodeUrl; ?>" alt="Scan this QR Code" class="qr-code">
                </div>
                <p class="form-text">Once you've scanned the QR code, enter the code generated by your app to verify:</p>
                <form action="../controller/authController.php" method="post" class="form-content">
                    <input type="hidden" name="action" value="verify_totp">
                    <label for="totp_code" class="form-label">Authentication Code:</label>
                    <input type="text" id="totp_code" name="totp_code" class="form-input" required>
                    <button type="submit" class="form-button">Verify</button>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
