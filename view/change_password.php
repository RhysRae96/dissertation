<?php
include("./header.php");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Fetch user data to check if MFA is enabled
require_once "../model/User.php";
$user = new User();
$userData = $user->getUserByID($_SESSION['user_id']);
$isMfaEnabled = $userData['is_mfa_enabled'];

if (isset($_SESSION['message'])) {
    echo '<p class="flash-message">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Change Password</h2>

            <form action="../controller/AuthController.php" method="post">
                <input type="hidden" name="action" value="change_password">

                <label for="current_password">Current Password:</label>
                <input type="password" id="current_password" name="current_password" required>

                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required>

                <label for="confirm_password">Confirm New Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>

                <!-- Show the MFA code input field only if MFA is enabled -->
                <?php if ($isMfaEnabled): ?>
                    <label for="totp_code">MFA Code:</label>
                    <input type="text" id="totp_code" name="totp_code" required>
                <?php endif; ?>

                <button type="submit">Change Password</button>
            </form>
        </div>
    </div>
</body>
</html>
