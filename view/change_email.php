<?php
require_once "../model/User.php"; // ✅ Ensure the User model is loaded
include("./header.php");

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

// ✅ Clear any old messages to prevent conflicts
unset($_SESSION['mfa_success']);
unset($_SESSION['error_message']);

// ✅ Display success or error messages
if (isset($_SESSION['message'])) {
    echo '<p class="flash-message" style="color: green;">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']);
}

if (isset($_SESSION['error_message'])) {
    echo '<p class="flash-message" style="color: red;">' . $_SESSION['error_message'] . '</p>';
    unset($_SESSION['error_message']);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Email</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Change Email Address</h2>
            <form action="../controller/AuthController.php" method="post">
                <input type="hidden" name="action" value="change_email">

                <label for="new_email">New Email Address:</label>
                <input type="email" id="new_email" name="new_email" required>

                <label for="password">Confirm Password:</label>
                <input type="password" id="password" name="password" required>

                <?php if ($isMfaEnabled): ?>
                    <label for="totp_code">MFA Code:</label>
                    <input type="text" id="totp_code" name="totp_code" required>
                <?php endif; ?>

                <button type="submit">Change Email</button>
            </form>
        </div>
    </div>
</body>
</html>
