<?php
require_once "../model/User.php";
// Only start the session if it's not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Initialize the User class
$user = new User();

// Fetch the user data to check if MFA is enabled
$userData = $user->getUserByID($_SESSION['user_id']);
$isMfaEnabled = false;

if ($userData && isset($userData['is_mfa_enabled'])) {
    $isMfaEnabled = (bool)$userData['is_mfa_enabled'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="./styles.css">
</head>
<body>
    <nav>
        <ul>
            <li><a href="index.php">Home</a></li>
            <li><a href="about.php">About</a></li>
            <li><a href="mfa_setup.php">Multifactor</a></li>
        </ul>
        <div class="auth-buttons">
            <span class="username-display">Hello, <?php echo htmlspecialchars($_SESSION['username']); ?>!</span>
            <a href="change_password.php" class="change-password-button">Change Password</a>
            <a href="logout.php" class="logout-button">Logout</a>
        </div>
    </nav>

    <!-- Dashboard Content -->
    <div class="dashboard-page">
        <div class="dashboard-container">
            <?php if ($isMfaEnabled): ?>
                <!-- MFA Enabled Message -->
                <h1 class="dashboard-title">Well Done, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
                <p class="dashboard-message">
                    Multi-Factor Authentication has been successfully enabled.
                </p>
            <?php else: ?>
                <!-- MFA Disabled Message -->
                <h1 class="dashboard-title">MFA Disabled, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
                <p class="dashboard-message">
                    You have successfully disabled Multi-Factor Authentication.
                    <br><a href="index.php" class="dashboard-link">Return to Home
                </p>
            <?php endif; ?>

            <!-- Logout Button -->
            <div class="dashboard-actions">
                <a href="logout.php" class="dashboard-button">Logout</a>
            </div>
        </div>
    </div>
</body>
</html>

