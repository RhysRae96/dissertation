<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($pageTitle) ? $pageTitle : "Website"; ?></title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>

    <!-- Navigation bar -->
    <nav>
        <ul>
            <li><a href="index.php">Home</a></li>
            <li><a href="page_unavailable.php">About</a></li>
            <li><a href="page_unavailable.php">Contact</a></li>
        </ul>
        
        <div class="auth-buttons">
        <?php if (isset($_SESSION['user_id'])): ?>
            <span class="username-display">Hello, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
            <a href="change_password.php" class="change-password-button">Change Password</a>
            <a href="logout.php" class="logout-button">Logout</a>
        <?php else: ?>
            <a href="login.php" class="login-button">Login</a>
            <a href="register.php" class="register-button">Register</a>
        <?php endif; ?>
    </div>
</nav>
