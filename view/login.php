<?php
include 'header.php';

// Start the session if it's not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check for error message
$error_message = '';
if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']); // Clear the message after displaying
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="../styles.css"> <!-- Link to your CSS file -->
    <script src="../script/validation.js"></script>
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Login</h2>

            <!-- Display error message if it exists -->
            <?php if (!empty($error_message)): ?>
                <p class="flash-message error"><?php echo htmlspecialchars($error_message); ?></p>
            <?php endif; ?>

            <form action="../controller/AuthController.php" method="post" onsubmit="return validateLoginForm()">
                <input type="hidden" name="action" value="login">

                <label for="username">Username or Email:</label>
                <input type="text" id="username" name="username" required><br><br>

                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br><br>

                <button type="submit">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
