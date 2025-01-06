<?php
include 'header.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (isset($_SESSION['message'])) {
    echo '<p class="flash-message">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']); // Clear the message after displaying
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Registration</title>
    <!-- Include the zxcvbn library for password strength -->
    <script src="https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js"></script>
    <!-- Include the password validation script -->
    <script src="../script/validation.js"></script>
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Register</h2>
            
            <form action="../controller/AuthController.php" method="post" onsubmit="return validateRegistrationForm()">
            <input type="hidden" name="action" value="register">

            <!-- Error message container -->
            <div id="error-message" style="color: red; margin-bottom: 10px;"></div>

            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br><br>

            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required><br><br>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" oninput="validatePasswordStrength()" required><br><br>

            <label for="confirm-password">Confirm Password:</label>
            <input type="password" id="confirm-password" name="confirm_password" required><br><br>

    <!-- Password strength meter and feedback -->
    <meter max="4" id="strength-meter"></meter>
    <p id="password-feedback"></p>

            <button type="submit">Register</button>
            </form>
        </div>
    </div>
</body>
</html>
