<?php
include 'header.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Registration</title>
    <!-- Include the zxcvbn library for password strength -->
    <script src="https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js"></script>
    <!-- Include the password validation and form validation scripts -->
    <script src="../script/password_validation.js"></script>
    <script src="../script/validation.js"></script>
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Register</h2>
            
            <form action="../controller/AuthController.php" method="post" onsubmit="return validateRegistrationForm()">
                <input type="hidden" name="action" value="register">

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
