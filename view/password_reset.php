<?php
include 'header.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$error_message = '';
if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

$token = $_GET['token'] ?? null;

if (!$token) {
    echo "<p>Invalid or missing token.</p>";
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <link rel="stylesheet" href="../styles.css">
    <!-- Include the zxcvbn library -->
    <script src="https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js"></script>
    <!-- Include validation script -->
    <script>
        document.addEventListener("DOMContentLoaded", function () {
            const passwordInput = document.getElementById("new_password");
            const strengthMeter = document.getElementById("strength-meter");
            const feedback = document.getElementById("password-feedback");

            passwordInput.addEventListener("input", function () {
                const { score, feedback: fb } = zxcvbn(passwordInput.value);

                // Update the strength meter (score is 0 to 4)
                strengthMeter.value = score;

                // Provide feedback
                feedback.innerHTML = fb.suggestions.length
                    ? fb.suggestions.join("<br>")
                    : "Strong password!";
            });
        });
    </script>
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Reset Your Password</h2>

            <?php if (!empty($error_message)): ?>
                <p class="flash-message error"><?php echo htmlspecialchars($error_message); ?></p>
            <?php endif; ?>

            <form action="../controller/AuthController.php" method="post">
                <input type="hidden" name="action" value="password_reset">
                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required>

                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>

                <!-- Password strength meter and feedback -->
                <meter max="4" id="strength-meter"></meter>
                <p id="password-feedback"></p>

                <button type="submit">Reset Password</button>
            </form>
        </div>
    </div>
</body>
</html>

