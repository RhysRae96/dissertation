<?php
include("./header.php");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Handle MFA form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once '../controller/AuthController.php';
    $authController = new AuthController();

    $mfa_code = $_POST['mfa_code'];

    if ($authController->verifyMfaCode($mfa_code)) {
        $_SESSION['mfa_verified'] = true;
        header("Location: change_password.php");
        exit();
    } else {
        $_SESSION['message'] = "Invalid MFA code. Please try again.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA Verification</title>
    <link rel="stylesheet" href="../styles.css"> <!-- Link to your CSS file -->
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>MFA Verification</h2>

            <!-- Display any messages -->
            <?php if (isset($_SESSION['message'])): ?>
                <p style="color: red;">
                    <?php 
                        echo $_SESSION['message']; 
                        unset($_SESSION['message']);
                    ?>
                </p>
            <?php endif; ?>

            <form action="" method="post">
                <label for="mfa_code">Enter MFA Code:</label>
                <input type="text" id="mfa_code" name="mfa_code" required>

                <button type="submit">Verify</button>
            </form>
        </div>
    </div>
</body>
</html>
