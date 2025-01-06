<?php
include("./header.php");

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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password</title>
    <link rel="stylesheet" href="../styles.css"> <!-- Link to your CSS file -->
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Change Password</h2>

            <!-- Display any messages -->
            <?php if (isset($_SESSION['message'])): ?>
                <p style="color: <?php echo strpos($_SESSION['message'], 'Success') === 0 ? 'green' : 'red'; ?>;">
                    <?php 
                        echo $_SESSION['message']; 
                        unset($_SESSION['message']);
                    ?>
                </p>
            <?php endif; ?>

            <form action="../controller/AuthController.php" method="post">
                <input type="hidden" name="action" value="change_password">

                <label for="current_password">Current Password:</label>
                <input type="password" id="current_password" name="current_password" required>

                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required>

                <label for="confirm_password">Confirm New Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>

                <button type="submit">Change Password</button>
            </form>
        </div>
    </div>
</body>
</html>
