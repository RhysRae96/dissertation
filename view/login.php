<?php
include 'header.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <!-- Include the form validation script only -->
    <script src="../script/validation.js"></script>
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
    <h2>Login</h2>
    <form action="../controller/AuthController.php" method="post" onsubmit="return validateLoginForm()">
        <input type="hidden" name="action" value="login">

        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>

        <button type="submit">Login</button>
    </form>
</div>
</div>
</body>
</html>
