<?php 
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recover Password</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Recover Password</h2>
            <form action="../controller/AuthController.php" method="post">
                <input type="hidden" name="action" value="password_recovery_request">
                
                <label for="email">Enter your email address:</label>
                <input type="email" id="email" name="email" required>
                
                <button type="submit">Submit</button>
            </form>
        </div>
    </div>
</body>
</html>
