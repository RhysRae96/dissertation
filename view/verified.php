<?php include('header.php'); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Verified</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body {
            background-color: #f3f4f6;
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 600px;
            margin: 50px auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .container h1 {
            font-size: 36px;
            color: #4CAF50;
            margin-bottom: 20px;
        }

        .container p {
            font-size: 18px;
            color: #333333;
            margin-bottom: 30px;
        }

        .btn {
            display: inline-block;
            background-color: #4CAF50;
            color: #ffffff;
            padding: 12px 20px;
            border-radius: 5px;
            font-size: 18px;
            text-decoration: none;
            transition: background-color 0.3s ease;
        }

        .btn:hover {
            background-color: #45a049;
        }

        .icon {
            font-size: 80px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🎉</div>
        <h1>Congratulations!</h1>
        <p>Your account has been successfully verified. You can now log in.</p>
        <a href="login.php" class="btn">Go to Login</a>
    </div>
</body>
</html>
