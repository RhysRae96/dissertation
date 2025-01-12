<?php
require_once "../model/User.php";

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    $user = new User();

    if ($user->verifyEmail($token)) {
        echo "Your account has been successfully verified!";
        header("Location: ../view/verified.php");
        exit();
    } else {
        echo "Invalid or expired token.";
    }
} else {
    echo "No token provided.";
}
?>
