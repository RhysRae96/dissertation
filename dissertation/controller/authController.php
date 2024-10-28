<?php
require_once "../model/user.php";

class AuthController {
    public function register() {
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $username = $_POST['username'];
            $email = $_POST['email'];
            $password = $_POST['password'];

            $user = new User();
            if ($user->register($username, $email, $password)) {
                header("Location: ../view/index.php"); // Redirect to homepage or success page
                exit();
            } else {
                echo "Error: Could not register user.";
            }
        } else {
            require "../view/register.php";
        }
    }

    public function login() {
        $username = $_POST['username'];
        $password = $_POST['password'];

        $user = new User();
        $authenticatedUser = $user->login($username, $password);

        if ($authenticatedUser) {
            session_start();
            $_SESSION['user_id'] = $authenticatedUser['id']; // Store user ID in session
            header("Location: ../view/index.php"); // Redirect to homepage
            exit();
        } else {
            echo "Invalid username or password.";
        }
    }
}

// Main logic to handle actions based on `action` input
if (isset($_POST['action'])) {
    $authController = new AuthController();
    if ($_POST['action'] === 'register') {
        $authController->register();
    } elseif ($_POST['action'] === 'login') {
        $authController->login();
    }
}
?>
