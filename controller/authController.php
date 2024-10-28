<?php
require_once "../model/User.php";

class AuthController {

    // Validates password based on strength requirements
    private function validatePassword($password) {
        // Check password length
        if (strlen($password) < 8) {
            throw new Exception("Password must be at least 8 characters long.");
        }
        if (strlen($password) > 64) {
            throw new Exception("Password must not exceed 64 characters.");
        }
        // Additional checks can be added here if needed (e.g., checking for breached passwords)
        return true;
    }

public function register() {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];

        $user = new User();

        // Check if the username or email already exists
        if ($user->userExists($username, $email)) {
            echo "Error: Username or email already in use. Please choose another.";
            return;
        }

        // Continue with registration if username and email are unique
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
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $identifier = $_POST['username']; // Can be either username or email
            $password = $_POST['password'];
    
            $user = new User();
            $authenticatedUser = $user->login($identifier, $password);
    
            if ($authenticatedUser) {
                session_start();
                $_SESSION['user_id'] = $authenticatedUser['user_id']; // Store user ID in session
                $_SESSION['username'] = $authenticatedUser['username']; // Store username in session
                header("Location: ../view/index.php"); // Redirect to homepage or another page
                exit();
            } else {
                echo "Invalid username/email or password.";
            }
        } else {
            require "../view/login.php";
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
