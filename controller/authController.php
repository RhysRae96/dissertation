<?php
require_once "../model/User.php";

class AuthController {
    // Validates password based on length and allows all characters
    private function validatePassword($password) {
        if (mb_strlen($password, 'UTF-8') < 8) {
            throw new Exception("Password must be at least 8 characters long.");
        }
        if (mb_strlen($password, 'UTF-8') > 64) {
            throw new Exception("Password must not exceed 64 characters.");
        }
        return true;
    }

    public function register() {
        session_start();
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $username = $_POST['username'];
            $email = $_POST['email'];
            $password = $_POST['password'];
            $confirmPassword = $_POST['confirm_password'];
    
            // Validate password confirmation
            if ($password !== $confirmPassword) {
                $_SESSION['message'] = "Error: Passwords do not match.";
                header("Location: ../view/register.php");
                exit();
            }
    
            $user = new User();
    
            // Validate password
            try {
                $this->validatePassword($password);
            } catch (Exception $e) {
                $_SESSION['message'] = "Error: " . $e->getMessage();
                header("Location: ../view/register.php");
                exit();
            }
    
            // Check if the username or email already exists
            if ($user->userExists($username, $email)) {
                $_SESSION['message'] = "Error: Username or email already in use. Please choose another.";
                header("Location: ../view/register.php");
                exit();
            }
    
            // Continue with registration if username and email are unique
            if ($user->register($username, $email, $password)) {
                $_SESSION['message'] = "Success: Registration complete. Please log in.";
                header("Location: ../view/login.php");
                exit();
            } else {
                $_SESSION['message'] = "Error: Could not register user. Please try again.";
                header("Location: ../view/register.php");
                exit();
            }
        } else {
            require "../view/register.php";
        }
    }

    public function login() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $identifier = $_POST['username'];
            $password = $_POST['password'];
    
            $user = new User();
            $userData = $user->getUserByUsernameOrEmail($identifier);
    
            // Define throttling parameters
            $maxAttempts = 3; // Maximum allowed failed attempts
            $lockoutTime = 5 * 60; // Lockout duration in seconds (e.g., 5 minutes)
    
            // Retrieve failed attempts data
            $failedAttemptsData = $user->getFailedAttempts($identifier);
            $failedAttempts = $failedAttemptsData['failed_attempts'] ?? 0;
            $lastFailedAttempt = $failedAttemptsData['last_failed_attempt'] ?? null;
    
            // Check for lockout
            if ($failedAttempts >= $maxAttempts) {
                $lastAttemptTime = strtotime($lastFailedAttempt);
                $currentTime = time();
    
                if (($currentTime - $lastAttemptTime) < $lockoutTime) {
                    $remainingLockoutTime = $lockoutTime - ($currentTime - $lastAttemptTime);
                    $_SESSION['error_message'] = "Too many failed attempts. Please try again after " . ceil($remainingLockoutTime / 60) . " minutes.";
                    header("Location: ../view/login.php");
                    exit();
                } else {
                    // Reset failed attempts if lockout period has expired
                    $user->resetFailedAttempts($identifier);
                    $failedAttempts = 0; // Reset the counter in the current context
                }
            }
    
            // Validate user credentials
            if (!$userData || !password_verify($password, $userData['password'])) {
                // Increment failed attempts on incorrect credentials
                $user->incrementFailedAttempts($identifier);
                $remainingAttempts = $maxAttempts - ($failedAttempts + 1);
    
                if ($remainingAttempts > 0) {
                    $_SESSION['error_message'] = "Invalid username/email or password. You have $remainingAttempts attempt(s) remaining before your account is locked.";
                } else {
                    $_SESSION['error_message'] = "Invalid username/email or password. Your account has been locked due to multiple failed login attempts. Please try again after " . ($lockoutTime / 60) . " minutes.";
                }
    
                header("Location: ../view/login.php");
                exit();
            }
    
            // Successful login
            // Reset failed attempts after successful login
            $user->resetFailedAttempts($identifier);
    
            // Set session variables and redirect the user
            $_SESSION['user_id'] = $userData['user_id'];
            $_SESSION['username'] = $userData['username'];
    
            header("Location: ../view/index.php");
            exit();
        } else {
            require "../view/login.php";
        }
    }
    
    
    
    public function changePassword() {
        session_start();
        if (!isset($_SESSION['user_id'])) {
            $_SESSION['message'] = "Error: User not logged in.";
            header("Location: ../view/change_password.php");
            exit();
        }
    
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $currentPassword = $_POST['current_password'];
            $newPassword = $_POST['new_password'];
            $confirmPassword = $_POST['confirm_password'];
    
            $userID = $_SESSION['user_id'];
            $user = new User();
    
            // Fetch user data to validate the current password
            $userData = $user->getUserByID($userID);
    
            // Check if the current password is correct
            if (!password_verify($currentPassword, $userData['password'])) {
                $_SESSION['message'] = "Error: Current password is incorrect.";
                header("Location: ../view/change_password.php");
                exit();
            }
    
            // Check if the new password is the same as the current password
            if (password_verify($newPassword, $userData['password'])) {
                $_SESSION['message'] = "Error: New password cannot be the same as the current password.";
                header("Location: ../view/change_password.php");
                exit();
            }
    
            // Validate new password
            try {
                $this->validatePassword($newPassword);
            } catch (Exception $e) {
                $_SESSION['message'] = "Error: " . $e->getMessage();
                header("Location: ../view/change_password.php");
                exit();
            }
    
            // Check if the new password matches the confirmation
            if ($newPassword !== $confirmPassword) {
                $_SESSION['message'] = "Error: New passwords do not match.";
                header("Location: ../view/change_password.php");
                exit();
            }
    
            // Update the password
            if ($user->changePassword($userID, $newPassword)) {
                // Destroy the session and redirect to the login page with a success message
                session_unset();
                session_destroy();
                session_start();
                $_SESSION['message'] = "Success: Your password has been updated. Please log in with your new password.";
                header("Location: ../view/login.php");
                exit();
            } else {
                $_SESSION['message'] = "Error: Could not update password.";
                header("Location: ../view/change_password.php");
                exit();
            }
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
    } elseif ($_POST['action'] === 'change_password') {
        $authController->changePassword();
    }
}
?>
