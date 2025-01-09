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
            $totpCode = isset($_POST['totp_code']) ? $_POST['totp_code'] : null;
    
            $user = new User();
    
            // Check if the account is locked BEFORE proceeding
            if ($user->isAccountLocked($identifier)) {
                $_SESSION['error_message'] = "Your account is locked due to too many failed login attempts. Please try again after 5 minutes.";
                header("Location: ../view/login.php");
                exit();
            }
    
            // Fetch user data and verify the password
            $userData = $user->getUserByUsernameOrEmail($identifier);
    
            // ✅ Check if the user exists and the password is correct
            if ($userData && password_verify($password, $userData['password'])) {
                // Check if the user has MFA enabled
                if ($userData['is_mfa_enabled']) {
                    $_SESSION['mfa_required'] = true;
    
                    // ✅ If MFA is enabled, verify the authentication code
                    if (!$user->verifyTotpCode($totpCode, $userData['user_id'])) {
                        $_SESSION['error_message'] = "Invalid authentication code.";
                        header("Location: ../view/login.php");
                        exit();
                    }
                } else {
                    $_SESSION['mfa_required'] = false;
                }
    
                // Reset failed attempts after successful login
                $user->resetFailedAttempts($identifier);
    
                // ✅ Set session variables and redirect the user
                $_SESSION['user_id'] = $userData['user_id'];
                $_SESSION['username'] = $userData['username'];
    
                // ✅ Clear the `mfa_required` session variable after successful login
                unset($_SESSION['mfa_required']);
    
                header("Location: ../view/index.php");
                exit();
            } else {
                // Increment failed attempts on incorrect login
                $remainingAttempts = $user->incrementFailedAttempts($identifier);
    
                // Provide feedback to the user about remaining attempts
                $_SESSION['error_message'] = "Invalid username/email or password. You have $remainingAttempts attempt(s) remaining.";
                header("Location: ../view/login.php");
                exit();
            }
        } else {
            // ✅ Check if MFA is required before showing the login form
            $isMfaEnabled = false;
            if (isset($_SESSION['username'])) {
                $user = new User();
                $userData = $user->getUserByUsernameOrEmail($_SESSION['username']);
                $isMfaEnabled = $userData['is_mfa_enabled'];
            }
    
            $_SESSION['mfa_required'] = $isMfaEnabled;
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
    public function verifyTotp() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $userId = $_SESSION['user_id'];
            $totpCode = $_POST['totp_code'];
    
            $user = new User();
    
            // Get the user's TOTP secret from the database
            $userData = $user->getUserByID($userId);
            if (!$userData['totp_secret']) {
                $_SESSION['error_message'] = "TOTP secret not found. Please set up MFA.";
                header("Location: ../view/mfa_setup.php");
                exit();
            }
    
            // Verify the TOTP code
            if ($user->verifyTotpCode($totpCode, $userId)) {
                // ✅ Success: Enable MFA for the user
                $user->enableMfa($userId);
                $_SESSION['message'] = "Multi-Factor Authentication enabled successfully.";
                header("Location: ../view/dashboard.php");
            } else {
                // ❌ Failure: TOTP code is incorrect
                $_SESSION['error_message'] = "Invalid authentication code. Please try again.";
                header("Location: ../view/mfa_setup.php");
            }
    
            exit();
        }
    }

    public function disableMfa() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        $userId = $_SESSION['user_id'];
        $user = new User();
    
        if ($user->disableMfa($userId)) {
            $_SESSION['flash_message'] = "You have successfully disabled Multi-Factor Authentication.";
            header("Location: ../view/dashboard.php");
            exit();
        } else {
            $_SESSION['error_message'] = "Failed to disable MFA. Please try again.";
            header("Location: ../view/mfa_setup.php");
            exit();
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
    } elseif ($_POST['action'] === 'verify_totp') {
        $authController->verifyTotp();
    } elseif ($_POST['action'] === 'disable_mfa') {
        $authController->disableMfa();
    }
}

