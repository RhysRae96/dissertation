<?php
require_once "../model/User.php";
require_once "../controller/EmailController.php";
use Sonata\GoogleAuthenticator\GoogleAuthenticator;

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
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
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
    
            // Check if the username or email already exists
            if ($user->userExists($username, $email)) {
                $_SESSION['message'] = "Error: Username or email already in use.";
                header("Location: ../view/register.php");
                exit();
            }
    
            // Generate a unique activation token
            $activationToken = bin2hex(random_bytes(16));
    
            // Register the user and store the activation token
            if ($user->register($username, $email, $password, $activationToken)) {
                // ✅ Send the verification email
                $emailController = new EmailController();
                $emailController->sendVerificationEmail($email, $username, $activationToken);
    
                $_SESSION['message'] = "Registration successful! Please check your email to activate your account.";
                header("Location: ../view/login.php");
                exit();
            } else {
                $_SESSION['message'] = "Error: Registration failed. Please try again.";
                header("Location: ../view/register.php");
                exit();
            }
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
            $userData = $user->getUserByUsernameOrEmail($identifier);
    
            // ✅ Check if the user exists and the password is correct
            if ($userData && password_verify($password, $userData['password'])) {
    
                // ❌ Check if the user is not verified
                if ($userData['is_active'] == 0) {
                    $_SESSION['error_message'] = "Please verify your email before logging in.";
                    header("Location: ../view/login.php");
                    exit();
                }
    
                // ✅ Check if the user has MFA enabled
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
    
                // ✅ Reset failed attempts after successful login
                $user->resetFailedAttempts($identifier);
    
                // ✅ Set session variables
                $_SESSION['user_id'] = $userData['user_id'];
                $_SESSION['username'] = $userData['username'];
                $_SESSION['role'] = $userData['role']; // Store the user's role (1 for User, 2 for Admin)
    
                // ✅ Log the login event
                $this->logEvent($userData['user_id'], $userData['username'], 'Logged In');
    
                // ✅ Redirect based on role
                if ($_SESSION['role'] === 2) {
                    header("Location: ../view/index.php"); 
                } else {
                    header("Location: ../view/index.php"); // Redirect regular user to home page
                }
                exit();
            } else {
                // ❌ Increment failed attempts on incorrect login
                $remainingAttempts = $user->incrementFailedAttempts($identifier);
    
                // ❌ Provide feedback to the user about remaining attempts
                $_SESSION['error_message'] = "Invalid username/email or password. You have $remainingAttempts attempt(s) remaining.";
                $this->logEvent($userData['user_id'], $userData['username'], 'Failed Login');
                header("Location: ../view/login.php");
                exit();
            }
        }
    }
    
    
    public function changePassword() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        if (!isset($_SESSION['user_id'])) {
            $_SESSION['message'] = "Error: User not logged in.";
            header("Location: ../view/change_password.php");
            exit();
        }
    
        if ($_SERVER["REQUEST_METHOD"] == "POST") {
            $currentPassword = $_POST['current_password'];
            $newPassword = $_POST['new_password'];
            $confirmPassword = $_POST['confirm_password'];
            $totpCode = isset($_POST['totp_code']) ? $_POST['totp_code'] : null;
    
            $userID = $_SESSION['user_id'];
            $user = new User();
    
            // Fetch user data to validate the current password and check if MFA is enabled
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
    
            // ✅ Check if the user has MFA enabled
            if ($userData['is_mfa_enabled']) {
                // Verify the MFA code
                $googleAuthenticator = new GoogleAuthenticator();
                if (!$googleAuthenticator->checkCode($userData['totp_secret'], $totpCode)) {
                    $_SESSION['message'] = "Error: Invalid MFA code.";
                    header("Location: ../view/change_password.php");
                    exit();
                }
            }
    
            // Update the password
            if ($user->changePassword($userID, $newPassword)) {
                $_SESSION['message'] = "Success: Your password has been updated. Please log in with your new password.";
                $this->logEvent($_SESSION['user_id'], $_SESSION['username'], 'Changed Password');
                header("Location: ../view/login.php");
                exit();
            } else {
                $_SESSION['message'] = "Error: Could not update password.";
                header("Location: ../view/change_password.php");
                exit();
            }
        }
    }

    public function changeEmail() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    
        if (!isset($_SESSION['user_id'])) {
            $_SESSION['error_message'] = "Error: User not logged in.";
            header("Location: ../view/change_email.php");
            exit();
        }
    
        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            $userId = $_SESSION['user_id'];
            $newEmail = $_POST['new_email'];
            $password = $_POST['password'];
            $totpCode = isset($_POST['totp_code']) ? $_POST['totp_code'] : null;
    
            $user = new User();
            $userData = $user->getUserByID($userId);
    
            // ✅ Verify the current password
            if (!password_verify($password, $userData['password'])) {
                $_SESSION['error_message'] = "Error: Incorrect password.";
                header("Location: ../view/change_email.php");
                exit();
            }
    
            // ✅ If MFA is enabled, verify the MFA code
            if ($userData['is_mfa_enabled']) {
                $googleAuthenticator = new GoogleAuthenticator();
                if (!$googleAuthenticator->checkCode($userData['totp_secret'], $totpCode)) {
                    $_SESSION['error_message'] = "Error: Invalid MFA code.";
                    header("Location: ../view/change_email.php");
                    exit();
                }
            }
    
            // ✅ Update the email address in the database
            if ($user->updateEmail($userId, $newEmail)) {
                $_SESSION['message'] = "Success: Your email address has been updated.";
                $this->logEvent($_SESSION['user_id'], $_SESSION['username'], 'Changed Email');
                header("Location: ../view/change_email.php");
                exit();
            } else {
                $_SESSION['error_message'] = "Error: Could not update email address. Please try again.";
                header("Location: ../view/change_email.php");
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
                $this->logEvent($_SESSION['user_id'], $_SESSION['username'], 'Enabled MFA');
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
    
        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            $userId = $_SESSION['user_id'];
            $totpCode = $_POST['totp_code'];
    
            $user = new User();
    
            // Get the user's TOTP secret from the database
            $userData = $user->getUserByID($userId);
            $userSecret = $userData['totp_secret'];
    
            // Check if the user has a TOTP secret
            if (!$userSecret) {
                $_SESSION['error_message'] = "Error: No TOTP secret found. MFA is not enabled.";
                header("Location: ../view/mfa_setup.php");
                exit();
            }
    
            // Verify the TOTP code
            $googleAuthenticator = new GoogleAuthenticator();
            if (!$googleAuthenticator->checkCode($userSecret, $totpCode)) {
                $_SESSION['error_message'] = "Error: Invalid MFA code. Please try again.";
                header("Location: ../view/mfa_setup.php");
                exit();
            }
    
            // Disable MFA and reset the TOTP secret
            if ($user->disableMfa($userId)) {
                $_SESSION['message'] = "Success: Multi-Factor Authentication has been disabled.";
                $this->logEvent($_SESSION['user_id'], $_SESSION['username'], 'Disabled MFA');
                header("Location: ../view/mfa_setup.php");
                exit();
            } else {
                $_SESSION['error_message'] = "Error: Failed to disable MFA. Please try again.";
                header("Location: ../view/mfa_setup.php");
                exit();
            }
        }
    }

    public function logEvent($userId, $username, $action) {
        $user = new User();
    
        $query = "INSERT INTO logs (user_id, username, action) VALUES (:user_id, :username, :action)";
        $stmt = $user->getConnection()->prepare($query);
        $stmt->bindParam(':user_id', $userId);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':action', $action);
        $stmt->execute();
    }
    
    public function sendChangePasswordEmail() {
       // session_start();
    
        // Ensure the user is logged in
        if (!isset($_SESSION['user_id'])) {
            echo "You must be logged in to change your password.";
            return;
        }
    
        // Get user details
        $user = new User();
        $userData = $user->getUserByID($_SESSION['user_id']);
    
        if ($userData) {
            $changePasswordLink = "http://localhost/dissertation/view/change_password.php";
    
            // Use your existing email controller to send the email
            $emailController = new EmailController();
            $emailController->sendChangePasswordEmail($userData['email'], $userData['username'], $changePasswordLink);
    
            $_SESSION['message'] = "An email with a password change link has been sent to your email.";
            header("Location: ../view/index.php");
            exit();
        } else {
            echo "User data not found.";
        }
    }
    
    
}

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
    } elseif ($_POST['action'] === 'change_email') {
        $authController->changeEmail();
    } elseif ($_POST['action'] === 'send_change_password_email') {
        $authController->sendChangePasswordEmail();
    }
}
