<?php
require_once "db.php";
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ✅ Keep a single User class declaration
use Sonata\GoogleAuthenticator\GoogleAuthenticator;
use Sonata\GoogleAuthenticator\GoogleQrUrl;

class User {
    private $conn;
    private $table = "users";

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    // UUID generation function
    private function generateUUID() {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    public function register($username, $email, $password) {
        $userID = $this->generateUUID();
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        $query = "INSERT INTO " . $this->table . " (user_id, username, email, password) VALUES (:user_id, :username, :email, :password)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $userID);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashedPassword);

        return $stmt->execute();
    }

    public function userExists($username, $email) {
        $query = "SELECT * FROM " . $this->table . " WHERE username = :username OR email = :email";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        return $stmt->rowCount() > 0;
    }

    public function login($identifier, $password) {
        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            $query = "SELECT * FROM " . $this->table . " WHERE email = :identifier";
        } else {
            $query = "SELECT * FROM " . $this->table . " WHERE username = :identifier";
        }

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':identifier', $identifier);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
        return false;
    }

    public function getUserByID($userID) {
        $query = "SELECT * FROM " . $this->table . " WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':user_id', $userID, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function incrementFailedAttempts($identifier) {
        $maxAttempts = 3;
        $query = "UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_attempt = NOW() WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();

        $query = "SELECT failed_attempts FROM users WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        $remainingAttempts = $maxAttempts - $result['failed_attempts'];

        if ($result['failed_attempts'] >= $maxAttempts) {
            $lockoutDuration = 5 * 60;
            $expiryTime = date('Y-m-d H:i:s', time() + $lockoutDuration);
            $lockQuery = "UPDATE users SET is_locked = 1, lockout_expiry = :expiryTime WHERE username = :identifier OR email = :identifier";
            $lockStmt = $this->conn->prepare($lockQuery);
            $lockStmt->bindValue(':expiryTime', $expiryTime);
            $lockStmt->bindValue(':identifier', $identifier);
            $lockStmt->execute();
        }

        return $remainingAttempts;
    }

    public function resetFailedAttempts($identifier) {
        $query = "UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL, is_locked = 0, lockout_expiry = NULL WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
    }

    public function isAccountLocked($identifier) {
        $query = "SELECT is_locked, lockout_expiry FROM users WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data && $data['is_locked'] == 1) {
            $currentTime = time();
            $lockoutExpiryTime = strtotime($data['lockout_expiry']);
            if ($currentTime < $lockoutExpiryTime) {
                error_log("Account is still locked for user: $identifier");
                return true;
            } else {
                $this->resetFailedAttempts($identifier);
                return false;
            }
        }
        return false;
    }

    public function getUserByUsernameOrEmail($identifier) {
        $query = "SELECT user_id, username, password, is_mfa_enabled FROM " . $this->table . " WHERE username = :identifier OR email = :identifier LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    

    // ✅ MFA Methods
    public function generateTotpSecret() {
        $g = new GoogleAuthenticator();
        $secret = $g->generateSecret();
    
        // Save the secret to the database
        $query = "UPDATE users SET totp_secret = :secret WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':secret', $secret);
        $stmt->bindValue(':user_id', $_SESSION['user_id']);
        $stmt->execute();
    
        return $secret;
    }
    

    public function getTotpSecret($userId) {
        $query = "SELECT totp_secret FROM users WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':user_id', $userId);
        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['totp_secret'];
    }

    public function verifyTotpCode($code, $userId) {
        if (empty($code)) {
            return false; // If the code is empty, return false immediately
        }
    
        $g = new GoogleAuthenticator();
        $secret = $this->getTotpSecret($userId);
    
        return $g->checkCode($secret, $code);
    }
    

    public function getQrCodeUrl($username, $secret) {
        return GoogleQrUrl::generate($username, $secret, 'YourWebsiteName');
    }

    public function enableMfa($userId) {
        $query = "UPDATE users SET is_mfa_enabled = 1 WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':user_id', $userId);
        $stmt->execute();
    }
    
    
//EXPIRMENTING
    public function generateEmailVerificationToken($userID) {
        $token = bin2hex(random_bytes(16)); // Generate a secure random token
        $expires = date("Y-m-d H:i:s", strtotime("+1 day")); // Token expiration time, e.g., 24 hours
    
        $query = "INSERT INTO email_verifications (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $userID);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':expires_at', $expires);
    
        $stmt->execute();
        return $token; // Return token to send in verification email
    }
    
    public function verifyEmail($token) {
        $query = "SELECT * FROM email_verifications WHERE token = :token AND expires_at > NOW()";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        $verification = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if ($verification) {
            $userID = $verification['user_id'];
            // Update the user's email verification status
            $updateQuery = "UPDATE users SET is_email_verified = 1 WHERE user_id = :user_id";
            $updateStmt = $this->conn->prepare($updateQuery);
            $updateStmt->bindParam(':user_id', $userID);
            $updateStmt->execute();
    
            // Remove the token once verified
            $deleteQuery = "DELETE FROM email_verifications WHERE token = :token";
            $deleteStmt = $this->conn->prepare($deleteQuery);
            $deleteStmt->bindParam(':token', $token);
            $deleteStmt->execute();
    
            return true; // Verification successful
        }
        return false; // Verification failed
    }
}
?>
