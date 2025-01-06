<?php
require_once "db.php";

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
        // Ensure a UUID is generated for the user ID
        $userID = $this->generateUUID();

        // Check if UUID was generated successfully
        if (empty($userID)) {
            throw new Exception("Failed to generate a unique User ID.");
        }

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
    
        // Return true if a record exists, false otherwise
        return $stmt->rowCount() > 0;
    }

    public function login($identifier, $password) {
        // Determine if id is an email or username
        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            $query = "SELECT * FROM " . $this->table . " WHERE email = :identifier";
        } else {
            $query = "SELECT * FROM " . $this->table . " WHERE username = :identifier";
        }
    
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':identifier', $identifier);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
        // Verify password and check if user was found
        if ($user && password_verify($password, $user['password'])) {
            return $user; // Return user data if login is successful
        }
        return false; // Return false if login fails
    }

    public function getUserByID($userID) {
        $query = "SELECT * FROM " . $this->table . " WHERE user_id = :user_id";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':user_id', $userID, PDO::PARAM_INT);
        $stmt->execute();
    
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function changePassword($userID, $newPassword) {
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $query = "UPDATE " . $this->table . " SET password = :password WHERE user_id = :user_id";
    
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':password', $hashedPassword);
        $stmt->bindValue(':user_id', $userID, PDO::PARAM_INT);
    
        return $stmt->execute();
    }
 
    public function incrementFailedAttempts($identifier) {
        // Increment failed attempts and update the last_failed_attempt timestamp
        $query = "UPDATE users 
                  SET failed_attempts = failed_attempts + 1, 
                      last_failed_attempt = NOW()
                  WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
    
        // Check if failed attempts have reached the maximum
        $maxAttempts = 3;
        $attempts = $this->getFailedAttempts($identifier)['failed_attempts'];
        if ($attempts >= $maxAttempts) {
            // Set the account as locked and record the lockout time
            $lockQuery = "UPDATE users 
                          SET is_locked = TRUE, lockout_time = NOW()
                          WHERE username = :identifier OR email = :identifier";
            $lockStmt = $this->conn->prepare($lockQuery);
            $lockStmt->bindValue(':identifier', $identifier);
            $lockStmt->execute();
        }
    }
    
    
    public function resetFailedAttempts($identifier) {
        $query = "UPDATE users 
                  SET failed_attempts = 0, 
                      last_failed_attempt = NULL, 
                      is_locked = FALSE, 
                      lockout_time = NULL
                  WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
    }
    
    public function getFailedAttempts($identifier) {
        $query = "SELECT failed_attempts, last_failed_attempt, is_locked, lockout_time 
                  FROM users 
                  WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    public function isAccountLocked($identifier) {
        $lockoutDuration = 5 * 60; // 5 minutes
        $data = $this->getFailedAttempts($identifier);
        if ($data['is_locked']) {
            $lockoutTime = strtotime($data['lockout_time']);
            $currentTime = time();
            if (($currentTime - $lockoutTime) < $lockoutDuration) {
                // Account is still locked
                return true;
            } else {
                // Lockout period has expired; unlock the account
                $this->resetFailedAttempts($identifier);
                return false;
            }
        }
        return false;
    }
    
    
    
    public function getUserByUsernameOrEmail($identifier) {
        $query = "SELECT * FROM " . $this->table . " WHERE username = :identifier OR email = :identifier LIMIT 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
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
