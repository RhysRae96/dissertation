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
        $maxAttempts = 3; // Maximum allowed failed attempts
    
        // Increment failed attempts
        $query = "UPDATE users 
                  SET failed_attempts = failed_attempts + 1, 
                      last_failed_attempt = NOW() 
                  WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
    
        // Fetch the updated failed attempts count
        $query = "SELECT failed_attempts FROM users WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
        // Calculate remaining attempts
        $remainingAttempts = $maxAttempts - $result['failed_attempts'];
    
        // Lock the account if the user has reached the max failed attempts
        if ($result['failed_attempts'] >= $maxAttempts) {
            $lockoutDuration = 5 * 60; // Lockout duration in seconds (5 minutes)
            $expiryTime = date('Y-m-d H:i:s', time() + $lockoutDuration);
            $lockQuery = "UPDATE users 
                          SET is_locked = 1, lockout_expiry = :expiryTime 
                          WHERE username = :identifier OR email = :identifier";
            $lockStmt = $this->conn->prepare($lockQuery);
            $lockStmt->bindValue(':expiryTime', $expiryTime);
            $lockStmt->bindValue(':identifier', $identifier);
            $lockStmt->execute();
        }
    
        return $remainingAttempts;
    }
    
    
    public function resetFailedAttempts($identifier) {
        $query = "UPDATE users 
                  SET failed_attempts = 0, 
                      last_failed_attempt = NULL, 
                      is_locked = 0, 
                      lockout_expiry = NULL 
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
        // Fetch lockout data
        $query = "SELECT is_locked, lockout_expiry FROM users WHERE username = :identifier OR email = :identifier";
        $stmt = $this->conn->prepare($query);
        $stmt->bindValue(':identifier', $identifier);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if ($data && $data['is_locked'] == 1) {
            $currentTime = time();
            $lockoutExpiryTime = strtotime($data['lockout_expiry']);
    
            if ($currentTime < $lockoutExpiryTime) {
                // 🚨 Account is still locked
                error_log("Account is still locked for user: $identifier");
                return true;
            } else {
                // ✅ Unlock the account if the lockout period has expired
                $this->resetFailedAttempts($identifier);
                return false;
            }
        }
    
        return false; // Account is not locked
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
