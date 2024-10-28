<?php
require_once "db.php";

class User {
    private $conn;
    private $table = "users";

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    // UUID v4 generation function
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
        // Determine if identifier is an email or username
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
