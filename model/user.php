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

    public function login($username, $password) {
        $query = "SELECT * FROM " . $this->table . " WHERE username = :username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            return $user; // Return user data if login is successful
        }
        return false; // Return false if login fails
    }
}
?>
