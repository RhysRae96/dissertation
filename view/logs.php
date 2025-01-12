<?php
require_once "../model/User.php";
include("./header.php");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect to login if the user is not logged in or not an admin
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user = new User();
$actionFilter = isset($_GET['action_filter']) ? $_GET['action_filter'] : null;
$logs = $user->getLogs($actionFilter);

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 2) {
    $_SESSION['error_message'] = "You do not have permission to access this page.";
    header("Location: index.php");
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Logs</title>
    <link rel="stylesheet" href="../styles.css">
</head>
<body class="form-page">
    <div class="form-wrapper">
        <div class="form-container">
            <h2>Website Logs</h2>

            <!-- Filter Form -->
            <form method="get" action="logs.php">
                <label for="action_filter">Filter by Action:</label>
                <select name="action_filter" id="action_filter">
                    <option value="">All Actions</option>
                    <option value="Logged In" <?php if ($actionFilter === 'Logged In') echo 'selected'; ?>>Logged In</option>
                    <option value="Logged Out" <?php if ($actionFilter === 'Logged Out') echo 'selected'; ?>>Logged Out</option>
                    <option value="Enabled MFA" <?php if ($actionFilter === 'Enabled MFA') echo 'selected'; ?>>Enabled MFA</option>
                    <option value="Disabled MFA" <?php if ($actionFilter === 'Disabled MFA') echo 'selected'; ?>>Disabled MFA</option>
                    <option value="Changed Email" <?php if ($actionFilter === 'Changed Email') echo 'selected'; ?>>Changed Email</option>
                    <option value="Changed Password" <?php if ($actionFilter === 'Changed Password') echo 'selected'; ?>>Changed Password</option>
                </select>
                <button type="submit">Filter</button>
            </form>

            <!-- Logs Table -->
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Action</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (count($logs) > 0): ?>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($log['username']); ?></td>
                                <td><?php echo htmlspecialchars($log['action']); ?></td>
                                <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="3">No logs found for the selected action.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
