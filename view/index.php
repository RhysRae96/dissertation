<?php
include 'header.php';

if (isset($_SESSION['message'])) {
    echo '<p class="flash-message">' . $_SESSION['message'] . '</p>';
    unset($_SESSION['message']);
}

if (isset($_GET['logout']) && $_GET['logout'] == 1) {
    echo '<p class="flash-message success">You have successfully logged out.</p>';
}

if (isset($_SESSION['error_message'])): ?>
    <div class="alert alert-error">
        <p><?php echo $_SESSION['error_message']; ?></p>
        <button class="close-btn" onclick="this.parentElement.style.display='none';">&times;</button>
    </div>
<?php
    unset($_SESSION['error_message']);
endif;
?>
<?php if (isset($_SESSION['warning_message'])): ?>
    <p class="flash-message warning"><?php echo htmlspecialchars($_SESSION['warning_message']); ?></p>
    <?php unset($_SESSION['warning_message']); ?>
<?php endif; ?>

<!-- Main content -->
<main>
    <h1>Hello World</h1>
    <p>Welcome to our homepage!</p>
    <link rel="stylesheet" href="styles.css">
</main>

</body>
</html>
