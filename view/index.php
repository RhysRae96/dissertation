<?php
include 'header.php';
if (isset($_GET['logout']) && $_GET['logout'] == 1) {
    echo '<p class="flash-message success">You have successfully logged out.</p>';
}
?>

<!-- Main content -->
<main>
    <h1>Hello World</h1>
    <p>Welcome to our homepage!</p>
</main>

</body>
</html>
