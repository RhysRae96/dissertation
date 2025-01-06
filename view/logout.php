<?php
session_start();
session_unset();
session_destroy();

// Redirect to homepage with a logout success message
header("Location: index.php?logout=1");
exit();
?>
