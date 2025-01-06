// Validate Login Form
function validateLoginForm() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    // Username can be either a valid username or a valid email
    const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/; // Username: 3-20 chars, letters, numbers, underscores
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Basic email pattern

    if (!usernamePattern.test(username) && !emailPattern.test(username)) {
        alert("Username must be 3-20 characters with only letters, numbers, and underscores, or a valid email.");
        return false;
    }

    if (password.length === 0) {
        alert("Password cannot be empty.");
        return false;
    }

    return true;
}

// Validate Registration Form
function validateRegistrationForm() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const errorContainer = document.getElementById('error-message');

    // Clear previous error messages
    errorContainer.innerHTML = '';

    // Username validation
    const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernamePattern.test(username)) {
        errorContainer.innerHTML = "Username must be 3-20 characters and contain only letters, numbers, and underscores.";
        return false;
    }

    // Email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        errorContainer.innerHTML = "Please enter a valid email address.";
        return false;
    }

    // Password validations
    if (password.length < 8 || password.length > 64) {
        errorContainer.innerHTML = "Password must be between 8 and 64 characters.";
        return false;
    }

    if (password !== confirmPassword) {
        errorContainer.innerHTML = "Passwords do not match.";
        return false;
    }

    return true;
}

// Validate Password Strength
function validatePasswordStrength() {
    const password = document.getElementById('password').value;
    const strengthMeter = document.getElementById('strength-meter');
    const feedback = document.getElementById('password-feedback');

    // Use zxcvbn library to calculate password strength
    const { score, feedback: fb } = zxcvbn(password);

    // Update the strength meter based on score (0 to 4)
    strengthMeter.value = score;

    // Provide feedback on the password
    feedback.innerHTML = fb.suggestions.length ? fb.suggestions.join('<br>') : 'Strong password!';
}
