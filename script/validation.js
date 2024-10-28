// validation.js

function validateLoginForm() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/;
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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

function validateRegistrationForm() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernamePattern.test(username)) {
        alert("Username must be 3-20 characters and contain only letters, numbers, and underscores.");
        return false;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        alert("Please enter a valid email address.");
        return false;
    }

    if (password.length === 0) {
        alert("Password cannot be empty.");
        return false;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return false;
    }

    return true;
}
