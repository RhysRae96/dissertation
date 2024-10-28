function validatePasswordStrength() {
    const password = document.getElementById('password').value;
    const strengthMeter = document.getElementById('strength-meter');
    const feedback = document.getElementById('password-feedback');

    const { score, feedback: fb } = zxcvbn(password);
    
    // Update the strength meter based on score (0 to 4)
    strengthMeter.value = score;

    // Provide feedback on the password
    feedback.innerHTML = fb.suggestions.length ? fb.suggestions.join('<br>') : 'Strong password!';
}
