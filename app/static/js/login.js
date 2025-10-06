document.getElementById('login-form').addEventListener('submit', function(event) {
    event.preventDefault();

    fetch('/login', {
        method: 'POST',
        body: new FormData(this)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            var otpModal = new bootstrap.Modal(document.getElementById('otpModal'));
            otpModal.show();
            startTimer(120);
        } else {
            alert(data.message || 'Login failed.');
        }
    })
    .catch(error => console.error('Error:', error));
});