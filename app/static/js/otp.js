let timerInterval;

function startTimer(duration) {
    let timer = duration, minutes, seconds;
    const timerDisplay = document.getElementById('timer');
    clearInterval(timerInterval);
    timerInterval = setInterval(function () {
        minutes = parseInt(timer / 60, 10);
        seconds = parseInt(timer % 60, 10);

        minutes = minutes < 10 ? "0" + minutes : minutes;
        seconds = seconds < 10 ? "0" + seconds : seconds;

        timerDisplay.textContent = minutes + ":" + seconds;

        if (--timer < 0) {
            clearInterval(timerInterval);
            alert('OTP expired, please request a new one.');
            var otpModal = bootstrap.Modal.getInstance(document.getElementById('otpModal'));
            otpModal.hide();
        }
    }, 1000);
}

document.getElementById('sendEmailButton').addEventListener('click', function() {
    fetch('/send_email', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            startTimer(120);  // Reset timer to 2 minutes
        } else {
            alert('Failed to send email.');
        }
    })
    .catch(error => console.error('Error:', error));
});

document.getElementById('otpForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const otp = document.getElementById('otp').value;

    fetch('/verify_otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ otp: otp })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = data.redirect;
        } else {
            alert(data.message || 'Invalid OTP.');
        }
    })
    .catch(error => console.error('Error:', error));
});