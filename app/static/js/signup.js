document.getElementById('signup-form').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent default form submission

    var formData = new FormData(this);

    fetch('/signup', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('success', data.message);
            window.location.href = data.redirect; // Redirect to the login page
        } else {
            showToast('error', data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});