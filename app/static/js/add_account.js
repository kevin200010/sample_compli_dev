document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('add-account-form').addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent default form submission

        var formData = new FormData(this); // Serialize form data
        var email = {{ email }}; // Get the email value from the template

        fetch('/add_account/' + email, {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('success', data.message);
                window.location.href = data.redirect; // Redirect to the user's page
            } else {
                showToast('error', data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});