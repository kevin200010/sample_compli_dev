function scrollToFormBox() {
    document.getElementById('form-box').scrollIntoView({ behavior: 'smooth' });
}
function toggleForm(event) {
    event.preventDefault(); // Prevent default behavior of anchor tag
    
    var loginForm = document.getElementById('login-form');
    var signupForm = document.getElementById('signup-form');
    var formTitle = document.getElementById('form-title');
    var toggleFormText = document.getElementById('toggle-form').getElementsByTagName('a')[0];
    var formBox = document.getElementById('form-box');
    var welcomeText = document.getElementById('welcome-text');
    var toggleFormP = document.getElementById('toggle-form');

    
    loginForm.classList.remove('show');
    signupForm.classList.remove('show');
    formTitle.classList.remove('show');
    welcomeText.classList.remove('show');
    toggleFormP.classList.remove('show');

    setTimeout(function () {
        if (loginForm.classList.contains('hidden')) {
            // Show login form
            signupForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            formTitle.textContent = "AWS Account Login";
            toggleFormText.textContent = "Need to sign up? Click here";
            formBox.classList.remove('expanded');
        } else {
            // Show signup form
            loginForm.classList.add('hidden');
            signupForm.classList.remove('hidden');
            formTitle.textContent = "Enter your information below";
            toggleFormText.textContent = "Already have an account? Click here";
            formBox.classList.add('expanded');
        }

        
        setTimeout(function () {
            loginForm.classList.add('show');
            signupForm.classList.add('show');
            formTitle.classList.add('show');
            welcomeText.classList.add('show');
            toggleFormP.classList.add('show');

            // Additional logic to show the sign-up button
            var signUpButton = document.querySelector("#signup-form button[type='submit']");
            if (signupForm.classList.contains('show')) {
                signUpButton.classList.add('show');
            } else {
                signUpButton.classList.remove('show');
            }
        }, 50); 
    }, 500); 
}
