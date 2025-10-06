
function getReport(accountAlias) {
    var form = document.getElementById('sidebar-action-form');

    // Clear any existing action input
    var existingActionInput = form.querySelector('input[name="action"]');
    if (existingActionInput) {
        form.removeChild(existingActionInput);
    }

    // Clear any existing account input
    var existingAccountInput = form.querySelector('input[name="account"]');
    if (existingAccountInput) {
        form.removeChild(existingAccountInput);
    }

    // Add new action input
    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'pci_report'; // Ensure this is correct
    form.appendChild(actionInput);

    // Add new account input
    var accountInput = document.createElement('input');
    accountInput.type = 'hidden';
    accountInput.name = 'account';
    accountInput.value = accountAlias;
    form.appendChild(accountInput);

    form.submit();
}

function selectInfo(accountAlias) {

    var form = document.getElementById('sidebar-action-form');

    // Clear any existing action input
    var existingActionInput = form.querySelector('input[name="action"]');
    if (existingActionInput) {
        form.removeChild(existingActionInput);
    }

    // Clear any existing account input
    var existingAccountInput = form.querySelector('input[name="account"]');
    if (existingAccountInput) {
        form.removeChild(existingAccountInput);
    }

    // Add new action input
    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'info'; // Ensure this is correct
    form.appendChild(actionInput);

    // Add new account input
    var accountInput = document.createElement('input');
    accountInput.type = 'hidden';
    accountInput.name = 'account';
    accountInput.value = accountAlias;
    form.appendChild(accountInput);

    form.submit();
}

function getHipaaReport(accountAlias) {

    var form = document.getElementById('sidebar-action-form');

    // Clear any existing action input
    var existingActionInput = form.querySelector('input[name="action"]');
    if (existingActionInput) {
        form.removeChild(existingActionInput);
    }

    // Clear any existing account input
    var existingAccountInput = form.querySelector('input[name="account"]');
    if (existingAccountInput) {
        form.removeChild(existingAccountInput);
    }

    // Add new action input
    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'hipaa_report'; // Ensure this is correct
    form.appendChild(actionInput);

    // Add new account input
    var accountInput = document.createElement('input');
    accountInput.type = 'hidden';
    accountInput.name = 'account';
    accountInput.value = accountAlias;
    form.appendChild(accountInput);

    form.submit();
}


function selectAccount(accountAlias) {
    var form = document.getElementById('sidebar-action-form');

    // Clear any existing action input
    var existingActionInput = form.querySelector('input[name="action"]');
    if (existingActionInput) {
        form.removeChild(existingActionInput);
    }

    // Clear any existing account input
    var existingAccountInput = form.querySelector('input[name="account"]');
    if (existingAccountInput) {
        form.removeChild(existingAccountInput);
    }

    // Add new action input
    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'select';
    form.appendChild(actionInput);

    // Add new account input
    var accountInput = document.createElement('input');
    accountInput.type = 'hidden';
    accountInput.name = 'account';
    accountInput.value = accountAlias;
    form.appendChild(accountInput);

    form.submit();
}

function resetForm(formId) {
    document.getElementById(formId).reset();
}


document.addEventListener('DOMContentLoaded', function() {
    // Function to show loader
    function showLoader() {
        document.querySelector('.loader-container').style.display = 'flex';
    }

    // Function to hide loader after a static 20 seconds
    function hideLoader() {
        setTimeout(function() {
            document.querySelector('.loader-container').style.display = 'none';
        }, 20000); // 20000 milliseconds = 20 seconds
    }

    function submitForm(actionValue, accountAlias) {
        showLoader(); // Show the loader

        var form = document.getElementById('sidebar-action-form');

        // Clear any existing action input
        var existingActionInput = form.querySelector('input[name="action"]');
        if (existingActionInput) {
            form.removeChild(existingActionInput);
        }

        // Clear any existing account input
        var existingAccountInput = form.querySelector('input[name="account"]');
        if (existingAccountInput) {
            form.removeChild(existingAccountInput);
        }

        // Add new action input
        var actionInput = document.createElement('input');
        actionInput.type = 'hidden';
        actionInput.name = 'action';
        actionInput.value = actionValue;
        form.appendChild(actionInput);

        // Add new account input
        var accountInput = document.createElement('input');
        accountInput.type = 'hidden';
        accountInput.name = 'account';
        accountInput.value = accountAlias;
        form.appendChild(accountInput);

        // Submit the form using AJAX
        fetch(form.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(new FormData(form)).toString()
        })
        .then(response => response.json())
        .then(data => {
            console.log('Success:', data);
            // Handle successful response if needed
        })
        .catch(error => {
            console.error('Error:', error);
        })
        .finally(() => {
            hideLoader(); // Hide the loader after 20 seconds
        });
    }

    document.querySelectorAll('.sidebar a').forEach(function(element) {
        element.addEventListener('click', function(event) {
            event.preventDefault();
            var actionValue;
            var accountAlias = '{{ account }}';

            if (this.id === 'getReportButton') {
                actionValue = 'pci_report';
            } else if (this.id === 'getHipaaReportButton') {
                actionValue = 'hipaa_report';
            } else {
                actionValue = 'select';
            }

            submitForm(actionValue, accountAlias);
        });
    });
});