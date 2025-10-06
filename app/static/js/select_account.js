showForm('select_remove')


function showLoader() {
    document.getElementById('loader').style.display = 'flex';
    setTimeout(function() {
        hideLoader();
    }, 25000); // 25000 milliseconds = 25 seconds
}

function hideLoader() {
    document.getElementById('loader').style.display = 'none';
}



function selectAccount(accountAlias) {
    var form = document.getElementById('manage-account-form');

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

function removeAccount(accountAlias) {
    var form = document.getElementById('manage-account-form');
    var actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'remove';
    form.appendChild(actionInput);

    var accountInput = document.createElement('input');
    accountInput.type = 'hidden';
    accountInput.name = 'account';
    accountInput.value = accountAlias;
    form.appendChild(accountInput);

    form.submit();
    form.reset();
}


function showForm(formType) {
    var addForm = document.getElementById('add-account-form');
    var updateForm = document.getElementById('update-account-form');
    var selectRemoveForm = document.getElementById('manage-account-form');
    var addBtn = document.getElementById('add-account-btn');
    var selectRemoveBtn = document.getElementById('manage-account-btn');

    addForm.classList.add('fade');
    updateForm.classList.add('fade');
    selectRemoveForm.classList.add('fade');

    setTimeout(function() {
        addForm.classList.add('hidden');
        updateForm.classList.add('hidden');
        selectRemoveForm.classList.add('hidden');

        addBtn.style.display = 'none';
        selectRemoveBtn.style.display = 'none';

        if (formType === 'add') {
            addForm.classList.remove('hidden');
            selectRemoveBtn.style.display = 'inline-block';
            addForm.classList.add('fade-in'); // Add fade-in class

            setTimeout(function() {
                addForm.classList.remove('fade');
            }, 10);
        } else if (formType === 'update_user') {
            updateForm.classList.remove('hidden');
            updateForm.classList.add('fade-in'); // Add fade-in class
            setTimeout(function() {
                updateForm.classList.remove('fade');
            }, 10);
        } else if (formType === 'select_remove') {
            selectRemoveForm.classList.remove('hidden');
            selectRemoveForm.classList.add('fade-in'); // Add fade-in class
            addBtn.style.display = 'inline-block';
            setTimeout(function() {
                selectRemoveForm.classList.remove('fade');
            }, 10);
        }
    }, 500);
}

function prefillUpdateForm(accountAlias) {
    fetch('/get_account_details?alias=' + accountAlias)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(accountDetails => {
            document.getElementById('update-alias').value = accountDetails.alias;
            document.getElementById('update-access_key_id').value = accountDetails.access_key_id;
            document.getElementById('update-secret_access_key').value = accountDetails.secret_access_key;
            document.getElementById('update-default_region_name').value = accountDetails.default_region_name;
            document.getElementById('update-default_output_format').value = accountDetails.default_output_format;
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
}

function updateAccount(accountAlias) {
    document.getElementById('update-account').value = accountAlias;
    prefillUpdateForm(accountAlias);
    showForm('update_user');
}