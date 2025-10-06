function showToast(type, message) {
    var toast = new bootstrap.Toast(document.getElementById('liveToast'));
    var toastBody = document.querySelector('.toast-body');
    toastBody.innerHTML = message;
    toastBody.classList.remove('text-success', 'text-danger');
    if (type === 'success') {
        toastBody.classList.add('text-success');
    } else if (type === 'error') {
        toastBody.classList.add('text-danger');
    }
    toast.show();
}

