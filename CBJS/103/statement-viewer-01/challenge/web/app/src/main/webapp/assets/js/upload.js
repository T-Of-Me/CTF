document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('.upload-form');
    const submitBtn = form.querySelector('button[type="submit"]');
    const btnText = submitBtn.querySelector('.btn-text');
    const btnLoading = submitBtn.querySelector('.btn-loading');

    form.addEventListener('submit', function (e) {
        const userIdInput = document.getElementById('hiddenUserId');
        const userId = userIdInput ? userIdInput.value : '';

        if (!userId || userId.trim() === '') {
            e.preventDefault();
            const alert = document.createElement('div');
            alert.className = 'alert alert-error';
            alert.innerHTML = 'ERROR: User ID is missing. Please try again.';
            form.insertBefore(alert, form.firstChild);

            setTimeout(() => alert.remove(), 5000);
            return false;
        }

        // Show loading state
        btnText.style.display = 'none';
        btnLoading.style.display = 'flex';
        submitBtn.disabled = true;

        // Validate file
        const fileInput = form.querySelector('input[type="file"]');
        if (!fileInput.files || fileInput.files.length === 0) {
            e.preventDefault();
            btnText.style.display = 'flex';
            btnLoading.style.display = 'none';
            submitBtn.disabled = false;

            // Show error message
            const alert = document.createElement('div');
            alert.className = 'alert alert-error';
            alert.innerHTML = '❌ Please select a file to upload';
            form.insertBefore(alert, form.firstChild);

            setTimeout(() => alert.remove(), 5000);
            return false;
        }

        const file = fileInput.files[0];
        const maxSize = 10 * 1024 * 1024; // 10MB
        const allowedTypes = ['application/pdf', 'text/plain'];

        if (file.size > maxSize) {
            e.preventDefault();
            btnText.style.display = 'flex';
            btnLoading.style.display = 'none';
            submitBtn.disabled = false;

            const alert = document.createElement('div');
            alert.className = 'alert alert-error';
            alert.innerHTML = '❌ File size must be less than 10MB';
            form.insertBefore(alert, form.firstChild);

            setTimeout(() => alert.remove(), 5000);
            return false;
        }

        if (!allowedTypes.includes(file.type)) {
            e.preventDefault();
            btnText.style.display = 'flex';
            btnLoading.style.display = 'none';
            submitBtn.disabled = false;

            const alert = document.createElement('div');
            alert.className = 'alert alert-error';
            alert.innerHTML = '❌ Only PDF and TXT files are allowed';
            form.insertBefore(alert, form.firstChild);

            setTimeout(() => alert.remove(), 5000);
            return false;
        }
    });
});