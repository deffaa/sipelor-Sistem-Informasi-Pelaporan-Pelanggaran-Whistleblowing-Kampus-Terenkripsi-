document.addEventListener('DOMContentLoaded', () => {
    // 1. Copy generated keys to clipboard
    document.querySelectorAll('[data-copy-target]').forEach((button) => {
        button.addEventListener('click', async () => {
            const targetId = button.getAttribute('data-copy-target');
            const inputEl = document.getElementById(targetId);
            if (!inputEl) return;

            try {
                await navigator.clipboard.writeText(inputEl.value);
                const originalText = button.textContent;
                button.textContent = 'Tersalin';
                setTimeout(() => {
                    button.textContent = originalText;
                }, 1500);
            } catch {
                inputEl.select();
                document.execCommand('copy');
            }
        });
    });

    // 2. Autofill newly generated keys into the Admin Login form
    const autofillBtn = document.getElementById('btn-autofill-keys');
    if (autofillBtn) {
        autofillBtn.addEventListener('click', () => {
            const genSym = document.getElementById('gen-sym');
            const genPriv = document.getElementById('gen-priv');
            const loginSym = document.getElementById('symmetric_key');
            const loginPriv = document.getElementById('private_key');

            if (genSym && genPriv && loginSym && loginPriv) {
                loginSym.value = genSym.value;
                loginPriv.value = genPriv.value;
                loginSym.focus();
            }
        });
    }

    // 3. Toggle symmetric key visibility
    document.querySelectorAll('[data-toggle-input]').forEach((button) => {
        button.addEventListener('click', () => {
            const inputId = button.getAttribute('data-toggle-input');
            const inputEl = document.getElementById(inputId);
            if (!inputEl) return;

            inputEl.type = inputEl.type === 'password' ? 'text' : 'password';
        });
    });

    // 4. Confirmation modal for delete actions
    const dialog = document.getElementById('confirm-dialog');
    const titleEl = document.getElementById('confirm-dialog-title');
    const descEl = document.getElementById('confirm-dialog-desc');
    const cancelBtn = document.getElementById('confirm-cancel-btn');
    const proceedBtn = document.getElementById('confirm-proceed-btn');
    let pendingForm = null;

    document.querySelectorAll('[data-confirm-form]').forEach((form) => {
        form.addEventListener('submit', (event) => {
            event.preventDefault();
            const title = form.getAttribute('data-confirm-title') || 'Konfirmasi Hapus';
            const message = form.getAttribute('data-confirm-message') || 'Hapus rekaman terenkripsi ini secara permanen?';

            if (dialog && typeof dialog.showModal === 'function') {
                pendingForm = form;
                if (titleEl) titleEl.textContent = title;
                if (descEl) descEl.textContent = message;
                dialog.showModal();
            } else if (window.confirm(message)) {
                form.submit();
            }
        });
    });

    if (cancelBtn && dialog) {
        cancelBtn.addEventListener('click', () => {
            pendingForm = null;
            dialog.close();
        });
    }

    if (proceedBtn && dialog) {
        proceedBtn.addEventListener('click', () => {
            if (pendingForm) {
                const formToSubmit = pendingForm;
                pendingForm = null;
                dialog.close();
                formToSubmit.submit();
            }
        });
    }
});