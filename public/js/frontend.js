document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const dashboard = document.getElementById('dashboard');
    const logoutBtn = document.getElementById('logoutBtn');

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const regUsername = document.getElementById('regUsername').value;
        const regPassword = document.getElementById('regPassword').value;

        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: regUsername, password: regPassword }),
        });

        if (response.ok) {
            alert('Registration successful! Please log in.');
            loginForm.reset();
        } else {
            alert('Registration failed. Please try again.');
        }
    });

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const loginUsername = document.getElementById('loginUsername').value;
        const loginPassword = document.getElementById('loginPassword').value;

        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: loginUsername, password: loginPassword }),
        });

        if (response.ok) {
            dashboard.style.display = 'block';
            loginForm.reset();
        } else {
            alert('Login failed. Please check your credentials.');
        }
    });

    logoutBtn.addEventListener('click', async () => {
        const response = await fetch('/logout', { method: 'POST' });
        if (response.ok) {
            dashboard.style.display = 'none';
        }
    });

    // Check if the user is logged in when the page loads
    fetch('/dashboard')
        .then((response) => response.json())
        .then((data) => {
            if (data.message === 'Welcome to the dashboard!') {
                dashboard.style.display = 'block';
            }
        })
        .catch((error) => {
            console.error(error);
        });
});
