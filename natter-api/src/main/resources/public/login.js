const apiUrl = 'https://localhost:4567';
async function login(username, password) {
    let credentials = 'Basic ' + btoa(username + ':' + password);
    try {
        let res = await fetch(apiUrl + '/sessions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': credentials
            }
        });
        if (res.ok) {
            let json = await res.json();
            localStorage.setItem('token', json.token);
            window.location.replace('/natter.html');
        }
    }
    catch (error) { console.error('Error logging in: ', error); }
}

window.addEventListener('load', async function (e) {
    document.getElementById('login')
        .addEventListener('submit', await processLoginSubmit());
});

async function processLoginSubmit(e) {
    e.preventDefault();
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;
    await login(username, password);
    return false;
}