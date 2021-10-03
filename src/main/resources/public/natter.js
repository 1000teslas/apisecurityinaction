const apiUrl = 'https://localhost:4567';
async function createSpace(name) {
    try {
        let data = { name: name };
        let token = localStorage.getItem('token');
        let response = await fetch(apiUrl + '/spaces', {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            }
        });
        let json;
        if (response.ok) {
            json = await response.json();
        } else if (response.status === 401) {
            window.location.replace('/login.html');
        } else {
            throw Error(response.statusText);
        }
        console.log('Created space: ', json.name, json.uri);
    } catch (error) {
        console.error('Error: ', error)
    }
}

window.addEventListener('load', async function (e) {
    document.getElementById('createSpace')
        .addEventListener('submit', await processFormSubmit());
});
async function processFormSubmit(e) {
    e.preventDefault();
    let spaceName = document.getElementById('spaceName').value;
    await createSpace(spaceName);
    return false;
}