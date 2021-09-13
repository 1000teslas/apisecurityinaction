const apiUrl = 'https://localhost:4567';
async function createSpace(name) {
    try {
        let data = { name: name };
        let csrfToken = getCookie('csrfToken');
        let response = await fetch(apiUrl + '/spaces', {
            method: 'POST',
            credentials: 'include',
            body: JSON.stringify(data),
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
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

window.addEventListener('load', function (e) {
    document.getElementById('createSpace')
        .addEventListener('submit', processFormSubmit);
});
function processFormSubmit(e) {
    e.preventDefault();
    let spaceName = document.getElementById('spaceName').value;
    createSpace(spaceName);
    return false;
}
function getCookie(cookieName) {
    var cookieValue = document.cookie.split(';')
        .map(item => item.split('=')
            .map(x => decodeURIComponent(x.trim())))
        .filter(item => item[0] === cookieName)[0]
    if (cookieValue) {
        return cookieValue[1];
    }
}