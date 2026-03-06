let _accessToken = null;

export function setToken(token) {
    _accessToken = token;
}

export function getToken() {
    return _accessToken;
}

export function clearToken() {
    _accessToken = null;
}