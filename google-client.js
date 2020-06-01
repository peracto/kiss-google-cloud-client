const jwt = require('kiss-jwt')
const retryFetch = require('./google-fetch')
const authFetchFactory = require('kiss-auth-fetch')

const now = () => Math.floor(new Date().getTime() / 1000)

const GOOGLE_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token'

module.exports = function createClient(config) {
    config = {
        ...config,
        scope: 'https://www.googleapis.com/auth/cloud-platform',
        ttl: 3600, // 1 hour
        renew: 300, // 5 minutes
    }
    return authFetchFactory({
        fetch: retryFetch,
        auth: authTokenFactory(
          fetcher(
            retryFetch
          ),
          config.renew,
          assertionFactory(
            config.credentials,
            config.ttl,
            config.scope
          )
        )
    })
}

function fetcher(retryFetch) {
    return function doRequest(payload) {
        return retryFetch(GOOGLE_TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': payload
            }),
        })
    }
}

function authTokenFactory(doRequest, renew, assertion) {
    let expires = 0
    let promise = null
    let loading = false

    return function refresh() {
        if (!loading && now() > expires) {
            loading = true
            promise = createRefreshPromise()
        }
        return promise
    }

    async function createRefreshPromise() {
        try {
            const response = await doRequest(await assertion())
            const token = await response.json()
            if (!response.ok)
                throw new Error(JSON.stringify(token))
            const auth = `${token.token_type} ${token.access_token}`
            expires = now() + (token.expires_in || 0) - renew
            promise = Promise.resolve(auth)
            loading = false
            return auth
        } catch (ex) {
            loading = false
            promise = Promise.reject(ex)
            expires = now() * 2
        }
    }
}

function assertionFactory(credentials, ttl, scope) {
    return async function createAssertion() {
        const iat = now()
        const c = await credentials()
        return jwt.sign({
            'iss': c.clientEmail,
            'aud': GOOGLE_TOKEN_URL,
            'exp': iat + ttl,
            'iat': iat,
            'scope': scope,
        }, c.privateKey)
    }
}
