const retryFetchFactory = require('kiss-retry-fetch')

module.exports = retryFetchFactory({
    maxRetries: 5,
    fetch: fetch,
    shouldRetry(response) {
        return [408, 429, 500, 502, 503].indexOf(response.status) === -1
          ? testErrors(getErrorPayload(response))
          : true
    }
})

function testErrors(errors) {
    if (!errors) return false

    for (const e of errors) {
        const reason = e.reason;
        if (reason && (
          reason === 'rateLimitExceeded'
          || reason === 'userRateLimitExceeded'
          || reason.includes('EAI_AGAIN')
        )) return true;
    }
    return false
}

function getErrorPayload(response) {
    try {
        return JSON.parse(response.body).error.errors;
    } catch (e) {
    }
}
