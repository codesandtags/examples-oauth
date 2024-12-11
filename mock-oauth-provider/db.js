const pushedRequests = {};

/**
 * Save a pushed authorization request
 * @param {string} requestUri
 * @param {object} data
 */
function savePushedRequest(requestUri, data) {
  pushedRequests[requestUri] = data;
}

/**
 * Get a pushed authorization request
 * @param {string} requestUri
 * @returns {object|null}
 */
function getPushedRequest(requestUri) {
  return pushedRequests[requestUri] || [];
}

module.exports = { savePushedRequest, getPushedRequest };
