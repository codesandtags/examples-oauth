# Examples of OAuth 2.0 Flows

This repository contains examples of implementing OAuth 2.0 flows using Node.js and Express.js. Each subfolder demonstrates a different flow:

- `authorization-code`: Implements the traditional OAuth 2.0 Authorization Code flow.
- `pkce`: Implements the OAuth 2.0 Authorization Code flow with PKCE for enhanced security.

## Prerequisites

1. Install [Node.js](https://nodejs.org/).
2. Clone this repository:
   ```bash
   git clone <repository-url>
   ```
3. Install dependencies for each example:

```bash
cd examples-oauth/<example-folder>
npm install
```

4. Replace YOUR_CLIENT_ID, YOUR_CLIENT_SECRET (if applicable), and https://example.com/oauth with your actual OAuth provider details in the code.

## References

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [RFC 9126: OAuth 2.0 Pushed Authorization Requests (PAR)](https://tools.ietf.org/html/rfc9126)
