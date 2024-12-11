const express = require("express");
const querystring = require("querystring");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");

// In memory storage for pushed authorization requests
const { savePushedRequest, getPushedRequest } = require("./db");

// Create an Express application
const app = express();
const port = 4000;

// In-memory storage for issued authorization codes
const authCodes = new Map();
const accessTokens = new Map();

// Configuration for the mock provider
const CLIENT_ID = "mock-client-id";
const CLIENT_SECRET = "mock-client-secret";
const REDIRECT_URI = "http://localhost:3000/callback";

// Mock database for clients and tokens
const CLIENTS = {
  "mock-client-id": { redirectUris: ["http://localhost:3000/callback"] },
};

const logRequestData = (req, res, next) => {
  console.log("Request URL:", req.url);
  console.log("Request Headers:", req.headers);
  console.log("Request Parameters:", req.body);
  console.log("Request Query:", req.query);
  next();
};

app.use(bodyParser.urlencoded({ extended: true })); // To parse URL-encoded bodies
app.use(express.json()); // To parse JSON bodies
app.use(logRequestData); // Use the logging middleware

// Authorization Endpoint (Step 1)
app.get("/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    request_uri,
    response_type,
    code_challenge,
    code_challenge_method,
  } = req.query;

  if (request_uri && request_uri?.startsWith("urn:uuid")) {
    // Retrieve the pushed authorization request
    const request = getPushedRequest(request_uri);
    if (!request) {
      return res.status(400).json({ error: "invalid_request_uri" });
    }
    // Simulate user authorization and generate an authorization code
    const authorizationCode = uuidv4(); // Random code
    request.authorizationCode = authorizationCode;

    res.redirect(`${request.redirect_uri}?code=${authorizationCode}`);
  }

  if (client_id !== CLIENT_ID) {
    return res.status(400).json({ error: "Invalid client_id" });
  }

  if (redirect_uri !== REDIRECT_URI) {
    return res.status(400).json({ error: "Invalid redirect_uri" });
  }

  if (response_type !== "code") {
    return res.status(400).json({ error: "Unsupported response_type" });
  }

  // Simulate user login and consent (skip UI for simplicity)
  const authCode = crypto.randomBytes(16).toString("hex");
  authCodes.set(authCode, { code_challenge, code_challenge_method });

  // Redirect back to client with authorization code
  const redirectWithCode = `${redirect_uri}?code=${authCode}`;
  res.redirect(redirectWithCode);
});

// Endpoint for Pushed Authorization Requests (PAR) - RFC 9126
app.post("/par", (req, res) => {
  const {
    client_id,
    response_type,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
  } = req.body;

  // Validate client_id
  if (!CLIENTS[client_id]) {
    return res.status(400).json({ error: "invalid_client" });
  }

  // Validate redirect_uri
  if (!CLIENTS[client_id].redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }

  // Save the pushed authorization request
  const requestUri = `urn:uuid:${uuidv4()}`;
  savePushedRequest(requestUri, {
    client_id,
    response_type,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
  });

  res.status(201).json({
    request_uri: requestUri,
    expires_in: 300, // Request URI expires in 300 seconds
  });
});

// Token Endpoint (Step 2)
app.post("/token", express.urlencoded({ extended: true }), (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier,
  } = req.body;

  // Verify PKCE challenge (if applicable)
  const { code_challenge, code_challenge_method } = authCodes.get(code) || {};

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "Unsupported grant_type" });
  }

  // Validate client_id
  // const request = Object.values(getPushedRequest()).find(
  //   (r) => r.client_id === client_id && r.authorizationCode === code
  // );
  // if (!request) {
  //   return res.status(400).json({ error: "invalid_grant" });
  // }

  if (
    (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) &&
    !code_challenge
  ) {
    return res.status(400).json({ error: "Invalid client credentials" });
  }

  if (redirect_uri !== REDIRECT_URI) {
    return res.status(400).json({ error: "Invalid redirect_uri" });
  }

  if (!authCodes.has(code)) {
    return res.status(400).json({ error: "Invalid authorization code" });
  }

  if (code_challenge) {
    if (code_challenge_method === "S256") {
      const expectedChallenge = crypto
        .createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
      if (expectedChallenge !== code_challenge) {
        return res.status(400).json({ error: "Invalid code_verifier" });
      }
    } else if (code_challenge_method === "plain") {
      if (code_challenge !== code_verifier) {
        return res.status(400).json({ error: "Invalid code_verifier" });
      }
    }
  }

  // Generate access token
  const accessToken = crypto.randomBytes(32).toString("hex");
  accessTokens.set(accessToken, { client_id, scope: "openid profile email" });

  // Respond with the access token
  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "openid profile email",
  });
});

// Mock User Info Endpoint
app.get("/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  if (!accessTokens.has(token)) {
    return res.status(401).json({ error: "Invalid token" });
  }

  // Respond with mock user info
  res.json({
    sub: "1234567890",
    name: "John Doe",
    email: "john.doe@example.com",
  });
});

app.listen(port, () => {
  console.log(`Mock OAuth Provider running on http://localhost:${port}`);
});
