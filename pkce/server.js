const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const querystring = require("querystring");

const app = express();
const port = 3000;

// OAuth Configuration
const clientId = "YOUR_CLIENT_ID";
const authorizationServer = "https://example.com/oauth"; // Replace with your OAuth provider
const redirectUri = "http://localhost:3000/callback";

const logRequestData = (req, res, next) => {
  console.log("Request URL:", req.url);
  console.log("Request Headers:", req.headers);
  console.log("Request Parameters:", req.body);
  console.log("Request Query:", req.query);
  next();
};

app.use(express.json()); // To parse JSON bodies
app.use(logRequestData); // Use the logging middleware

// Generate PKCE Code Verifier and Challenge
function generateCodeVerifier() {
  const codeVerifier = crypto.randomBytes(32).toString("hex");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { codeVerifier, codeChallenge };
}

// Store codeVerifier for the session (In production, use a proper session store)
let pkce = {};

// Redirect user to Authorization Server
app.get("/login", (req, res) => {
  pkce = generateCodeVerifier();

  const authUrl =
    `${authorizationServer}/authorize?` +
    querystring.stringify({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid profile email",
      code_challenge: pkce.codeChallenge,
      code_challenge_method: "S256",
    });
  res.redirect(authUrl);
});

// Handle Authorization Code Callback
app.get("/callback", async (req, res) => {
  const authorizationCode = req.query.code;

  try {
    const tokenResponse = await axios.post(
      `${authorizationServer}/token`,
      querystring.stringify({
        grant_type: "authorization_code",
        code: authorizationCode,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: pkce.codeVerifier,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    res.json(tokenResponse.data); // Contains access_token
  } catch (error) {
    res.status(500).json({ error: error.response?.data || error.message });
  }
});

app.listen(port, () => {
  console.log(`App running on http://localhost:${port}`);
});
