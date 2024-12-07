const express = require("express");
const axios = require("axios");
const querystring = require("querystring");
require("dotenv").config();

const app = express();
const port = 3000;

// OAuth Configuration
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const authorizationServer = "https://example.com/oauth"; // Replace with your OAuth provider
const redirectUri = "http://localhost:3000/callback";

// Redirect user to Authorization Server
app.get("/login", (req, res) => {
  const authUrl =
    `${authorizationServer}/authorize?` +
    querystring.stringify({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid profile email",
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
        client_secret: clientSecret,
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
