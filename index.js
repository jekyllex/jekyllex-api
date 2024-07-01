const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const jwtAuthz = require("express-jwt-authz");
const bodyParser = require("body-parser");
const axios = require("axios");

require("dotenv").config();

if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
  throw "Make sure you have AUTH0_DOMAIN, and AUTH0_AUDIENCE in your .env file";
}

// token to get data from the Auth0 Management API
accessToken = "";

// function that periodically renews Auth0 Management API access token
function getAccessToken() {

  // time after which token must be refreshed, will be updated later
  refreshAfter = -1;

  // required parameter to pass to the Auth0 Management API OAuth
  const body = JSON.stringify({
    "client_id": process.env.CLIENT_ID,
    "client_secret": process.env.CLIENT_SECRET,
    "audience": process.env.AUTH0_AUDIENCE,
    "grant_type": process.env.GRANT_TYPE
  });

  // fetch the access token
  axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, body, {
    headers: {
      "Content-Type": "application/json"
    }
  }).then(function (response) {
    accessToken = response.data.access_token;

    // token must refresh every 10 minutes before the expiration time
    refreshAfter = response.data.expires_in - 600;

    // refresh the token
    setTimeout(getAccessToken, (refreshAfter * 1000));
  }).catch(function (error) {
    accessToken = "";
  });
}

// get access token on server start
getAccessToken();

app.use(cors());

// Create JWT processor
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  }),
  audience: process.env.API_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ["RS256"]
});

// Enable the use of request body parsing middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

// API home, just to test if it"s working fine
app.get("/", function(req, res){
  res.status(200).send({"message":"API is functional."})
});

// route to download ruby bootstrap for a specific android arch
app.get("/ruby/:version/:arch", function(req, res){
  res.status(200).redirect(`https://github.com/jekyllex/ruby-android/releases/download/${req.params.version}/ruby-${req.params.arch}`);
});

// route to get the user data from Auth0 Management API
app.get("/user/:id", checkJwt, jwtAuthz(["read:userdata"]), function (req, res) {

  // if accessToken is empty, get a new access token
  // else process the request
  if(accessToken==="") {
    getAccessToken();
  } else {
    var options = {
      method: "GET",
      url: `https://${process.env.AUTH0_DOMAIN}/api/v2/users/${req.params.id}`,
      headers: {
        "Authorization": `Bearer ${accessToken}`,
      }
    };
    
    // retrieve user data from Auth0 API
    axios.request(options).then(function (response) {
      res.status(200).send(response.data);
    }).catch(function (error) {
      res.status(200).send({"message":`${error.message}`});
    });
  }
});

// launch the API Server
app.listen(process.env.PORT || 8080);
