// import libraries
const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const jwtAuthz = require("express-jwt-authz");
const bodyParser = require("body-parser");
const axios = require("axios");

// configure .env variables
require("dotenv").config();

if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
  throw "Make sure you have AUTH0_DOMAIN, and AUTH0_AUDIENCE in your .env file";
}

// The access token to access the Auth0 Management API
accessToken = "";

// Function to renew Auth0 Management API access token
function getAccessToken() {

  // time after which token must be refreshed, will be updated later
  refreshAfter = -1;

  // required parameter to pass to Auth0 Management API OAuth
  const body = JSON.stringify({
    "client_id": process.env.CLIENT_ID,
    "client_secret": process.env.CLIENT_SECRET,
    "audience": process.env.AUTH0_AUDIENCE,
    "grant_type": process.env.GRANT_TYPE
  });

  // axios request to get the access token
  axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, body, {
    headers: {
      // Overwrite Axios"s automatically set Content-Type
      "Content-Type": "application/json"
    }
  }).then(function (response) {
    // get the access token
    accessToken = response.data.access_token;

    // token must refresh every 10 minutes before the expiration time
    refreshAfter = response.data.expires_in - 600;

    // refresh the token
    setTimeout(getAccessToken, (refreshAfter * 1000));
  }).catch(function (error) {
    accessToken = "";
  });
}

// execute the function for the first time
getAccessToken();

// Enable CORS
app.use(cors());

// Create middleware for checking the JWT
const checkJwt = jwt({
  // Dynamically provide a signing key based on the kid in the header and the singing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  }),

  // Validate the audience and the issuer.
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
    
    // send request
    axios.request(options).then(function (response) {
      // user data found
      res.status(200).send(response.data);
    }).catch(function (error) {
      // send error message and log it
      res.status(200).send({"message":`${error.message}`});
    });
    
  }
});

// launch the API Server
app.listen(8080, () => {
  console.log("listening");
});