const express = require('express');
const oidcrp = require('..'); // Using the local oidc-rp in parent

const clients = require('./clients');

const app = express();

const authFlow = oidcrp.authorizationCodeFlow({
  getClient: clients.get,
  registerClient: clients.register,
  clientMetadata: {
    // See http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    redirect_uris: ['http://localhost:3000/auth/callback'],
  },
});


app.post('/auth', async (req, res) => {
  const identifier = req.param.identifier;

  const url = await authFlow.getRedirectUrl({
    identifier,
    callbackUrl: 'https://myApp.org/auth/callback',
  });

  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const user = await authFlow.validate({query: req.query}); // throws if invalid

  console.log('Got a user:', user.identifier, user.id_token);

  // Store user as logged in on session...
  req.user = user;
  res.redirect('/loggedIn');
});

app.get('/', (req, res) => {
  res.send('TODO: add view with input for OIDC discovery identifier');
});

app.listen(3000, () => console.log('Example app listening on port 3000!'));
