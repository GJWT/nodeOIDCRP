OpenID Connect Relying Party
============================

[![Build Status](https://secure.travis-ci.org/GJWT/nodeOIDCRP?branch=master)](http://travis-ci.org/GJWT/nodeOIDCRP)

Helper to properly authenticate with OpenID Connect.


Example usage (in a connect web application)
--------------------------------------------

The full example can be found in [examples](examples).

```javascript
const oidcrp = require('oidc-rp');

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
```
