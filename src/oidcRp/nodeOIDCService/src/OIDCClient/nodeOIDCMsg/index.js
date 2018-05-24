/**
 * @fileoverview Node JS Library for Message protocols
 *
 * @description This is a module that implements the protocol messages in OAuth2
 * and OpenID Connect.
 */
const ImplicitAccessToken =
    require('./src/oicMsg/tokenProfiles/implicitAccessToken');
const await = require('asyncawait/await');
const jws = require('./src/oicMsg/jose/jws')

    const BasicIdToken = require('./src/oicMsg/tokenProfiles/basicIdToken');
const AuthorizationRequest =
    require('./src/oicMsg/oauth2/requests').AuthorizationRequest;

const getClient = require('./src/oicMsg/keystore/keyJar').getClient;
const getKey = require('./src/oicMsg/keystore/keyJar').getKey;

let client =
    getClient('https://sandrino.auth0.com/.well-known/jwks.json', true);
var clockTimestamp = 1000000000;

const Token = require('./src/oicMsg/tokenProfiles/token');
var expect = require('chai').expect;

const jwtDecoder = require('./src/oicMsg/jose/jwt/decode');
var assert = require('chai').assert;


var key = 'key';

var basicIdToken = new BasicIdToken(
    {iss: 'issuer', sub: 'subject', iat: 1437018582, jti: 'jti'});
basicIdToken.addOptionalClaims(
    {'foo': 'bar', 'aud': 'audience', 'exp': 1437018592});
basicIdToken.setNoneAlgorithm(true);
var options = {algorithms: ['HS256'], clockTimestamp: 1437018587000};

basicIdToken.toJWT(key).then(function(token){


try {
  var result = basicIdToken.fromJWT(
      token, key, {
        'iss': 'issuer',
        'sub': 'subject',
        'aud': 'audience',
        'maxAge': 6,
        'clockTolerance': 0.001,
        'jti': 'jti'
      },
      options);
} catch (err) {
  assert.isNull(err);
  assert.equal(result.foo, 'bar');
}
});

/*

const resp = AuthorizationRequest.toJSON(
  {responseType: ['code', 'token'], clientId: 'foobar'});
assert.deepEqual(
  resp,
  JSON.stringify({responseType: ['code', 'token'], clientId: 'foobar'}));
assert.isNotNull(resp);

/*

var key = 'key';
var options = {algorithms: ['HS256'], clockTimestamp: 1437018587000};
basicIdToken = new BasicIdToken(
    {iss: 'issuer', sub: 'subject', iat: 1437018587000 - 5, jti: 'jti'});
basicIdToken.addOptionalClaims(
    {'foo': 'bar', 'aud': 'audience', 'exp': 1437018587000 + 5});
basicIdToken.setNoneAlgorithm(true);
basicIdToken.toJWT(key).then(function(token){

try {
  var result = basicIdToken.fromJWT(
      token, key, {
          'iss': 'issuer',
          'sub': 'subject',
          'aud': 'audience',
          'maxAge': '3s',
          'clockTolerance': 0.001,
          'jti': 'jti'
      },
      options);
} catch (err) {
    assert.equal(err.name, 'TokenExpiredError');
    assert.equal(err.message, 'maxAge exceeded');
    assert.equal(err.expiredAt.constructor.name, 'Date');
    assert.equal(Number(err.expiredAt), 1437018586998000);
    assert.isUndefined(result);
}
});

/*

var clockTimestamp = 1000000000;
var basicIdToken = new BasicIdToken(
    {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
basicIdToken.addOptionalClaims({
  'aud': 'audience',
  'nbf': clockTimestamp + 2,
  'exp': clockTimestamp + 3
});
basicIdToken.setNoneAlgorithm(true);
basicIdToken.toJWT('shhhh').then(function(jws) {
  signedJWT = jws;
  basicIdToken
  .fromJWT(
      signedJWT, 'shhhh', {
        'iss': 'issuer',
        'sub': 'subject',
        'maxAge': '1d',
        'clockTolerance': 10,
        'aud': 'audience',
        'jti': 'jti'
      },
      {'clockTimestamp': clockTimestamp}
    ).then(function(decodedPayload) {
    assert.isNotNull(decodedPayload);
  })
  .catch(function(err) {
    assert.isNull(err);
  });
})

/*
BasicIdToken.toJWT({iss: "https://my.auth.server", sub: "subject", iat:
clockTimestamp, jti: "jti", exp: clockTimestamp + 3600, aud:"myClientId"},
'secret', {algorithm : "HS256"}).then (function (signedJWT) {
    console.log(signedJWT);
    var decoded = jws.decode(signedJWT, {complete:true});
    getKey(decoded, client).then(function (key){
      console.log(key);
      assert.isNotNull(key);
    }).catch(function (err) { assert.isNull(err)});
  }).catch(function (err) {
    assert.isNull(err);
  });
/*
const resp = AuthorizationRequest.toUrlEncoded({'error': 'barsoap'})

/*

var basicIdToken2 =
new BasicIdToken({iss:'issuer', sub:'subject', iat:clockTimestamp, jti:'jti'});
basicIdToken2.addOptionalClaims({
'aud': 'audience',
'nbf': clockTimestamp + 2,
'exp': clockTimestamp + 3
});
basicIdToken2.setNoneAlgorithm(true);
var signedJWT = basicIdToken2.toJWT('shhhh');

try {
var decodedPayload = basicIdToken2.fromJWT(
    signedJWT, 'shhhh', {
      'iss': 'issuer',
      'sub': 'subject',
      'aud': 'audience',
      'maxAge': '1d',
      'clockTolerance': 10,
      'jti': 'jti'
    },
    {'clockTimestamp': clockTimestamp});
assert.isNotNull(decodedPayload);
} catch (err) {
assert.isNull(err);
}

/*
BasicIdToken.toJWT({iss: "https://my.auth.server", sub: "subject", iat:
clockTimestamp, jti: "jti", exp: clockTimestamp + 3600, aud:"myClientId"},
'secret', {algorithm : "HS256"}).then (function (signedJWT) {
  console.log(signedJWT);
  var decoded = jws.decode(signedJWT, {complete:true});
  getKey(decoded, client).then(function (key){
    console.log(key);
    BasicIdToken.fromJWT(
      signedJWT, 'secret', {iss : 'https://my.auth.server', sub: 'subject', aud
: 'myClientId', maxAge: '3s', clockTolerance : 10, jti: 'jti'}, {algorithm:
'HS256', clockTimestamp: clockTimestamp}).then( function(decodedPayload){
        console.log(decodedPayload);
      }).catch(function (err){
        console.log(err);
      })
  }).catch(function (err) { console.log(err)});
}).catch(function (err) {
  console.log(err)
}); */


/*

var basicIdToken =
new BasicIdToken({iss:'issuer', sub:'subject', iat:clockTimestamp, jti:'jti'});
basicIdToken.addOptionalClaims({
'aud': 'audience',
'nbf': clockTimestamp + 2,
'exp': clockTimestamp + 3
});
basicIdToken.setNoneAlgorithm(true);
basicIdToken.toJWT('secret', {}).then (function (token) {
}).catch(function (err){
expect(err).to.be.exist();
expect(err.message)
  .to.equal('secretOrPrivateKey must have a value');
});

/*
var basicIdToken =
    new BasicIdToken({iss:'issuer', sub:'subject', iat:clockTimestamp,
jti:'jwtid'}); basicIdToken.addOptionalClaims({'foo': 'bar', 'aud':
'audience'}); basicIdToken.setNoneAlgorithm(true); basicIdToken.toJWT('secret',
{algorithm: 'RS256'}).then (function (token) {
  jwtDecoder.prototype.verifyJwtSign(
    token, pub, basicIdToken,
    {'clockTimestamp': clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'},
    'base64');
}).catch(function (err){});
/*var verified = jwtDecoder.prototype.verifyJwtSign(
  token, pub, basicIdToken,
  {'clockTimestamp': clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'},
  'base64');*/

/*

var secret = 'secret';
var basicIdToken =
    new BasicIdToken({iss:'issuer', sub:'subject', iat:clockTimestamp,
jti:'jti'}); basicIdToken.addOptionalClaims({ foo: 'bar', 'aud': 'audience',
  'nbf': clockTimestamp + 2,
  'exp': 1
});
basicIdToken.setNoneAlgorithm(true);
var token = basicIdToken.toJWT(secret, {algorithm: 'none'}).then (function
(token) { expect(token).to.be.a('string');
  expect(token.split('.')).to.have.length(3);
}).catch(function (err){
  expect(err).to.be.null();
});


/*
const resp = AuthorizationRequest.toJSON({responseType:['code', 'token'],
clientId: 'foobar'}); console.log(resp);*/

/*
var clockTimestamp = 1000000000;
BasicIdToken.toJWT({iss: "https://my.auth.server", sub: "subject", iat:
clockTimestamp, jti: "jti", exp: clockTimestamp + 3600, aud:"myClientId"},
'secret', {algorithm : "HS256"}).then (function (signedJWT) {
  BasicIdToken.fromJWT(
    signedJWT, 'secret', {iss : 'https://my.auth.server', sub: 'subject', aud :
'myClientId', maxAge: '3s', clockTolerance : 10, jti: 'jti'}, {algorithm:
'HS256', clockTimestamp: clockTimestamp}).then( function(decodedPayload){
      console.log(decodedPayload);
    }).catch(function (err){
      console.log(err);
    })
}).catch(function (err) {
  console.log('Something went wrong: ' + err)
});*/

/*
var decodedPayload = BasicIdToken.fromJWT(
  idToken, 'secret', {iss : 'https://my.auth.server', sub: 'subject', aud :
'myClientId', maxAge: '3s', clockTolerance : 10, jti: 'jti'}, {algorithm:
'HS256', clockTimestamp: clockTimestamp});

/*
var clockTimestamp = 1000000000;

const jwksClient = require('./node_modules/jwks-rsa');

const client = jwksClient({
strictSsl: true, // Default value
jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
const signingKey = key.publicKey || key.rsaPublicKey;
console.log(signingKey);
// Now I can use this to configure my Express or Hapi middleware
});

function getKey({header, payload}= {}){
let kid = header[kid];
let iss = payload[iss];
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.rsaPublicKey;
  console.log(signingKey);
  // Now I can use this to configure my Express or Hapi middleware
});
}*/
/*
var clockTimestamp = 1000000000;

var implicitAccessToken =
  new ImplicitAccessToken({iss:'issuer', sub:'subject', iat:clockTimestamp});
implicitAccessToken.addOptionalClaims({'aud': 'audience'});
implicitAccessToken.setNoneAlgorithm(true);
implicitAccessToken.toJWT('shhhh').then (function (signedJWT) {
  implicitAccessToken.fromJWT(
    signedJWT, 'shhhh', {
      'iss': 'issuer',
      'sub': 'subject',
      'aud': 'audience',
      'maxAge': '1d'
    },
    {'clockTimestamp': clockTimestamp}).then (function (decodedPayload)
{console.log(decodedPayload);
    }).catch(function(err){});
    console.log(signedJWT);
 }).catch(function (err) {
   console.log('Something went wrong: ' + err)
  });

  /*
var clockTimestamp = 1000000000;
var implicitAccessToken =
  new ImplicitAccessToken({iss:'issuer', sub:'subject', iat:clockTimestamp});
implicitAccessToken.addOptionalClaims({'aud': 'audience'});
implicitAccessToken.setNoneAlgorithm(true);
let signedJWT = implicitAccessToken.toJWT('shhhh');

  var decodedPayload = implicitAccessToken.fromJWT(
    signedJWT, 'shhhh', {
      'iss': 'issuer',
      'sub': 'subject',
      'aud': 'audience',
      'maxAge': '1d'
    },
    {'clockTimestamp': clockTimestamp});
    console.log(decodedPayload);
    console.log(signedJWT);


/*
var clockTimestamp = 1000000000;
var secret = 'shhhhhh';

var basicIdToken =
new BasicIdToken({iss:'issuer', sub:'subject', iat:clockTimestamp, jti:'jti'});
basicIdToken.addOptionalClaims({
'foo': 'bar',
'aud': 'audience',
'nbf': clockTimestamp + 2,
'exp': clockTimestamp + 3
});
basicIdToken.setNoneAlgorithm(true);
var token = basicIdToken.toJWT(secret, {algorithm: 'HS256'});
var decoded = basicIdToken.fromJWT(
    token, secret, {
      'iss': 'issuer',
      'sub': 'subject',
      'aud': 'audience',
      'maxAge': '1d',
      'clockTolerance': 10,
      'jti': 'jti'
    },
    {'clockTimestamp': clockTimestamp});

console.log(decoded); */