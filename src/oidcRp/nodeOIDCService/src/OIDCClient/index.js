var serviceContext = require('./src/serviceContext.js');
var assert = require('chai').assert;
var urlParse = require('url-parse');
var State = require('./src/state.js').State;
var ExpiredToken = require('./src/state.js').ExpiredToken;
var AuthorizationRequest =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
var AuthorizationResponse =
    require('./nodeOIDCMsg/src/oicMsg/oic/responses').AuthorizationResponse;
var AccessTokenResponse =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
var AccessTokenRequest = require('./nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
var CCAccessTokenRequest =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/requests').CCAccessTokenRequest;
var ResourceRequest = require('./nodeOIDCMsg/src/oicMsg/oauth2/requests').ResourceRequest;
// var Client = require('./src/oic/init').Client;
// var Client = require('./src/oic/init').Client;

var Client = require('./src/oauth2/init').Client;
var CLIENT_AUTHN_METHOD =
    require('./src/clientAuth/privateKeyJWT').CLIENT_AUTHN_METHOD;
var ClientSecretBasic =
    require('./src/clientAuth/clientSecretBasic').ClientSecretBasic;
var ClientSecretPost =
    require('./src/clientAuth/clientSecretPost').ClientSecretPost;
var BearerHeader = require('./src/clientAuth/bearerHeader').BearerHeader;
var BearerBody = require('./src/clientAuth/bearerBody').BearerBody;
var validserviceContext =
    require('./src/clientAuth/clientAuth').validserviceContext;
var WebFinger = require('./src/webFinger/webFinger').WebFinger;
var URINormalizer = require('./src/webFinger/uriNormalizer').URINormalizer;
var LINK = require('./src/webFinger/link').LINK;
var JRD = require('./src/webFinger/link').JRD;

var addCodeChallenge = require('./src/oic/pkce.js').addCodeChallenge;
var addCodeVerifier = require('./src/oic/pkce.js').addCodeVerifier;

const SINGLE_REQUIRED_STRING =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_REQUIRED_STRING;
const SINGLE_OPTIONAL_DICT =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_DICT;
const SINGLE_OPTIONAL_INT = require('./nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_INT;
let util = require('./src/util').Util;
const Message = require('./nodeOIDCMsg/src/oicMsg/message');
const KeyJar = require('./nodeOIDCMsg/src/oicMsg/keystore/keyJar.js');

var SINGLE_OPTIONAL_STRING =
    require('./nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_OPTIONAL_STRING;
// const Service = require('./src/service.js').Service;
var ErrorResponse = require('./nodeOIDCMsg/src/oicMsg/oauth2/init').ErrorResponse;
const factory = require('./src/oic/service/service').OicFactory;

var wf = require('./node_modules/webfinger/lib/webfinger');

const buildServices = require('./src/service').buildServices;
const DEFAULT_SERVICES = require('./src/oic/init').DEFAULT_SERVICES;
const OicFactory = require('./src/oic/service/service').OicFactory;
const ServiceContext = require('./src/serviceContext').ServiceContext;
const Service = require('./src/service').Service;
var OpenIDSchema = require('./nodeOIDCMsg/src/oicMsg/oic/init').OpenIDSchema;
var addJwksUriOrJwks = require('./src/service.js').addJwksUriOrJwks;
const RP_BASEURL = "https://example.com/rp";
const OP_BASEURL = "https://example.org/op";
const parseQs = require('./src/util').parseQs;

const CLIENT_ID = 'A';

const CLIENT_CONF = {
  issuer: 'https://example.com/as',
  redirect_uris: ['https://example.com/cli/authz_cb'],
  client_secret: 'boarding pass',
  client_id: CLIENT_ID,
};

const REQ_ARGS = {
  redirect_uri: 'https://example.com/rp/cb',
  response_type: 'code',
};

class DummyMessage extends Message{
constructor(){
    super();
    this.cParam = {'req_str': SINGLE_REQUIRED_STRING}
    return this;
}
}

class DummyService extends Service{
constructor(ci, db){
    super(ci, db);
    this.msgType = DummyMessage;
    return this;
}
}

class DB{
    constructor(){
        this.db = {};
    }

    set(key, value){
        this.db[key] = value;
    }

    get(item){
        return this.db[item];
    }
}
  
function getService(){
    let serviceContext = new ServiceContext(null, CLIENT_CONF);
    serviceContext.client_secret = 'boarding pass';
    return serviceContext;
}

function getServiceContext(){
    let serviceContext = new ServiceContext(null, CLIENT_CONF);
    serviceContext.client_secret = 'boarding pass';
    return serviceContext;
}

function getServices(){
    let db = new DB();
    let authRequest = AuthorizationRequest.toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
    let authResponse = AuthorizationResponse.toJSON({access_token: 'token', state: 'ABCDE'});
    db.set('ABCDE', State.toJSON({iss:'Issuer', auth_request:authRequest, auth_response:authResponse}));
    return buildServices(DEFAULT_SERVICES, OicFactory, getServiceContext(), db, CLIENT_AUTHN_METHOD);
}


let services = getServices();


let clientConfig = {
    "client_preferences":
        {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.org"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
    "redirect_uris": [RP_BASEURL + "/authz_cb"],
    "jwks_uri": RP_BASEURL + "/static/jwks.json"
}
serviceContext = new ServiceContext(null, clientConfig);
let serviceSpec = DEFAULT_SERVICES;
serviceSpec['WebFinger'] = {};
let service = buildServices(serviceSpec, factory, serviceContext, new DB());
serviceContext.service = service

//TEST BUILD SERVICES
assert.deepEqual(Object.keys(service).length, 7);

// TEST WEBFINGER 
let info = service['webfinger'].getRequestParameters({requestArgs:{'resource': 'foobar@example.org'}});
assert.deepEqual(info['url'], 'https://example.org/.well-known/webfinger?resource=acct%3Afoobar%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');
let webfingerResponse = JSON.stringify({
    "subject": "acct:foobar@example.org",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://example.org/op"}],
    "expires": "2018-02-04T11:08:41Z"});
let response = service['webfinger'].parseResponse(webfingerResponse);
assert.deepEqual(Object.keys(response), ['subject', 'links', 'expires']);
assert.deepEqual(response['links'], [
    {'rel': 'http://openid.net/specs/connect/1.0/issuer',
        'href': 'https://example.org/op'}]);
service['webfinger'].updateServiceContext(response);
assert.deepEqual(serviceContext.issuer, OP_BASEURL);

info = service['provider_info'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/.well-known/openid-configuration');
let providerInfoResponse = JSON.stringify({
    "version": "3.0",
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "claims_parameter_supported": true,
    "request_parameter_supported": true,
    "request_uri_parameter_supported": true,
    "require_request_uri_registration": true,
    "grant_types_supported": ["authorization_code",
                            "implicit",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer",
                            "refresh_token"],
    "response_types_supported": ["code", "id_token",
                                "id_token token",
                                "code id_token",
                                "code token",
                                "code id_token token"],
    "response_modes_supported": ["query", "fragment",
                                "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "claim_types_supported": ["normal", "aggregated",
                            "distributed"],
    "claims_supported": ["birthdate", "address",
                        "nickname", "picture", "website",
                        "email", "gender", "sub",
                        "phone_number_verified",
                        "given_name", "profile",
                        "phone_number", "updated_at",
                        "middle_name", "name", "locale",
                        "email_verified",
                        "preferred_username", "zoneinfo",
                        "family_name"],
    "scopes_supported": ["openid", "profile", "email",
                        "address", "phone",
                        "offline_access", "openid"],
    "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512", "none"],
    "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512"],
    "userinfo_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "id_token_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "request_object_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "userinfo_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "id_token_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "request_object_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "acr_values_supported": ["PASSWORD"],
    "issuer": OP_BASEURL,
    "jwks_uri": OP_BASEURL + "/static/jwks_tE2iLbOAqXhe8bqh.json",
    "authorization_endpoint": OP_BASEURL + "/authorization",
    "token_endpoint": OP_BASEURL + "/token",
    "userinfo_endpoint": OP_BASEURL + "/userinfo",
    "registration_endpoint": OP_BASEURL + "/registration",
    "end_session_endpoint": OP_BASEURL + "/end_session"});

response = service['provider_info'].parseResponse(providerInfoResponse);
service['provider_info'].updateServiceContextProviderInfo(response);

assert.deepEqual(serviceContext.providerInfo['issuer'], OP_BASEURL);
assert.deepEqual(serviceContext.providerInfo['authorization_endpoint'], 'https://example.org/op/authorization');
assert.deepEqual(serviceContext.providerInfo['registration_endpoint'], 'https://example.org/op/registration');

info = service['registration'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/registration');
let body = info['body'];

assert.equal(Object.keys(body).length, 7);

assert.deepEqual(info['headers'], {'Content-Type': 'application/json'});

let now = Date.now();

let opClientRegistrationResponse = JSON.stringify({
    "client_id": "zls2qhN1jO6A",
    "client_secret": "c8434f28cf9375d9a7",
    "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
    "registration_client_uri": RP_BASEURL + "/registration?client_id=zls2qhN1jO6A",
    "client_secret_expires_at": now + 3600,
    "application_type": "web",
    "client_id_issued_at": now + 1,    
    "response_types": ["code"],
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": [RP_BASEURL + "/authz_cb"]});

response = service['registration'].parseResponse(opClientRegistrationResponse);
service['registration'].updateServiceContext(response);

assert.deepEqual(serviceContext.client_id, 'zls2qhN1jO6A');
assert.deepEqual(serviceContext.client_secret, 'c8434f28cf9375d9a7');
assert.deepEqual(Object.keys(serviceContext.registrationResponse).length, 11);
  
   // AUTHORIZATION
   const STATE = 'Oh3w3gKlvoM2ehFqlxI3HIK5'
   const NONCE = 'UvudLKz287YByZdsY3AJoPAlEXQkJ0dK'

   info = service['authorization'].getRequestParameters({requestArgs:{'state': STATE, 'nonce': NONCE}});

   let p = urlParse(info['url']);
   let parsedResp = Message.fromUrlEncoded(p.query.substring(1, p.query.length));
   let query = parseQs(parsedResp);
   assert.deepEqual(Object.keys(query).length, 6);
   assert.deepEqual(query['scope'], ['openid']);
   assert.deepEqual(query['nonce'], [NONCE]);
   assert.deepEqual(query['state'], [STATE]);

   let opAuthzResp = {
       'state': STATE,
       'scope': 'openid',
       'code': 'Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01',
       'iss': OP_BASEURL,
       'client_id': 'zls2qhN1jO6A'};

   //let authzRep = new AuthorizationResponse(opAuthzResp);
   let resp = service['authorization'].parseResponse(AuthorizationResponse.toUrlEncoded(opAuthzResp));

   service['authorization'].updateServiceContext(resp, STATE);
   let item2 = service['authorization'].getItem(AuthorizationResponse, 'auth_response', STATE);
   assert.deepEqual(item2.claims['code'], 'Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01');

   // Access Token
   let requestArgs = {'state': STATE,
   'redirect_uri': serviceContext.redirectUris[0]};

   info = service['accessToken'].getRequestParameters({requestArgs: requestArgs});
   assert.deepEqual(info['url'], 'https://example.org/op/token');
   body = info['body'];
   query = Message.fromUrlEncoded(body);
   let qp = parseQs(query);
   assert.deepEqual(Object.keys(qp).length, 5);
   /*assert.deepEqual(qp, {'grant_type': ['authorization_code'],
   'redirect_uri': ['https://example.com/rp/authz_cb'],
   'client_id': ['zls2qhN1jO6A'],
   'state': ['Oh3w3gKlvoM2ehFqlxI3HIK5'],
   'code': ['Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01']});*/
   assert.deepEqual(info['headers'], {
       'Authorization': {"zls2qhN1jO6A": "c8434f28cf9375d9a7"},
       'Content-Type': 'application/x-www-form-urlencoded'});

   let payload = {'sub': '1b2fc9341a16ae4e30082965d537', 'acr': 'PASSWORD',
   'auth_time': 1517736988, 'nonce': NONCE};

   let token = new Message();
   token.addOptionalClaims(payload);
   token.toJWT('shhh', {algorithm: 'HS256'}).then(function(jws){
       resp = {
           "state": "Oh3w3gKlvoM2ehFqlxI3HIK5",
           "scope": "openid",
           "access_token": "Z0FBQUFBQmFkdFF",
           "token_type": "Bearer",
           "id_token": jws}

    serviceContext.issuer = OP_BASEURL;

    let resp2 = service['accessToken'].parseResponse(JSON.stringify(resp), null, STATE);
    resp2.verify();
    assert.deepEqual(Object.keys(resp2.claims['verified_id_token']).length, 5);
    service['accessToken'].updateServiceContext(resp2, STATE);
    let item3 = service['authorization'].getItem(AccessTokenResponse, 'token_response', STATE);
    console.log(item3);
    assert.deepEqual(Object.keys(item3.claims).length, 6);
    assert.deepEqual(item3.claims['token_type'], 'Bearer');
    assert.deepEqual(item3.claims['access_token'], 'Z0FBQUFBQmFkdFF');

    // User Info

    info = service['userinfo'].getRequestParameters({params: {state:STATE}});
    assert.deepEqual(info['url'], 'https://example.org/op/userInfo');
    let header = {'Authorization': 'Bearer Z0FBQUFBQmFkdFF'};
    assert.deepEqual(info['headers'], header);

    let opResp = {"sub": "1b2fc9341a16ae4e30082965d537"}
    resp = service['userinfo'].parseResponse(JSON.stringify(opResp), null, STATE);
    service['userinfo'].updateServiceContext(resp, STATE);
    assert.deepEqual(resp.claims, {'sub': '1b2fc9341a16ae4e30082965d537'});

    let item4 = service['authorization'].getItem(OpenIDSchema, 'userinfo', STATE);
    assert.deepEqual(item4.claims, {'sub': '1b2fc9341a16ae4e30082965d537'});
});

  /*
  let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']
  };
  serviceContext = new ServiceContext(null, config);
  let db = new DB();
  //let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
  //let authResponse = new AuthorizationResponse({code:'access_code'});
  //let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
  //db.set('state', _state.toJSON());
  db.set('state', State.toJSON({auth_request: AuthorizationRequest.toJSON({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'}), auth_response: AuthorizationResponse.toJSON({code:'access_code'})}));
  service = new factory('AccessToken', serviceContext, db);

var reqArgs = {
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'
  };
  service.endpoint = 'https://example.com/authorize';
  var info = service.getRequestParameters({requestArgs: reqArgs, authnMethod:'client_secret_basic', params: {state: 'state'}});
  assert.deepEqual(Object.keys(info).length, 4);
  assert.deepEqual(info.url, 'https://example.com/authorize');
  /*var msg = new AccessTokenRequest().fromUrlEncoded(
  service.getUrlInfo(info['body']));*/

  /*
  var msg = AccessTokenRequest.fromUrlEncoded(
    service.getUrlInfo(info['body']));
  assert.deepEqual(msg['claims'], {
    'client_id': 'client_id',
    'code': 'access_code',
    'grant_type': 'authorization_code',
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'state': 'state'
  });
  assert.deepEqual(Object.keys(msg).indexOf('client_secret'), -1);

  /*

let service;
let config = {
'client_id': 'client_id',
'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']
};
serviceContext = new ServiceContext(null, config);
service = new factory('Authorization', serviceContext, new DB());

/*
var reqArgs = {'response_type': 'code'};
service.endpoint = 'https://example.com/authorize';
var info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
assert.deepEqual(Object.keys(info), ['method', 'url']);
var msg = AuthorizationRequest.fromUrlEncoded(
service.getUrlInfo(info['url']));
assert.deepEqual(Object.keys(msg).length, 6);

/*
let services = getServices();


let clientConfig = {
    "client_preferences":
        {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.org"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
    "redirect_uris": [RP_BASEURL + "/authz_cb"],
    "jwks_uri": RP_BASEURL + "/static/jwks.json"
}
serviceContext = new ServiceContext(null, clientConfig);
let serviceSpec = DEFAULT_SERVICES;
serviceSpec['WebFinger'] = {};
let service = buildServices(serviceSpec, factory, serviceContext, new DB());
serviceContext.service = service

//TEST BUILD SERVICES
assert.deepEqual(Object.keys(service).length, 7);

// TEST WEBFINGER 
let info = service['webfinger'].getRequestParameters({requestArgs:{'resource': 'foobar@example.org'}});
assert.deepEqual(info['url'], 'https://example.org/.well-known/webfinger?resource=acct%3Afoobar%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');
let webfingerResponse = JSON.stringify({
    "subject": "acct:foobar@example.org",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://example.org/op"}],
    "expires": "2018-02-04T11:08:41Z"});
let response = service['webfinger'].parseResponse(webfingerResponse);
assert.deepEqual(Object.keys(response), ['subject', 'links', 'expires']);
assert.deepEqual(response['links'], [
    {'rel': 'http://openid.net/specs/connect/1.0/issuer',
        'href': 'https://example.org/op'}]);
service['webfinger'].updateServiceContext(response);
assert.deepEqual(serviceContext.issuer, OP_BASEURL);

info = service['provider_info'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/.well-known/openid-configuration');
let providerInfoResponse = JSON.stringify({
    "version": "3.0",
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "claims_parameter_supported": true,
    "request_parameter_supported": true,
    "request_uri_parameter_supported": true,
    "require_request_uri_registration": true,
    "grant_types_supported": ["authorization_code",
                            "implicit",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer",
                            "refresh_token"],
    "response_types_supported": ["code", "id_token",
                                "id_token token",
                                "code id_token",
                                "code token",
                                "code id_token token"],
    "response_modes_supported": ["query", "fragment",
                                "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "claim_types_supported": ["normal", "aggregated",
                            "distributed"],
    "claims_supported": ["birthdate", "address",
                        "nickname", "picture", "website",
                        "email", "gender", "sub",
                        "phone_number_verified",
                        "given_name", "profile",
                        "phone_number", "updated_at",
                        "middle_name", "name", "locale",
                        "email_verified",
                        "preferred_username", "zoneinfo",
                        "family_name"],
    "scopes_supported": ["openid", "profile", "email",
                        "address", "phone",
                        "offline_access", "openid"],
    "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512", "none"],
    "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512"],
    "userinfo_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "id_token_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "request_object_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "userinfo_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "id_token_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "request_object_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "acr_values_supported": ["PASSWORD"],
    "issuer": OP_BASEURL,
    "jwks_uri": OP_BASEURL + "/static/jwks_tE2iLbOAqXhe8bqh.json",
    "authorization_endpoint": OP_BASEURL + "/authorization",
    "token_endpoint": OP_BASEURL + "/token",
    "userinfo_endpoint": OP_BASEURL + "/userinfo",
    "registration_endpoint": OP_BASEURL + "/registration",
    "end_session_endpoint": OP_BASEURL + "/end_session"});
response = service['provider_info'].parseResponse(providerInfoResponse);
service['provider_info'].updateServiceContextProviderInfo(response);

assert.deepEqual(serviceContext.providerInfo['issuer'], OP_BASEURL);
assert.deepEqual(serviceContext.providerInfo['authorization_endpoint'], 'https://example.org/op/authorization');
assert.deepEqual(serviceContext.providerInfo['registration_endpoint'], 'https://example.org/op/registration');

info = service['registration'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/registration');
let body = JSON.parse(info['body']);

assert.equal(Object.keys(body).length, 7);

assert.deepEqual(info['headers'], {'Content-Type': 'application/json'});

let now = Date.now();

let opClientRegistrationResponse = JSON.stringify({
    "client_id": "zls2qhN1jO6A",
    "client_secret": "c8434f28cf9375d9a7",
    "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
    "registration_client_uri": RP_BASEURL + "/registration?client_id=zls2qhN1jO6A",
    "client_secret_expires_at": now + 3600,
    "application_type": "web",
    "client_id_issued_at": now + 1,    
    "response_types": ["code"],
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": [RP_BASEURL + "/authz_cb"]});

response = service['registration'].parseResponse(opClientRegistrationResponse);
service['registration'].updateServiceContext(response);

assert.deepEqual(serviceContext.client_id, 'zls2qhN1jO6A');
assert.deepEqual(serviceContext.client_secret, 'c8434f28cf9375d9a7');
assert.deepEqual(Object.keys(serviceContext.registrationResponse).length, 11);
/*



let request = services['accessToken'].construct(null,
    {'redirect_uri': 'http://example.com', 'state': 'ABCDE'});
  let csp = new ClientSecretPost();
  let list = csp.construct(request, services['accessToken']);
  let httpArgs = list[0];
  request = list[1];

  assert.deepEqual(request['client_id'], 'A');
  assert.deepEqual(request['client_secret'], 'boarding pass');
  assert.deepEqual(httpArgs, undefined);

  let request2 = new AccessTokenRequest(
    {'code': 'foo', 'redirect_uri': 'http://example.com'});
  let list2 = csp.construct(
    request2, services['accessToken'], null, {'client_secret': 'another'});
  let httpArgs2 = list2[0];
  request2 = list2[1];
  assert.deepEqual(request2['client_id'], 'A');
  assert.deepEqual(request2['client_secret'], 'another');
  assert.deepEqual(httpArgs2, null);
/*
services['authorization'].stateDb.set('AAAA', State.toJSON({iss:'Issuer'}));
services['authorization'].parseResponse(AuthorizationResponse.toUrlEncoded({code:'auth_grant', state: 'AAAA'}), 'urlencoded');
// based on state find the code and then get an access token
let response2 = services['accessToken'].parseResponse(
  AccessTokenResponse.toUrlEncoded({
    access_token: 'token1',
    token_type: 'Bearer',
    expires_in: 0,
    state: 'AAAA',
  }), 'urlencoded');
services['accessToken'].updateServiceContext(response2, 'AAAA');
const httpArgs = new BearerHeader().construct(
  new ResourceRequest(), services['accessToken'], null,{state: 'AAAA'});
assert.deepEqual(httpArgs, {headers: {Authorization: 'Bearer token1'}});

/*
let authSrv = services['authorization'];
let accessTokenSrv = services['accessToken'];

 authSrv.stateDb.set('EEEE', State.toJSON({iss:'Issuer'}));
    let response = authSrv.parseResponse(AuthorizationResponse.toUrlEncoded({code:'auth_grant', state:'EEEE'}), 'urlencoded');
    authSrv.updateServiceContext(response, 'EEEE');
    let response2 = accessTokenSrv.parseResponse(
        AccessTokenResponse.toUrlEncoded({
        access_token: 'token1',
        token_type: 'Bearer',
        expires_in: 0,
        state: 'EEEE',
      }), 'urlencoded');
    authSrv.updateServiceContext(response2, 'EEEE');
    let request = new ResourceRequest();
    const list = new BearerBody().construct(
      request, authSrv, null, {state: 'EEEE'});
    request = list[1];
    assert.isTrue(Object.keys(request).indexOf('access_token') !== -1);
    assert.deepEqual(request.access_token, 'token1');

/*
  const sdb = authSrv.stateDb;
  authSrv.stateDb.set('FFFF', State.toJSON({iss:'Issuer'}));
  
  const resp = new AuthorizationResponse({code:'code', state:'FFFFF'});
  authSrv.storeItem(resp, 'auth_response', 'FFFFF');
  const atr = new AccessTokenResponse({
    access_token: '2YotnFZFEjr1zCsicMWpAA',
    token_type: 'example',
    refresh_token: 'tGzv3JOkF0XG5Qx2TlKWIA',
    example_parameter: 'example_value',
    scope: ['inner', 'outer'],
  });
  authSrv.storeItem(atr, 'token_response', 'FFFFF');
  let request = new ResourceRequest();
  const list = new BearerBody().construct(
    request, authSrv, null, {state: 'FFFFF'});
  const httpArgs = list[0];
  request = list[1];
  assert.deepEqual(request.access_token, '2YotnFZFEjr1zCsicMWpAA');
  assert.deepEqual(httpArgs, null);
/*

let service;
let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']
  };
  serviceContext = new ServiceContext(null, config);
  let db = new DB();
  let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
  let authResponse = new AuthorizationResponse({code:'access_code'});
  let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
  db.set('state', _state.toJSON());
  service = new factory('AccessToken', serviceContext, db);

  var reqArgs = {
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'
  };
  service.endpoint = 'https://example.com/authorize';
  var info = service.getRequestParameters({requestArgs: reqArgs, authnMethod:'client_secret_basic', params: {state: 'state'}});
  assert.deepEqual(Object.keys(info).length, 4);
  assert.deepEqual(info.url, 'https://example.com/authorize');

  var msg = new AccessTokenRequest().fromUrlEncoded(
  service.getUrlInfo(info['body']));
  assert.deepEqual(msg['claims'], {
    'client_id': 'client_id',
    'code': 'access_code',
    'grant_type': 'authorization_code',
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'state': 'state'
  });
  assert.deepEqual(Object.keys(msg).indexOf('client_secret'), -1);
  assert.isNotNull(Object.keys(info['headers'].Authorization)); 

/*



let clientConfig = {
    "client_preferences":
        {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.org"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
    "redirect_uris": [RP_BASEURL + "/authz_cb"],
    "jwks_uri": RP_BASEURL + "/static/jwks.json"
}
serviceContext = new ServiceContext(null, clientConfig);
let serviceSpec = DEFAULT_SERVICES;
serviceSpec['WebFinger'] = {};
let service = buildServices(serviceSpec, factory, serviceContext, new DB(), CLIENT_AUTHN_METHOD);
serviceContext.service = service;
assert.deepEqual(Object.keys(service).length, 8); 

// TEST WEBFINGER 
let info = service['webfinger'].getRequestParameters({requestArgs:{'resource': 'foobar@example.org'}});
assert.deepEqual(info['url'], 'https://example.org/.well-known/webfinger?resource=acct%3Afoobar%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');
let webfingerResponse = JSON.stringify({
    "subject": "acct:foobar@example.org",
    "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": "https://example.org/op"}],
    "expires": "2018-02-04T11:08:41Z"});
let response = service['webfinger'].parseResponse(webfingerResponse);
assert.deepEqual(Object.keys(response.claims), ['subject', 'links', 'expires']);
assert.deepEqual(response.claims['links'], [
    {'rel': 'http://openid.net/specs/connect/1.0/issuer',
        'href': 'https://example.org/op'}]);
service['webfinger'].updateServiceContext(response);
assert.deepEqual(serviceContext.issuer, OP_BASEURL);

// TEST PROVIDER INFO
info = service['provider_info'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/.well-known/openid-configuration');
let providerInfoResponse = JSON.stringify({
    "version": "3.0",
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "claims_parameter_supported": true,
    "request_parameter_supported": true,
    "request_uri_parameter_supported": true,
    "require_request_uri_registration": true,
    "grant_types_supported": ["authorization_code",
                              "implicit",
                              "urn:ietf:params:oauth:grant-type:jwt-bearer",
                              "refresh_token"],
    "response_types_supported": ["code", "id_token",
                                 "id_token token",
                                 "code id_token",
                                 "code token",
                                 "code id_token token"],
    "response_modes_supported": ["query", "fragment",
                                 "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "claim_types_supported": ["normal", "aggregated",
                              "distributed"],
    "claims_supported": ["birthdate", "address",
                         "nickname", "picture", "website",
                         "email", "gender", "sub",
                         "phone_number_verified",
                         "given_name", "profile",
                         "phone_number", "updated_at",
                         "middle_name", "name", "locale",
                         "email_verified",
                         "preferred_username", "zoneinfo",
                         "family_name"],
    "scopes_supported": ["openid", "profile", "email",
                         "address", "phone",
                         "offline_access", "openid"],
    "userinfo_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "id_token_signing_alg_values_supported": [
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "HS256", "HS384", "HS512",
        "PS256", "PS384", "PS512", "none"],
    "request_object_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512", "none"],
    "token_endpoint_auth_signing_alg_values_supported": [
        "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "HS256", "HS384", "HS512", "PS256",
        "PS384", "PS512"],
    "userinfo_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "id_token_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "request_object_encryption_alg_values_supported": [
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW",
        "A192KW", "A256KW", "ECDH-ES", "ECDH-ES+A128KW",
        "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "userinfo_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "id_token_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "request_object_encryption_enc_values_supported": [
        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128GCM", "A192GCM", "A256GCM"],
    "acr_values_supported": ["PASSWORD"],
    "issuer": OP_BASEURL,
    "jwks_uri": OP_BASEURL + "/static/jwks_tE2iLbOAqXhe8bqh.json",
    "authorization_endpoint": OP_BASEURL + "/authorization",
    "token_endpoint": OP_BASEURL + "/token",
    "userinfo_endpoint": OP_BASEURL + "/userinfo",
    "registration_endpoint": OP_BASEURL + "/registration",
    "end_session_endpoint": OP_BASEURL + "/end_session"});
response = service['provider_info'].parseResponse(providerInfoResponse);
service['provider_info'].updateServiceContextProviderInfo(response);

assert.deepEqual(serviceContext.providerInfo.claims['issuer'], OP_BASEURL);
assert.deepEqual(serviceContext.providerInfo.claims['authorization_endpoint'], 'https://example.org/op/authorization');
assert.deepEqual(serviceContext.providerInfo.claims['registration_endpoint'], 'https://example.org/op/registration');

// REGISTRATION

info = service['registration'].getRequestParameters();
assert.deepEqual(info['url'], 'https://example.org/op/registration');
let body = JSON.parse(info['body']);

assert.equal(Object.keys(body).length, 7);

assert.deepEqual(info['headers'], {'Content-Type': 'application/json'});

let now = Date.now();

let opClientRegistrationResponse = JSON.stringify({
    "client_id": "zls2qhN1jO6A",
    "client_secret": "c8434f28cf9375d9a7",
    "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
    "registration_client_uri": RP_BASEURL + "/registration?client_id=zls2qhN1jO6A",
    "client_secret_expires_at": now + 3600,
    "application_type": "web",
    "client_id_issued_at": now + 1,    
    "response_types": ["code"],
    "contacts": ["ops@example.com"],
    "token_endpoint_auth_method": "client_secret_basic",
    "redirect_uris": [RP_BASEURL + "/authz_cb"]});

response = service['registration'].parseResponse(opClientRegistrationResponse);
service['registration'].updateServiceContext(response);

assert.deepEqual(serviceContext.client_id, 'zls2qhN1jO6A');
assert.deepEqual(serviceContext.client_secret, 'c8434f28cf9375d9a7');
assert.deepEqual(Object.keys(serviceContext.registrationResponse).length, 11);


// AUTHORIZATION
const STATE = 'Oh3w3gKlvoM2ehFqlxI3HIK5'
const NONCE = 'UvudLKz287YByZdsY3AJoPAlEXQkJ0dK'

info = service['authorization'].getRequestParameters({requestArgs:{'state': STATE, 'nonce': NONCE}});

let p = urlParse(info['url']);
let parsedResp = new Message().fromUrlEncoded(p.query.substring(1, p.query.length));
let query = parseQs(parsedResp.claims);
assert.deepEqual(Object.keys(query).length, 6);
assert.deepEqual(query['scope'], ['openid']);
assert.deepEqual(query['nonce'], [NONCE]);
assert.deepEqual(query['state'], [STATE]);

let opAuthzResp = {
    'state': STATE,
    'scope': 'openid',
    'code': 'Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01',
    'iss': OP_BASEURL,
    'client_id': 'zls2qhN1jO6A'};

let authzRep = new AuthorizationResponse(opAuthzResp);
let resp = service['authorization'].parseResponse(authzRep.toUrlEncoded(authzRep.claims));

service['authorization'].updateServiceContext(resp, STATE);
let item2 = service['authorization'].getItem(AuthorizationResponse, 'auth_response', STATE);
assert.deepEqual(item2.claims['code'], 'Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01');

// Access Token
let requestArgs = {'state': STATE,
'redirect_uri': serviceContext.redirectUris[0]};

info = service['accessToken'].getRequestParameters({requestArgs: requestArgs});
assert.deepEqual(info['url'], 'https://example.org/op/token');
body = info['body'];
query = new Message().fromUrlEncoded(body);
let qp = parseQs(query.claims);
assert.deepEqual(qp, {'grant_type': ['authorization_code'],
'redirect_uri': ['https://example.com/rp/authz_cb'],
'client_id': ['zls2qhN1jO6A'],
'state': ['Oh3w3gKlvoM2ehFqlxI3HIK5'],
'code': ['Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01']});
assert.deepEqual(info['headers'], {
    'Authorization': {"zls2qhN1jO6A": "c8434f28cf9375d9a7"},
    'Content-Type': 'application/x-www-form-urlencoded'});

let payload = {'sub': '1b2fc9341a16ae4e30082965d537', 'acr': 'PASSWORD',
'auth_time': 1517736988, 'nonce': NONCE};

let token = new Message();
token.addOptionalClaims(payload);
let jws = token.toJWT('shhh', {algorithm: 'HS256'});

resp = {
    "state": "Oh3w3gKlvoM2ehFqlxI3HIK5",
    "scope": "openid",
    "access_token": "Z0FBQUFBQmFkdFF",
    "token_type": "Bearer",
    "id_token": jws}

serviceContext.issuer = OP_BASEURL;

let resp2 = service['accessToken'].parseResponse(JSON.stringify(resp), null, STATE);
resp2.verify();
assert.deepEqual(Object.keys(resp2.claims['verified_id_token']).length, 5);
service['accessToken'].updateServiceContext(resp2, STATE);
let item3 = service['authorization'].getItem(AccessTokenResponse, 'token_response', STATE);
console.log(item3);
assert.deepEqual(Object.keys(item3.claims).length, 6);
assert.deepEqual(item3.claims['token_type'], 'Bearer');
assert.deepEqual(item3.claims['access_token'], 'Z0FBQUFBQmFkdFF');

// User Info

info = service['userinfo'].getRequestParameters({params: {state:STATE}});
assert.deepEqual(info['url'], 'https://example.org/op/userInfo');
let header = {'Authorization': 'Bearer Z0FBQUFBQmFkdFF'};
assert.deepEqual(info['headers'], header);

let opResp = {"sub": "1b2fc9341a16ae4e30082965d537"}
resp = service['userinfo'].parseResponse(JSON.stringify(opResp), null, STATE);
service['userinfo'].updateServiceContext(resp, STATE);
assert.deepEqual(resp.claims, {'sub': '1b2fc9341a16ae4e30082965d537'});

let item4 = service['authorization'].getItem(OpenIDSchema, 'userinfo', STATE);
assert.deepEqual(item4.claims, {'sub': '1b2fc9341a16ae4e30082965d537'});

/* 
let iss = 'https://example.com/as';

let clientConfig = {
'client_id': 'client_id',
'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'behaviour': {'response_types': ['code']}
}
serviceContext = new ServiceContext(null, clientConfig);
service = new factory('Authorization', serviceContext, new DB(), CLIENT_AUTHN_METHOD, conf={
'request_args': {
    'claims': {
        "id_token":
            {
                "auth_time": {"essential": true},
                "acr": {"values": ["urn:mace:incommon:iap:silver"]}
            }}}});

let req = service.construct();
assert.isTrue(Object.keys(req).indexOf('claims') !== -1);
assert.deepEqual(Object.keys(req.claims), ['id_token']);

/*

let client_config = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': 'https://example.com/as',
'client_preferences': {
    'id_token_signed_response_alg': 'RS384',
    'userinfo_signed_response_alg': 'RS384'
}}
serviceContext= new ServiceContext(null, client_config, {jwks:'{"keys":[]}'});
let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
let list = addJwksUriOrJwks({}, service);
let reqArgs = list[0];
let postArgs = list[1];
assert.deepEqual(reqArgs['jwks'], '{"keys":[]}');

/*let client_config = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'jwks_uri': 'https://example.com/jwks/jwks.json',
'issuer': 'https://example.com/as',
'client_preferences': {
    'id_token_signed_response_alg': 'RS384',
    'userinfo_signed_response_alg': 'RS384'
}}
serviceContext= new ServiceContext(null, client_config);
let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
let list = addJwksUriOrJwks({}, service);
let reqArgs = list[0];
let postArgs = list[1];
assert.deepEqual(reqArgs['jwks_uri'], 'https://example.com/jwks/jwks.json');*/

/*
let client_config = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': 'https://example.com/as',
'client_preferences': {
    'id_token_signed_response_alg': 'RS384',
    'userinfo_signed_response_alg': 'RS384'
}}
serviceContext= new ServiceContext(null, client_config, {jwks_uri:'https://example.com/jwks/jwks.json'});
let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
let list = addJwksUriOrJwks({}, service);
let reqArgs = list[0];
let postArgs = list[1];
assert.deepEqual(reqArgs['jwks_uri'], 'https://example.com/jwks/jwks.json');
/*
let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': iss, 'requests_dir': 'requests',
'base_url': 'https://example.com/cli/'};
serviceContext = new ServiceContext(null, clientConfig);

/*

let db = new DB();
let tokenResponse = new AccessTokenResponse({access_token:'access_token', id_token:'a.signed.jwt', verified_id_token:{sub:'diana'}});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({token_response: tokenResponse.toJSON(), auth_response: authResponse.toJSON()});
db.set('abcde', _state.toJSON());
service = new factory('UserInfo', serviceContext, db, CLIENT_AUTHN_METHOD);

let resp = new OpenIDSchema({sub:'diana', given_name:'Diana', family_name:'krall'});
resp = service.parseResponse(resp.toJSON(), null, null, {state:'abcde'});
assert.isNotNull(resp);*/

/*
let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': iss, 'requests_dir': 'requests',
'base_url': 'https://example.com/cli/'};
serviceContext = new ServiceContext(null, clientConfig);
service = new factory('EndSession', serviceContext, new DB(), CLIENT_AUTHN_METHOD);

service.storeItem(new Message({'id_token': 'a.signed.jwt'}), 'token_response', 'abcde');
let msg = service.construct(null, {state: 'abcde'});
assert.deepEqual(Object.keys(msg.claims).length, 1);

/*

let iss = 'https://example.com/as';
let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': iss, 'requests_dir': 'requests',
'base_url': 'https://example.com/cli/'};
serviceContext = new ServiceContext(null, clientConfig);
service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);

service.serviceContext.providerInfo['require_request_uri_registration'] = true
let req = service.construct();
assert.deepEqual(Object.keys(req.claims).length, 5);
assert.isTrue(Object.keys(req.claims).indexOf('request_uris') !== -1);

/*
service.serviceContext.post_logout_redirect_uris = ['https://example.com/post_logout'];
let req = service.construct();
assert.deepEqual(Object.keys(req.claims).length, 5);
assert.isTrue(Object.keys(req.claims).indexOf('post_logout_redirect_uris') !== -1);

/*
let msg = service.construct();
assert.deepEqual(Object.keys(msg.claims).length, 4);

/*
let services = getServices();
services['authorization'].stateDb.set('AAAA', new State({iss:'Issuer'}).toJSON());
const resp1 = new AuthorizationResponse({code:'auth_grant', state: 'AAAA'});
services['authorization'].parseResponse(resp1.toUrlEncoded({code:'auth_grant', state: 'AAAA'}), 'urlencoded');
// based on state find the code and then get an access token
const resp2 = new AccessTokenResponse({
  access_token: 'token1',
  token_type: 'Bearer',
  expires_in: 0,
  state: 'AAAA',
});
let response2 = services['accessToken'].parseResponse(
  resp2.toUrlEncoded({
    access_token: 'token1',
    token_type: 'Bearer',
    expires_in: 0,
    state: 'AAAA',
  }), 'urlencoded');
services['accessToken'].updateServiceContext(response2, 'AAAA');
const httpArgs = new BearerHeader().construct(
  new ResourceRequest(), services['accessToken'], null,{state: 'AAAA'});
assert.deepEqual(httpArgs, {headers: {Authorization: 'Bearer token1'}});
*/

/*
let iss = 'https://example.com/as';
let clientConfig ={'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb'],
'issuer': iss,
'client_preferences': {
    'id_token_signed_response_alg': 'RS384',
    'userinfo_signed_response_alg': 'RS384'
}}
serviceContext = new ServiceContext(null, clientConfig);
service = new factory('ProviderInfoDiscovery', serviceContext, null, CLIENT_AUTHN_METHOD);

let info = service.getRequestParameters()
assert.deepEqual(Object.keys(info), ['method', 'url']);
assert.deepEqual(info['url'], iss + '/.well-known/openid-configuration');

/*

let clientConfig ={'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']};
serviceContext = new ServiceContext(null, clientConfig);
let db = new DB();
let authRequest = new AuthorizationRequest({redirect_uri: 'https://example.com/cli/authz_cb', state:'state', response_type:'code'});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
db.set('state', _state.toJSON());
service = new factory('AccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);

service.storeNonce2State('nonce', 'state');
let resp = new AccessTokenResponse({verifiedIdToken:{nonce:'nonce'}});
service.storeNonce2State('nonce2', 'state2');
try{
    service.updateServiceContext(resp, 'state2')
}catch(err){
    console.log(err)
}

/*

let requestArgs = {'redirect_uri': 'https://example.com/cli/authz_cb',
'code': 'access_code'}
service.endpoint = 'https://example.com/authorize'
info = service.getRequestParameters({requestArgs:requestArgs, authnMethod:'client_secret_basic', params: {state: 'state'}});
assert.deepEqual(Object.keys(info), ['method', 'url', 'body', 'headers']);
assert.deepEqual(info.url, 'https://example.com/authorize');
let msg = new AccessTokenRequest().fromUrlEncoded(service.getUrlInfo(info['body']));
assert.deepEqual(msg.claims, {
  'client_id': 'client_id', 'code': 'access_code',
  'grant_type': 'authorization_code', 'state': 'state',
  'redirect_uri': 'https://example.com/cli/authz_cb'});

/* 
let clientConfig ={'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']};
serviceContext = new ServiceContext(null, clientConfig);
let db = new DB();
let authRequest = new AuthorizationRequest({redirect_uri: 'https://example.com/cli/authz_cb', state:'state', response_type:'code'});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
db.set('state', _state.toJSON());
service = new factory('AccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);
/*let ci = new ServiceContext(null, config, {client_id:'client_id', issuer: 'https://www.example.org/as'});
let service = new DummyService(ci, new DB());
let state = new State({iss:'Issuer'});
service.stateDb.set('state', state.toJSON())
let spec = addCodeChallenge({state: 'state'}, service);

assert.deepEqual(
Object.keys(spec), ['state', 'code_challenge', 'code_challenge_method']);
assert.deepEqual(spec['code_challenge_method'], 'sha256');

let codeVerifier = addCodeVerifier({}, service, {state: 'state'});
assert.deepEqual(codeVerifier.length, 64);*/

/*
let requestArgs = {'foo': 'bar'}
let msg = service.construct(requestArgs, {'state': 'state'});
assert.deepEqual(Object.keys(msg.claims), ['foo', 'redirect_uri', 'state', 'code', 'grant_type', 'client_id', 'client_secret']);

/*

const ATTRMAP = {
    'userinfo': {
        'sign': 'userinfo_signed_response_alg',
        'alg': 'userinfo_encrypted_response_alg',
        'enc': 'userinfo_encrypted_response_enc'
    },
    'id_token': {
        'sign': 'id_token_signed_response_alg',
        'alg': 'id_token_encrypted_response_alg',
        'enc': 'id_token_encrypted_response_enc'
    },
    'request': {
        'sign': 'request_object_signing_alg',
        'alg': 'request_object_encryption_alg',
        'enc': 'request_object_encryption_enc'
    }
};

const DEFAULT_SIGN_ALG = {
'userinfo': 'RS256',
'request': 'RS384',
'id_token': 'ES384',
};

const CLIENT_ID = 'A';

const CLIENT_CONF = {
  issuer: 'https://example.com/as',
  redirect_uris: ['https://example.com/cli/authz_cb'],
  client_secret: 'boarding pass',
  client_id: CLIENT_ID,
};

const REQ_ARGS = {
  redirect_uri: 'https://example.com/rp/cb',
  response_type: 'code',
};

class DB{
  constructor(){
    this.db = {};
  }

  set(key, value){
    this.db[key] = value;
  }

  get(item){
    return this.db[item];
  }
}

function getService(){
  let serviceContext = new ServiceContext(null, CLIENT_CONF);
  serviceContext.client_secret = 'boarding pass';
  return serviceContext;
}

function getServiceContext(){
  let serviceContext = new ServiceContext(null, CLIENT_CONF);
  serviceContext.client_secret = 'boarding pass';
  return serviceContext;
}

function getServices(){
  let db = new DB();
  let authRequest = new AuthorizationRequest().toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
  let authResponse = new AuthorizationResponse().toJSON({access_token: 'token', state: 'ABCDE'});
  db.set('ABCDE', new State().toJSON({iss:'Issuer', auth_request:authRequest, auth_response:authResponse}));
  return buildServices(DEFAULT_SERVICES, OicFactory, getServiceContext(), db, CLIENT_AUTHN_METHOD);
}

let services = getServices();

function signEncAlgs(serviceContext, typ) {
    let resp = {};
    for (let i = 0; i < Object.keys(ATTRMAP[typ]).length; i++) {
        let key = Object.keys(ATTRMAP[typ])[i];
        let val = ATTRMAP[typ][key];
        if (serviceContext.registrationResponse && serviceContext.registrationResponse[val]){
        resp[key] = serviceContext.registrationResponse[val];
        }else if (key === 'sign') {
        try {
            resp[key] = DEFAULT_SIGN_ALG[typ];
        } catch (err) {
            return;
        }
        }
    }
    return resp;
}

function verifyAlgSupport(serviceContext, alg, usage, typ) {
    let supported = serviceContext.providerInfo[usage + '_' + typ + '_values_supported'];
    if (supported.indexOf(alg) !== -1) {
        return true;
    } else {
        return false;
    }
}

class Response {
    constructor(statusCode, text, headers = null) {
        this.statusCode = statusCode;
        this.text = text;
        this.headers = headers || {'content-type': 'text/plain'};
        return this;
    }
}

let KEYSPEC = [
    {'type': 'RSA', 'use': ['sig']},
    {'type': 'EC', 'crv': 'P-256', 'use': ['sig']},
];

function testRequestFactory() {
    let req = new factory('Service', new ServiceContext(null), new DB(), null);
    assert.deepEqual(req, Service);
}
  
let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']}
serviceContext = new ServiceContext(null, clientConfig);
service = new factory('Authorization', serviceContext, new DB(), CLIENT_AUTHN_METHOD)

let requestArgs = {'foo': 'bar', 'response_type': 'code',
'state': 'state'}
let msg = service.construct(requestArgs);
assert.deepEqual(Object.keys(msg.claims), ['foo',
'response_type', 'state', 'redirect_uri', 'scope',
'nonce', 'client_id']);


      //assert.deepEqual(msg.claims['client_id'], 'client_1');
      //assert.deepEqual(msg.claims['redirect_uri'], 'https://example.com/auth_cb');

  /*

const EXAMPLE = {
    'example.com': 'https://example.com',
    'example.com:8080': 'https://example.com:8080',
    'example.com/path': 'https://example.com/path',
    'example.com?query': 'https://example.com?query',
    'example.com#fragment': 'https://example.com',
    'example.com:8080/path?query#fragment': 'https://example.com:8080/path?query',
    'http://example.com': 'http://example.com',
    'http://example.com:8080': 'http://example.com:8080',
    'http://example.com/path': 'http://example.com/path',
    'http://example.com?query': 'http://example.com?query',
    'http://example.com#fragment': 'http://example.com',
    'http://example.com:8080/path?query#fragment':
        'http://example.com:8080/path?query',
    'nov@example.com': 'acct:nov@example.com',
    'nov@example.com:8080': 'https://nov@example.com:8080',
    'nov@example.com/path': 'https://nov@example.com/path',
    'nov@example.com?query': 'https://nov@example.com?query',
    'nov@example.com#fragment': 'acct:nov@example.com',
    'nov@example.com:8080/path?query#fragment':
        'https://nov@example.com:8080/path?query',
    'acct:nov@matake.jp': 'acct:nov@matake.jp',
    'acct:nov@example.com:8080': 'acct:nov@example.com:8080',
    'acct:nov@example.com/path': 'acct:nov@example.com/path',
    'acct:nov@example.com?query': 'acct:nov@example.com?query',
    'acct:nov@example.com#fragment': 'acct:nov@example.com',
    'acct:nov@example.com:8080/path?query#fragment':
        'acct:nov@example.com:8080/path?query',
    'mailto:nov@matake.jp': 'mailto:nov@matake.jp',
    'mailto:nov@example.com:8080': 'mailto:nov@example.com:8080',
    'mailto:nov@example.com/path': 'mailto:nov@example.com/path',
    'mailto:nov@example.com?query': 'mailto:nov@example.com?query',
    'mailto:nov@example.com#fragment': 'mailto:nov@example.com',
    'mailto:nov@example.com:8080/path?query#fragment':
        'mailto:nov@example.com:8080/path?query',
    'localhost': 'https://localhost',
    'localhost:8080': 'https://localhost:8080',
    'localhost/path': 'https://localhost/path',
    'localhost?query': 'https://localhost?query',
    'localhost#fragment': 'https://localhost',
    'localhost/path?query#fragment': 'https://localhost/path?query',
    'nov@localhost': 'acct:nov@localhost',
    'nov@localhost:8080': 'https://nov@localhost:8080',
    'nov@localhost/path': 'https://nov@localhost/path',
    'nov@localhost?query': 'https://nov@localhost?query',
    'nov@localhost#fragment': 'acct:nov@localhost',
    'nov@localhost/path?query#fragment': 'https://nov@localhost/path?query',
    'tel:+810312345678': 'tel:+810312345678',
    'device:192.168.2.1': 'device:192.168.2.1',
    'device:192.168.2.1:8080': 'device:192.168.2.1:8080',
    'device:192.168.2.1/path': 'device:192.168.2.1/path',
    'device:192.168.2.1?query': 'device:192.168.2.1?query',
    'device:192.168.2.1#fragment': 'device:192.168.2.1',
    'device:192.168.2.1/path?query#fragment': 'device:192.168.2.1/path?query',
};

for (let i = 0; i < Object.keys(EXAMPLE).length; i++) {
    let key = Object.keys(EXAMPLE)[i];
    let val = EXAMPLE[key];
    let uriNormalizer = new URINormalizer();
    let res = uriNormalizer.normalize(key);
    assert.deepEqual(res, val);
}

/*
let link = new LINK({
    'rel': 'blog',
    'type': 'text/html',
    'href': 'http://blogs.example.com/bob/',
    'titles': {
      'en-us': 'The Magical World of Bob',
      'fr': 'Le monde magique de Bob'
    }
});
assert.deepEqual(link['rel'], 'blog');
assert.deepEqual(link['type'], 'text/html');
assert.deepEqual(link['href'], 'http://blogs.example.com/bob/');
assert.deepEqual(Object.keys(link['titles']).length, 2);

/*
let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']
  };
serviceContext = new ServiceContext(null, config);
let db = new DB();
let tokenResponse = new AccessTokenResponse({access_token:'bearer_token', refresh_token:'refresh'});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({token_response: tokenResponse.toJSON(), auth_response: authResponse.toJSON()});
db.set('abcdef', _state.toJSON());
service = new factory('RefreshAccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);
service.endpoint = 'https://example.com/token';

let req = service.construct(null, {state: 'abcdef'});
//assert.deepEqual(Object.keys(req.claims).length, 4);
assert.deepEqual(Object.keys(req.claims),
  ['refresh_token', 'client_id', 'client_secret', 'grant_type',]);*/

  /*

  class DummyMessage extends Message{
    constructor(){
      super();
      this.cParam = {'req_str': SINGLE_REQUIRED_STRING}
      return this;
    }
  }
  
  class DummyService extends Service{
    constructor(){
      super();
      this.msgType = DummyMessage;
      return this;
    }
  }
  
  class DB{
    constructor(){
      this.db = {};
    }
  
    set(key, value){
      this.db[key] = value;
    }
  
    get(item){
      return this.db[item];
    }
  }
  
let ci;
let spec;
let service;
let state;
let config = {
'client_id': 'client_id',
'issuer': 'issuer',
'client_secret': 'client_secret',
'base_url': 'https://example.com',
'requests_dir': 'requests',
};

ci = new ServiceContext(null, config, {client_id:'client_id', issuer: 'https://www.example.org/as'});
service = new DummyService(ci, new DB());
state = new State({iss:'Issuer'});
service.stateDb.set('state', state.toJSON())
spec = addCodeChallenge({state: 'state'}, service);

assert.deepEqual(
Object.keys(spec), ['code_challenge', 'code_challenge_method', 'state']);
assert.deepEqual(spec['code_challenge_method'], 'sha256');

let codeVerifier = addCodeVerifier({}, service, {state: 'state'});
assert.deepEqual(codeVerifier.length, 64);

/*
let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']
  };
serviceContext = new ServiceContext(null, config);
let db = new DB();
let tokenResponse = new AccessTokenResponse({access_token:'bearer_token', refresh_token:'refresh'});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({token_response: tokenResponse.toJSON(), auth_response: authResponse.toJSON()});
db.set('abcdef', _state.toJSON());
service = new factory('RefreshAccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);
service.endpoint = 'https://example.com/token';

let req = service.construct(null, {state: 'abcdef'});
assert.deepEqual(Object.keys(req.claims).length, 4);
assert.deepEqual(
Object.keys(req.claims),
['grant_type', 'refresh_token', 'client_id', 'client_secret']);

/*

let config = {
'client_id': 'client_id',
'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']
};
serviceContext = new ServiceContext(null, config);
service = new factory('ProviderInfoDiscovery', serviceContext, new DB());
iss = 'https://example.com/as';
config = {
  'client_id': 'client_id',
  'client_secret': 'password',
  'redirect_uris': ['https://example.com/cli/authz_cb'],
  'issuer': iss
};
service.endpoint = iss + '/.well-known/openid-configuration';

let info = service.getRequestParameters()
assert.deepEqual(Object.keys(info), ['method', 'url']);
assert.deepEqual(info['url'], iss + '/.well-known/openid-configuration');
/*
serviceContext = new ServiceContext(null, config);
service = new factory('Authorization', serviceContext, new DB());

var reqArgs = {'response_type': 'code'};
service.endpoint = 'https://example.com/authorize';
var info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
assert.deepEqual(Object.keys(info), ['method', 'url']);
var msg = new AuthorizationRequest().fromUrlEncoded(
  service.getUrlInfo(info['url']));
assert.deepEqual(msg['claims'], {
  'client_id': 'client_id',
  'redirect_uri': 'https://example.com/cli/authz_cb',
  'response_type': 'code',
  'state': 'state'
});*/
/*


let db = new DB();
let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
let authResponse = new AuthorizationResponse({code:'access_code'});
let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
db.set('state', _state.toJSON());
serviceContext = new ServiceContext(null, config);

let service = new factory('AccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);

var reqArgs = {
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'
  };
  service.endpoint = 'https://example.com/authorize';
  var info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
  assert.deepEqual(Object.keys(info).length, 4);
  assert.deepEqual(info['url'], 'https://example.com/authorize');
  var msg = new AccessTokenRequest().fromUrlEncoded(
    service.getUrlInfo(info['body']));
  assert.deepEqual(msg.claims, {
    'client_id': 'client_id',
    'state': 'state',
    'code': 'access_code',
    'grant_type': 'authorization_code',
    'redirect_uri': 'https://example.com/cli/authz_cb'
  });

/*

var reqArgs = {
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'
  };
  service.endpoint = 'https://example.com/authorize';
  var info = service.getRequestParameters({requestArgs: reqArgs, authnMethod:'client_secret_basic', params: {state: 'state'}});
  assert.deepEqual(Object.keys(info).length, 4);
  assert.deepEqual(info.url, 'https://example.com/authorize');

  var msg = new AccessTokenRequest().fromUrlEncoded(
  service.getUrlInfo(info['body']));
  assert.deepEqual(msg['claims'], {
    'client_id': 'client_id',
    'code': 'access_code',
    'grant_type': 'authorization_code',
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'state': 'state'
  });
  assert.deepEqual(Object.keys(msg).indexOf('client_secret'), -1);
  assert.isNotNull(Object.keys(info['headers'].Authorization)); 

/*
let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']
  };

serviceContext = new ServiceContext(null, config);
let service = new factory('Authorization', serviceContext, new DB());

/*
var reqArgs = {'response_type': 'code'};
service.endpoint = 'https://example.com/authorize';
var info = service.requestInfo(
    serviceContext, null, reqArgs, null, null, null, {state: 'state'});
assert.deepEqual(Object.keys(info), ['uri', 'request']);
assert.deepEqual(info['request'], {
    'client_id': 'client_id',
    'redirect_uri': 'https://example.com/cli/authz_cb',
    'response_type': 'code',
    'state': 'state'
});
var msg = new AuthorizationRequest().fromUrlEncoded(
    service.getUrlInfo(info['uri']));
assert.deepEqual(msg['claims'], info['request']);*/

/*
let resp = {client_id:'client_id', redirect_uri: 'https://example.com/cli/authz_cb', response_type : 'code', state:'state'};

var reqArgs = {'response_type': 'code', 'state': 'state'};
service.endpoint = 'https://example.com/authorize';
var info = service.getRequestParameters({requestArgs :reqArgs});
assert.deepEqual(Object.keys(info), ['method', 'url']);
assert.deepEqual(info['httpArgs'], undefined);
var msg = new AuthorizationRequest().fromUrlEncoded(
  service.getUrlInfo(info['url']));
assert.deepEqual(msg['claims'], resp);

/*

let config = {
    'client_id': 'client_id',
    'issuer': 'issuer',
    'client_secret': 'client_secret',
    'base_url': 'https://example.com',
    'requests_dir': 'requests'
  };

let ci = new ServiceContext(null, config);

assert.isNotNull(ci);

ci.registrationResponse = {
'application_type': 'web',
'redirect_uris': [
    'https://client.example.org/callback',
    'https://client.example.org/callback2'
],
'token_endpoint_auth_method': 'client_secret_basic',
'jwks_uri': 'https://client.example.org/my_public_keys.jwks',
'userinfo_encrypted_response_alg': 'RSA1_5',
'userinfo_encrypted_response_enc': 'A128CBC-HS256',
};

let res = signEncAlgs(ci, 'userinfo');
assert.deepEqual(
res, {'sign': 'RS256', 'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'});

config = {
'client_id': 'client_id',
'client_secret': 'password',
'redirect_uris': ['https://example.com/cli/authz_cb']
};

serviceContext = new ServiceContext(null, config);
let service = new factory('Authorization', serviceContext, new DB());


let reqArgs = {'foo': 'bar'};
let req = service.construct(serviceContext, reqArgs, {state: 'state'});
assert.deepEqual(Object.keys(req).length, 4);*/

/*

let request = services['accessToken'].construct(null, null,
    {'redirect_uri': 'http://example.com', 'state': 'ABCDE'});
  let csp = new ClientSecretPost();
  let list = csp.construct(request, services['accessToken']);
  let httpArgs = list[0];
  request = list[1];

  assert.deepEqual(request['client_id'], 'A');
  assert.deepEqual(request['client_secret'], 'boarding pass');
  assert.deepEqual(httpArgs, undefined);

  let request2 = new AccessTokenRequest(
    {'code': 'foo', 'redirect_uri': 'http://example.com'});
  let list2 = csp.construct(
    request2, services['accessToken'], null, {'client_secret': 'another'});
  let httpArgs2 = list2[0];
  request2 = list2[1];
  assert.deepEqual(request2['client_id'], 'A');
  assert.deepEqual(request2['client_secret'], 'another');
  assert.deepEqual(httpArgs2, null);
  

/*let services = getServices();
let authSrv = services['authorization'];
let accessTokenSrv = services['accessToken'];*/

/*
let services = getServices();
let request = services['accessToken'].construct(null, null, {'redirect_uri':
'http://example.com', 'state': 'ABCDE'})
const csb = new ClientSecretBasic();
let httpArgs = csb.construct((request, services['accessToken']))

/*

authSrv.stateDb.set('AAAA', new State({iss:'Issuer'}).toJSON());
const resp1 = new AuthorizationResponse({code:'auth_grant', state: 'AAAA'});
services['authorization'].parseResponse(resp1.toUrlEncoded({code:'auth_grant', state: 'AAAA'}), 'urlencoded');
// based on state find the code and then get an access token
const resp2 = new AccessTokenResponse({
  access_token: 'token1',
  token_type: 'Bearer',
  expires_in: 0,
  state: 'AAAA',
});
let response2 = services['accessToken'].parseResponse(
  resp2.toUrlEncoded({
    access_token: 'token1',
    token_type: 'Bearer',
    expires_in: 0,
    state: 'AAAA',
  }), 'urlencoded');
services['accessToken'].updateServiceContext(response2, 'AAAA');
const httpArgs = new BearerHeader().construct(
  new ResourceRequest(), services['accessToken'], null,{state: 'AAAA'});
assert.deepEqual(httpArgs, {headers: {Authorization: 'Bearer token1'}});
/*
authSrv.stateDb.set('EEEE', new State({iss:'Issuer'}).toJSON());
let resp1 = new AuthorizationResponse();
let response = authSrv.parseResponse(resp1.toUrlEncoded({code:'auth_grant', state:'EEEE'}), 'urlencoded');
authSrv.updateServiceContext(response, 'EEEE');
const resp2 = new AccessTokenResponse({
  access_token: 'token1',
  token_type: 'Bearer',
  expires_in: 0,
  state: 'EEEE',
});
let response2 = accessTokenSrv.parseResponse(
  resp2.toUrlEncoded({
    access_token: 'token1',
    token_type: 'Bearer',
    expires_in: 0,
    state: 'EEEE',
  }), 'urlencoded');
authSrv.updateServiceContext(response2, 'EEEE');
let request = new ResourceRequest();
const list = new BearerBody().construct(
  request, authSrv, null, {state: 'EEEE'});
request = list[1];
assert.isTrue(Object.keys(request).indexOf('access_token') !== -1);
assert.deepEqual(request.access_token, 'token1');

/*
const request = new ResourceRequest({access_token: 'Sesame'});
const bh = new BearerHeader();
const httpArgs = bh.construct(request);
const testDict = {headers: {Authorization: 'Bearer Sesame'}};
assert.deepEqual(testDict, httpArgs);
*/

/*
authSrv.stateDb.set('EEEE', new State({iss:'Issuer'}).toJSON());
let resp1 = new AuthorizationResponse();
let response = authSrv.parseResponse(resp1.toUrlEncoded({code:'auth_grant', state:'EEEE'}), 'urlencoded');
authSrv.updateServiceContext(response, {state:'EEEE'});
const resp2 = new AccessTokenResponse({ 
  access_token: 'token1',
  token_type: 'Bearer',
  expires_in: 0,
  state: 'EEEE',
});
let response2 = accessTokenSrv.parseResponse(
  resp2.toUrlEncoded({
    access_token: 'token1',
    token_type: 'Bearer',
    expires_in: 0,
    state: 'EEEE',
  }), 'urlencoded');
authSrv.updateServiceContext(response2, {state:'EEEE'});
  
let request = new ResourceRequest();
const list = new BearerBody().construct(
  request, authSrv, null, {state: 'EEEE'});
request = list[1];
assert.isTrue(Object.keys(request).indexOf('access_token') !== -1);
assert.deepEqual(request.access_token, 'token1');
*/
/*
function callbackFunc(err, resp){
    if (err){
        throw new Error(err);
    }else{
        console.log(resp);
    }
}
let jrd = wf.webfinger("acct:alice@localhost", callbackFunc);
console.log(jrd);
*/

//let authRequest = new AuthorizationResponse().toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
//getServices();
//let statetest = new State().toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
//console.log(statetest);
/*
const factory = require('./src/oauth2/service/service').Factory;
class Response {
    constructor(statusCode, text, headers) {
      headers = headers || null;
      this.statusCode = statusCode;
      this.text = text;
      this.headers = headers || {'content-type': 'text/plain'};
      return this;
    }
  }
  
  function testServiceFactory() {
    var req = new factory('Service');
    assert.deepEqual(typeof req, Service);
  }
let service;
let serviceContext;
let iss;
  const serv = new factory('ProviderInfoDiscovery');
  service = new serv();
  iss = 'https://example.com/as';
  let config = {
    'client_id': 'client_id',
    'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss
  };
  serviceContext = new ServiceContext();
  serviceContext.init(null, config);
  let req = service.construct(serviceContext);
  assert.deepEqual(Object.keys(req).length, 0);

  

    /*
    var client = getClient();

    var requestArgs = {'state': 'ABCDE',
    'redirect_uri': 'https://example.com/auth_cb',
    'response_type': ['code']};

    var msg = new client.service['Authorization']().construct(client.serviceContext,
    requestArgs); assert.deepEqual(msg['client_id'], 'client_1');
    assert.deepEqual(msg['redirect_uri'], 'https://example.com/auth_cb');
    *

    let service;
    let serviceContext;
    let iss;
    const serv = new factory('AccessToken', null, null, CLIENT_AUTHN_METHOD);
    service = new serv();
    let config = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']}
    serviceContext = new ServiceContext();
    serviceContext.init(null, config);
    serviceContext.stateDb['abcdef'] = {'code': 'access_code'};
    service.endpoint = 'https://example.com/authorize';
    let reqArgs = {'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'};
    let info = service.requestInfo(
    serviceContext, null, reqArgs, null, null, null, {state: 'state'});
    let msg = new
    AccessTokenRequest().fromUrlEncoded(service.getUrlInfo(info['body']))
    assert.isNotNull(msg.client_secret);
    assert.isUndefined(info.params.headers['Authorization']);

    /*
    let service;
    let serviceContext;
    service = new DummyService();
    serviceContext = new ServiceContext();
    serviceContext = serviceContext.init(null, null, null, null, null, null, {'clientId':
    'client_id', 'issuer' : 'https://www.example.org/as'});
    serviceContext.stateDb['state'] = {};
    var req_resp = new Response(200, new Token().toUrlEncoded({'foo':'bar'}));
    var resp = service.parseRequestResponse(req_resp, serviceContext,
                                               null, {'state':'state'});
    assert.deepEqual(Object.keys(resp), ['foo']);

    /*
    let service;
    let serviceContext;
    service = new DummyService();
    serviceContext = new ServiceContext();
    serviceContext = serviceContext.init(null, null, null, null, null, null, {'clientId':
    'client_id', 'issuer' : 'https://www.example.org/as'});
    serviceContext.stateDb['state'] = {};
    // TODO
    let reqArgs = {'foo': 'bar', 'req_str': 'some string'};
    service.endpoint = 'https://example.com/authorize';
    info = service.doRequestInit(serviceContext, null, null, null, reqArgs);
    assert.deepEqual(Object.keys(info), ['uri', 'request', 'httpArgs']);
    assert.deepEqual(info['request'], {'foo': 'bar', 'req_str': 'some string'});
    assert.deepEqual(info['httpArgs'], {});
    let msg = new
    DummyMessage().fromUrlEncoded(service.getUrlInfo(info['uri']));
    assert.deepEqual(msg, info['request']);




      /*

      let client = new Client();
      client.init(CLIENT_AUTHN_METHOD);
      let ci = new ServiceContext();
      client.serviceContext = ci.init(null, conf);
      client.serviceContext.stateDb['ABCDE'] = {'code': 'access_code'};
      return client;
    };

    var client = getClient();
    let resp = new AccessTokenResponse(
        {'refresh_token': 'refresh_with_me', 'access_token': 'access'});
    client.serviceContext.stateDb.addResponse(resp, 'ABCDE');

    let srv = new client.service['UserInfo']();
    srv.endpoint = 'https://example.com/userinfo';
    let info = srv.doRequestInit(
        client.serviceContext, null, null, null, null, null, {'state': 'ABCDE'});
    assert.isNotNull(info);
    assert.deepEqual(info['request'], {});
    assert.deepEqual(
        info['httpArgs'], {'headers': {'Authorization': 'Bearer access'}});
    /*
    let accessToken = new client.service['AccessToken']();
    accessToken.init();
    let request = accessToken.construct(client.serviceContext, {}, {'redirect_uri':
    'http://example.com', 'state': 'ABCDE'}); let csb = new ClientSecretBasic();
    let httpArgs = csb.construct(request, client.serviceContext);

    */

    /*

    var sdb = client.serviceContext.stateDb;
    sdb['FFFFF'] = {}
    var resp = new AuthorizationResponse(code="code", state="FFFFF")
    sdb.addResponse(resp)
    var atr = new AccessTokenResponse({'access_token':"2YotnFZFEjr1zCsicMWpAA",
                              'token_type':"example",
                              'refresh_token':"tGzv3JOkF0XG5Qx2TlKWIA",
                              'example_parameter':"example_value",
                              'scope':["inner", "outer"]});
    sdb.addResponse(atr, {'state':'FFFFF'});
    var request = new ResourceRequest();
    var list = new BearerBody().construct(
        request, client.serviceContext, {}, null, {'state' : "FFFFF"}, "inner")
    var httpArgs = list[0];
    var request = list[1];
    assert.deepEqual(request["access_token"], "2YotnFZFEjr1zCsicMWpAA");
    assert.deepEqual(httpArgs, null);

    var sdb = client.serviceContext.stateDb;
    sdb['EEEE'] = {};
    var resp = new AuthorizationResponse(code="auth_grant", state="EEEE");
    new client.service['Authorization']().parseResponse(resp, client.serviceContext,
    'urlencoded');

    var resp2 = new AccessTokenResponse({'access_token':"token1",
                              'token_type':"Bearer",
                              'expires_in': 0,
                              'state':'EEEE'});
    new client.service['AccessToken']().parseResponse(resp2, client.serviceContext,
    'urlencoded'); var request = new ResourceRequest(); var list = new
    BearerBody().construct( request, client.serviceContext, null, null,
    {'state':"EEEE"}); var httpArgs = list[0]; var request = list[1];
    assert.isTrue(Object.keys(request).indexOf('access_token') !== -1);
    assert.deepEqual(request["access_token"], "token1");
    /*
    var REQ_ARGS = {'redirect_uri': 'https://example.com/rp/cb',
    'response_type': "code"};

    var config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    };

    var REQ_ARGS = {'redirect_uri': 'https://example.com/rp/cb',
    'response_type': "code"}; var CLIENT_ID = "A";

    var CLIENT_CONF = {'issuer': 'https://example.com/as',
                   'redirect_uris': ['https://example.com/cli/authz_cb'],
                   'client_secret': 'boarding pass',
                   'client_id': CLIENT_ID};

    var stateDb = new State();
    stateDb.init('client_id', 'state');

    function client(){
        var redirect_uri = "http://example.com/redirect";
        var conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop'
        }
        var client = new Client();
        client.init(CLIENT_AUTHN_METHOD);
        var ci = new ServiceContext();
        client.serviceContext = ci.init(null, conf);
        client.serviceContext.stateDb['ABCDE'] =  {'code': 'access_code'};
        return client;
    }

    /*
    var link = new JRD({'subject':'acct:bob@example.com',
    'aliases':[
        "http://www.example.com/~bob/"
    ],
    'properties':{
        "http://example.com/ns/role/": "employee"
    },
    'links':[new LINK({'rel':"http://webfinger.net/rel/avatar",
    'type':"image/jpeg",
    'href':"http://www.example.com/~bob/bob.jpg"}), new
    LINK({'rel':'http://webfinger.net/rel/profile-page',
    'href':'http://www.example.com/~bob/'})]});
    assert.deepEqual(Object.keys(link), ['subject', 'aliases', 'properties',
    'links']);
    });

    var ex0 = {
        "subject": "acct:bob@example.com",
        "aliases": [
            "http://www.example.com/~bob/"
        ],
        "properties": {
            "http://example.com/ns/role/": "employee"
        },
        "links": [
            {
                "rel": "http://webfinger.net/rel/avatar",
                "type": "image/jpeg",
                "href": "http://www.example.com/~bob/bob.jpg"
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "href": "http://www.example.com/~bob/"
            },
            {
                "rel": "blog",
                "type": "text/html",
                "href": "http://blogs.example.com/bob/",
                "titles": {
                    "en-us": "The Magical World of Bob",
                    "fr": "Le monde magique de Bob"
                }
            },
            {
                "rel": "vcard",
                "href": "https://www.example.com/~bob/bob.vcf"
            }
        ]
    }
    var jrd = new JRD();
    var jrd0 = jrd.fromJSON(JSON.stringify(ex0));
    for (var i = 0; i < jrd0['links'].length; i++){
        var link = jrd0['links'][i];
        if (link['rel'] == 'blog'){
            assert.deepEqual(link['href'], "http://blogs.example.com/bob/");
            break;
        }
    }

    /*
    var client = client();
    var OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer";

    var link = new LINK({'rel':'http://webfinger.net/rel/avatar',
    'type':'image/jpeg',
    'href':'http://www.example.com/~bob/bob.jpg'});
    assert.deepEqual(link['rel'], 'http://webfinger.net/rel/avatar');
    assert.deepEqual(link['type'], 'image/jpeg');
    assert.deepEqual(link['href'], 'http://www.example.com/~bob/bob.jpg');

    /*

    var EXAMPLE = {
        "example.com": "https://example.com",
        "example.com:8080": "https://example.com:8080",
        "example.com/path": "https://example.com/path",
        "example.com?query": "https://example.com?query",
        "example.com#fragment": "https://example.com",
        "example.com:8080/path?query#fragment":
            "https://example.com:8080/path?query",
        "http://example.com": "http://example.com",
        "http://example.com:8080": "http://example.com:8080",
        "http://example.com/path": "http://example.com/path",
        "http://example.com?query": "http://example.com?query",
        "http://example.com#fragment": "http://example.com",
        "http://example.com:8080/path?query#fragment":
            "http://example.com:8080/path?query",
        "nov@example.com": "acct:nov@example.com",
        "nov@example.com:8080": "https://nov@example.com:8080",
        "nov@example.com/path": "https://nov@example.com/path",
        "nov@example.com?query": "https://nov@example.com?query",
        "nov@example.com#fragment": "acct:nov@example.com",
        "nov@example.com:8080/path?query#fragment":
            "https://nov@example.com:8080/path?query",
        "acct:nov@matake.jp": "acct:nov@matake.jp",
        "acct:nov@example.com:8080": "acct:nov@example.com:8080",
        "acct:nov@example.com/path": "acct:nov@example.com/path",
        "acct:nov@example.com?query": "acct:nov@example.com?query",
        "acct:nov@example.com#fragment": "acct:nov@example.com",
        "acct:nov@example.com:8080/path?query#fragment":
            "acct:nov@example.com:8080/path?query",
        "mailto:nov@matake.jp": "mailto:nov@matake.jp",
        "mailto:nov@example.com:8080": "mailto:nov@example.com:8080",
        "mailto:nov@example.com/path": "mailto:nov@example.com/path",
        "mailto:nov@example.com?query": "mailto:nov@example.com?query",
        "mailto:nov@example.com#fragment": "mailto:nov@example.com",
        "mailto:nov@example.com:8080/path?query#fragment":
            "mailto:nov@example.com:8080/path?query",
        "localhost": "https://localhost",
        "localhost:8080": "https://localhost:8080",
        "localhost/path": "https://localhost/path",
        "localhost?query": "https://localhost?query",
        "localhost#fragment": "https://localhost",
        "localhost/path?query#fragment": "https://localhost/path?query",
        "nov@localhost": "acct:nov@localhost",
        "nov@localhost:8080": "https://nov@localhost:8080",
        "nov@localhost/path": "https://nov@localhost/path",
        "nov@localhost?query": "https://nov@localhost?query",
        "nov@localhost#fragment": "acct:nov@localhost",
        "nov@localhost/path?query#fragment": "https://nov@localhost/path?query",
        "tel:+810312345678": "tel:+810312345678",
        "device:192.168.2.1": "device:192.168.2.1",
        "device:192.168.2.1:8080": "device:192.168.2.1:8080",
        "device:192.168.2.1/path": "device:192.168.2.1/path",
        "device:192.168.2.1?query": "device:192.168.2.1?query",
        "device:192.168.2.1#fragment": "device:192.168.2.1",
        "device:192.168.2.1/path?query#fragment":
    "device:192.168.2.1/path?query",
    };

    for (var i = 0; i < Object.keys(EXAMPLE).length; i++){
        var key = Object.keys(EXAMPLE)[i];
        var val = EXAMPLE[key];
        var uriNormalizer = new URINormalizer();
        var res = uriNormalizer.normalize(key);
        assert.deepEqual(res, val);
    }
    var wf = new WebFinger();
    wf.init(OIC_ISSUER);
    var query = wf.query("acct:carol@example.com");
    assert.deepEqual(query,
    'https://example.com/.well-known/webfinger?resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer');

    /*
    var requestArgs = {'state': 'ABCDE',
    'redirect_uri': 'https://example.com/auth_cb',
    'response_type': ['code']};

    var msg =
    client.service['authorization'].prototype.construct(client.serviceContext,
    requestArgs); assert.deepEqual(msg['client_id'], 'client_1');
    assert.deepEqual(msg['redirect_uri'], 'https://example.com/auth_cb');*/


    /*
    var accessToken = new client.service['accessToken']();
    accessToken.init();
    var request = accessToken.construct(client.serviceContext, {}, {'redirect_uri':
    'http://example.com', 'state': 'ABCDE'}); var csb = new ClientSecretBasic();
    var httpArgs = csb.construct(request, client.serviceContext); var credentialsDict =
    {}; credentialsDict['A'] = 'boarding pass'; var authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    var headersDict = {};
    headersDict['headers'] = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);

    /*
    var requestArgs = {'state': 'ABCDE',
    'redirect_uri': 'https://example.com/auth_cb',
    'response_type': ['code']};
    var msg =
    client.service['authorization'].prototype.construct(client.serviceContext,
    requestArgs); assert.deepEqual(msg['client_id'], 'client_1');
    assert.deepEqual(msg['redirect_uri'], 'https://example.com/auth_cb');

    /*var client = client();

    var reqArgs = {};
    var msg =
    client.service['accessToken'].prototype.construct(client.serviceContext,
    reqArgs, {'state':'ABCDE'});
    /*

    var resp = new AccessTokenResponse({'refresh_token':"refresh_with_me",
    'access_token':"access"});
    client.serviceContext.stateDb.addResponse(resp, "ABCDE")

    var srv = client.service['UserInfo'];
    srv.prototype.endpoint = 'https://example.com/userinfo';
    var info = srv.prototype.doRequestInit(client.serviceContext, null, null, null,
    null, null, {'state' : 'ABCDE'}); assert.isNotNull(info);
    assert.deepEqual(info['request'], {});
    assert.deepEqual(info['httpArgs'], {'headers': {'Authorization': 'Bearer
    access'}});
    //var msg =
    client.service['authorization'].prototype.construct(client.serviceContext,
    requestArgs);

    /*
    var client = client();
    var requestArgs = {'state': 'ABCDE',
    'redirect_uri': 'https://example.com/auth_cb',
    'response_type': ['code']};

    var msg =
    client.service['authorization'].prototype.construct(client.serviceContext,
    requestArgs); assert.deepEqual(msg['client_id'], 'client_1');
    assert.deepEqual(msg['redirect_uri'], 'https://example.com/auth_cb');

    /*
    client.serviceContext.stateDb['ABCDE'] = {'code': 'access_code'};
    var resp = new
    AccessTokenResponse({'refresh_token':'refresh_with_me','access_token':'access'})
    client.serviceContext.stateDb.addResponse(resp, 'ABCDE');

    var reqArgs = {};
    var msg =
    client.service['refresh_token'].prototype.construct(client.serviceContext,
    reqArgs, {'state':'ABCDE'}); assert.deepEqual(msg['refresh_token'],
    'refresh_with_me'); assert.deepEqual(msg['grant_type'], 'refresh_token');
    assert.deepEqual(msg['client_secret'], 'abcdefghijklmnop');
    assert.deepEqual(msg['client_id'], 'client_1');
    */
    /*
    var accessToken = new client.service['accessToken']();
    accessToken.init();
    var request = accessToken.construct(client.serviceContext, {}, {'redirect_uri':
    'http://example.com', 'state': 'ABCDE'}); var csb = new ClientSecretBasic();
    var httpArgs = csb.construct(request, client.serviceContext);

    var reqArgs = {};
    client.serviceContext.stateDb['ABCDE'] = {'code' : 'access_code'};
    var msg =
    client.service['accessToken'].prototype.construct(client.serviceContext,
    reqArgs, {'state':'ABCDE'}); assert.deepEqual(msg['code'], 'access_code');
    assert.deepEqual(msg['grant_type'], 'authorization_code');
    assert.deepEqual(msg['client_secret'], 'abcdefghijklmnop');
    assert.deepEqual(msg['client_id'], 'client_1');
    */

    /*
    var _now = 123456;

    assert.isTrue(validServiceContext({}, _now));
    assert.isTrue(validServiceContext({'client_id': 'test', 'client_secret':
    'secret'}, _now));
    assert.isTrue(validServiceContext({'client_secret_expires_at': 0}, _now));
    assert.isTrue(validServiceContext({'client_secret_expires_at': 123460}, _now));
    assert.isTrue(validServiceContext({'client_id': 'test',
    'client_secret_expires_at': 123460}, _now));
    assert.isFalse(validServiceContext({'client_secret_expires_at': 1}, _now));
    assert.isFalse(validServiceContext({'client_id': 'test',
    'client_secret_expires_at': 123455}, _now));
    /*
    var request = client.service['accessToken'].prototype.parseResponse(resp2,
    client.serviceContext, 'urlencoded'); var request =
    client.service['accesstoken'].construct( cli_info=client.client_info,
    redirect_uri="http://example.com", state='ABCDE');

    new BearerBody().construct(request, client.serviceContext, "http://example.com",
    null, "EEEE")


    var request =
    client.service['accessToken'].prototype.construct(client.serviceContext, null,
    {'redirect_uri' : "http://example.com", 'state':'ABCDE'}); var csp = new
    ClientSecretPost(); var list = csp.construct(request, client.serviceContext);
    var httpArgs = list[0]; request = list[1];

    assert.deepEqual(request['client_id'], 'A');
    assert.deepEqual(request['client_secret'], 'boarding pass');
    assert.deepEqual(httpArgs, undefined);

    var request2 = new AccessTokenRequest({'code':'foo', 'redirect_uri':
    'http://example.com'}); var list2 = csp.construct(request2,
    client.serviceContext, null, {'client_secret':'another'}); var httpArgs2 =
    list2[0]; request2 = list2[1]; assert.deepEqual(request2['client_id'], 'A');
    assert.deepEqual(request2['client_secret'], 'another');
    assert.deepEqual(httpArgs2, {});

    /*
    var sdb = client.serviceContext.stateDb;
    sdb['EEEE'] = {}
    var resp = new AuthorizationResponse(code="auth_grant", state="EEEE")
    client.service['authorization'].prototype.parseResponse(resp,
    client.serviceContext, 'urlencoded');

    var resp2 = new AccessTokenResponse({'access_token':"token1",
                              'token_type':"Bearer",
                              'expires_in': 0,
                              'state':'EEEE'});
    client.service['accessToken'].prototype.parseResponse(resp2,
    client.serviceContext, 'urlencoded'); var request = new ResourceRequest(); var list
    = new BearerBody().construct( request, client.serviceContext, null, null, "EEEE");
    var httpArgs = list[0]; var request = list[1];
    assert.isTrue(Object.keys(request).indexOf('access_token') !== -1);
    assert.deepEqual(request["access_token"], "token1");

    var requestArgs = {"access_token": "Sesame"}
    var request = new ResourceRequest()
    var list = new BearerBody().construct(request, client.serviceContext, requestArgs);
    var httpArgs = list[0];
    request = list[1];

    assert.deepEqual(request["access_token"], "Sesame");
    assert.deepEqual(httpArgs, undefined);

    var sdb = client.serviceContext.stateDb;
    sdb['FFFFF'] = {}
    var resp = new AuthorizationResponse(code="code", state="FFFFF")
    sdb.addResponse(resp)
    var atr = new AccessTokenResponse({'access_token':"2YotnFZFEjr1zCsicMWpAA",
                              'token_type':"example",
                              'refresh_token':"tGzv3JOkF0XG5Qx2TlKWIA",
                              'example_parameter':"example_value",
                              'scope':["inner", "outer"]});
    sdb.addResponse(atr, state='FFFFF');

    var request = new ResourceRequest();
    var list = new BearerBody().construct(
        request, client.serviceContext, {}, null, "FFFFF", "inner")
    var httpArgs = list[0];
    var request = list[1];
    assert.deepEqual(request["access_token"], "2YotnFZFEjr1zCsicMWpAA");
    assert.deepEqual(httpArgs, null);

    /*
    client.serviceContext.stateDb['AAAA'] = {}
    var resp1 = new AuthorizationResponse("auth_grant", "AAAA");
    client.service['authorization'].prototype.parseResponse(resp1,
    client.serviceContext, "urlencoded")

    // based on state find the code and then get an access token
    var resp2 = new AccessTokenResponse({'access_token':"token1",
                                'token_type':"Bearer", 'expires_in':0,
                                'state':"AAAA"});
    client.service['accessToken'].prototype.parseResponse(resp2,
    client.serviceContext, "urlencoded")

    var httpArgs = new BearerHeader().construct(
        new ResourceRequest(), client.serviceContext, null, null, {'state':"AAAA"});
    assert.deepEqual(httpArgs, {"headers": {"Authorization": "Bearer token1"}});

    /*
    var requestArgs = {"access_token": "Sesame"};
    var bh = new BearerHeader();
    var httpArgs = bh.construct(requestArgs);
    var testDict = {"headers": {"Authorization": "Bearer Sesame"}};
    assert.deepEqual(testDict, httpArgs);
    */
    /*
    var requestArgs = {"access_token": "Sesame"}
    var bh = new BearerHeader()
    var httpArgs = bh.construct(null, null, requestArgs,{"headers": {"x-foo":
    "bar"}});

    assert.deepEqual(Object.keys(httpArgs), ["headers"]);
    //assert http_args["headers"] == {"Authorization": "Bearer Sesame"}
    assert.deepEqual(Object.keys(httpArgs['headers']), ["x-foo",
    "Authorization"]); assert.deepEqual(httpArgs["headers"]["Authorization"],
    "Bearer Sesame");


    var bh = new BearerHeader();
    var request = new ResourceRequest({'access_token':"Sesame"});
    var client = client();

    var list = bh.construct(request, client.serviceContext)
    var httpArgs = list[0];
    request = list[1];
    assert.deepEqual(Object.keys(request).indexOf('access_token'), -1);
    assert.deepEqual(httpArgs, {"headers": {"Authorization": "Bearer Sesame"}});

    /*
    var request = new AccessTokenRequest({'code':"foo",
    'redirect_uri':"http://example.com"}) var csb = new ClientSecretBasic(); var
    httpArgs = csb.construct(request, client.client_info, null, null, {'user':"ab",
    'password':"c"});
    //assert.isTrue(http_args["headers"]["Authorization"].endsWith("=="));
    var credentialsDict = {};
    credentialsDict['ab'] = 'c';
    var authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    var headersDict = {};
    headersDict['headers'] = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);*/

    /*
    var request = new CCAccessTokenRequest({'grant_type':"client_credentials"})

    var csb = new ClientSecretBasic();
    var httpArgs = csb.construct(request, client.client_info, null, null,
                                      {'user':"service1", 'password':"secret"})
    //assert http_args["headers"]["Authorization"].startswith('Basic ')
    var credentialsDict = {};
    credentialsDict['service1'] = 'secret';
    var authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    var headersDict = {};
    headersDict['headers'] = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);

    /*
    function client(){
        var client = new Client();
        client.init(CLIENT_AUTHN_METHOD, CLIENT_CONF);
        var sdb = client.serviceContext.stateDb;
        sdb.dict = {};
        sdb.dict['ABCDE'] = {'code' : 'accessCode'};
        client.serviceContext.clientSecret = 'boardingPass';
        return client;
    }

    /*
    var client = client();
    var accessToken = new client.service['accessToken']();
    accessToken.init();
    var request = accessToken.construct(client.serviceContext, {}, {'redirect_uri':
    'http://example.com', 'state': 'ABCDE'}); var csb = new ClientSecretBasic();
    var httpArgs = csb.construct(request, client.serviceContext);

    var credentialsDict = {};
    credentialsDict['A'] = 'boarding pass';
    var authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    var headersDict = {};
    headersDict['headers'] = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);
    */
