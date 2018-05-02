const AccessTokenRequest =
require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const AccessTokenResponse =
require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
const assert = require('chai').assert;
const AuthorizationRequest =
require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse =
require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const BearerBody = require('../src/clientAuth/bearerBody').BearerBody;
const BearerHeader = require('../src/clientAuth/bearerHeader').BearerHeader;
const CCAccessTokenRequest =
require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').CCAccessTokenRequest;
const Client = require('../src/oic/init').Client;
const CLIENT_AUTHN_METHOD =
require('../src/clientAuth/privateKeyJWT').CLIENT_AUTHN_METHOD;
const serviceContext = require('../src/serviceContext');
const ClientSecretBasic =
require('../src/clientAuth/clientSecretBasic').ClientSecretBasic;
const ClientSecretPost =
require('../src/clientAuth/clientSecretPost').ClientSecretPost;
const ResourceRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').ResourceRequest;
const Service = require('../src/service').Service;
const validserviceContext = require('../src/clientAuth/clientAuth').validserviceContext;
var ServiceContext = require('../src/ServiceContext.js').ServiceContext;
const factory = require('../src/oic/service/service').OicFactory;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const OpenIDSchema = require('../nodeOIDCMsg/src/oicMsg/oic/init').OpenIDSchema;
var State = require('../src/state.js').State;
var addJwksUriOrJwks = require('../src/service.js').addJwksUriOrJwks;

const RP_BASEURL = "https://example.com/rp";
const buildServices = require('../src/service').buildServices;
const DEFAULT_SERVICES = require('../src/oic/init').DEFAULT_SERVICES;
const OP_BASEURL = "https://example.org/op";
const parseQs = require('../src/util').parseQs;
var urlParse = require('url-parse');


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

describe('Test Conversation', function() {
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
    let serviceContext = new ServiceContext(null, clientConfig);
    let serviceSpec = DEFAULT_SERVICES;
    serviceSpec['WebFinger'] = {};
    let service = buildServices(serviceSpec, factory, serviceContext, new DB(), CLIENT_AUTHN_METHOD);
    serviceContext.service = service

    it('test build services', function() {
        //TEST BUILD SERVICES
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
    });
});