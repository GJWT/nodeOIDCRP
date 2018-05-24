
const assert = require('chai').assert;
const RP = require('../oic/init').RP;
const State = require('../nodeOIDCService/src/OIDCClient/src/state').State;
const AuthorizationRequest = require('../nodeOIDCService/src/OIDCClient/nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse = require('../nodeOIDCService/src/OIDCClient/nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const AccessTokenResponse = require('../nodeOIDCService/src/OIDCClient/nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
const RPHandler = require('../init').RPHandler;
const urlParse = require('url-parse');
const Message = require('../nodeOIDCService/src/OIDCClient/nodeOIDCMsg/src/oicMsg/message');
const parseQs = require('../nodeOIDCService/src/OIDCClient/src/util').parseQs;
const request = require('supertest');
const express = require('express');

// content of index.js
const http = require('http')

const BASEURL = 'https://example.com/rp';

const CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic"
}

const CLIENT_CONFIG = {
    "": {
        "client_prefs": CLIENT_PREFS,
        "redirect_uris": null,
        "services": {
            'WebFinger': {},
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    },
    "linkedin": {
        "issuer": "https://www.linkedin.com/oauth/v2/",
        "client_id": "xxxxxxx",
        "client_secret": "yyyyyyy",
        "redirect_uris": [BASEURL + "/authz_cb/linkedin"],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["r_basicprofile", "r_emailaddress"],
            "token_endpoint_auth_method": 'client_secret_post'
        },
        "provider_info": {
            "authorization_endpoint":
                "https://www.linkedin.com/oauth/v2/authorization",
            "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_endpoint":
                "https://api.linkedin.com/v1/people/~?format=json"
        },
        "userinfo_request_method": "GET",
        'services': {
            'Authorization': {},
            'linkedin.AccessToken': {},
            'linkedin.UserInfo': {}
        }
    },
    "facebook": {
        "issuer": "https://www.facebook.com/v2.11/dialog/oauth",
        "client_id": "ccccccccc",
        "client_secret": "dddddddd",
        "behaviour": {
            "response_types": ["code"],
            "scope": ["email", "public_profile"],
            "token_endpoint_auth_method": ''
        },
        "redirect_uris": [BASEURL + "/authz_cb/facebook"],
        "provider_info": {
            "authorization_endpoint":
                "https://www.facebook.com/v2.11/dialog/oauth",
            "token_endpoint":
                "https://graph.facebook.com/v2.11/oauth/access_token",
            "userinfo_endpoint":
                "https://graph.facebook.com/me"
        },
        'services': {
            'Authorization': {},
            'AccessToken': {'default_authn_method': ''},
            'UserInfo': {'default_authn_method': ''}
        }
    },
    'github': {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": [BASEURL + "/authz_cb/github"],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ''
        },
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },
        'services': {
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {'default_authn_method': ''}
        }
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

describe('RPHandler', function() {
    let rph = null;
    beforeEach(function() {
       rph = new RPHandler({baseUrl: BASEURL, clientConfigs: CLIENT_CONFIG});
    });
    it('Test webfinger support', function() {      
        assert.isTrue(rph.supportsWebfinger());
    });
    it('Test pick facebook config', function() {      
        let cnf = rph.pickConfig('facebook');
        assert.deepEqual(cnf['issuer'], "https://www.facebook.com/v2.11/dialog/oauth");
    });
    it('Test pick linkedin config', function() {      
        let cnf = rph.pickConfig('linkedin');
        assert.deepEqual(cnf['issuer'], "https://www.linkedin.com/oauth/v2/");
    });
    it('Test pick github config', function() {      
        let cnf = rph.pickConfig('github');
        assert.deepEqual(cnf['issuer'], "https://github.com/login/oauth/authorize");
    });
    it('Test pick no config', function() {      
        let cnf = rph.pickConfig('');
        assert.deepEqual(Object.keys(cnf).indexOf('issuer'), -1);
    });
    it('Test init client', function() {      
        let client = rph.initClient('github');
        assert.deepEqual(Object.keys(client.service), ['authorization', 'accessToken', 'refresh_token',  'userinfo',]);
    
        let context = client.serviceContext;

        assert.deepEqual(context.client_id, 'eeeeeeeee');
        assert.deepEqual(context.client_secret, 'aaaaaaaaaaaaa');
        assert.deepEqual(context.issuer, "https://github.com/login/oauth/authorize");

        assert.isTrue(Object.keys(context).indexOf('provider_info') !== -1);

        assert.deepEqual(Object.keys(context.provider_info), ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'])
    
        assert.deepEqual(context.behavior, {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ''
        });

        /* TODO
        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.
        */
        assert.deepEqual(context.keyjar.owners(), ['']);
        
        let keyBundle = context.keyjar.issuerKeys[''];
        let keys = keyBundle.keys;
        
        assert.deepEqual(keys.length, 2);
        
        for (var i =0; i <keys.length; i++){
            let key = keys[i]
            assert.deepEqual(key.kty, 'oct');
            assert.deepEqual(key.k, 'aaaaaaaaaaaaa');
        }

        assert.deepEqual(context.baseUrl, BASEURL);
    });

    it('Test doProviderInfo', function() {      
        let client = rph.initClient('github');
        let issuer = rph.doProviderInfo(client);
        assert.deepEqual(issuer, "https://github.com/login/oauth/authorize");
        
        let srvTypes = ['authorization', 'accessToken', 'userinfo'];
        for (var i = 0; i < srvTypes.length; i++){
            let srvType = srvTypes[i];
            let srv = client.service[srvType];
            let endpoint = client.serviceContext.provider_info[srv.endpointName];
            console.log(srv.endpointName);
            console.log(client.serviceContext.provider_info[srv.endpointName]);
            console.log("**************************");
            assert.deepEqual(endpoint, srv.endpoint);
        }
    });

    it('Test do client registration', function() {      
        let client = rph.initClient('github');
        let issuer = rph.doProviderInfo(client);

        rph.registerClient(client);
        
        assert.deepEqual(rph.hash2issuer[context.issuer], context.issuer);
        assert.deepEqual(client.serviceContext.postLogoutRedirectUris, [BASEURL]);
    });

    it('Test client setup', function() {      
        let client = rph.clientSetUp('github');
    
        let context = client.serviceContext;

        assert.deepEqual(context.client_id, 'eeeeeeeee');
        assert.deepEqual(context.client_secret, 'aaaaaaaaaaaaa');
        assert.deepEqual(context.issuer, "https://github.com/login/oauth/authorize");

        /* TODO
        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.*/

        assert.deepEqual(context.keyjar.owners(), ['']);
        
        let keyBundle = context.keyjar.issuerKeys[''];
        let keys = keyBundle.keys;
        
        assert.deepEqual(keys.length, 2);
        
        for (var i =0; i <keys.length; i++){
            let key = keys[i]
            assert.deepEqual(key.kty, 'oct');
            assert.deepEqual(key.k, 'aaaaaaaaaaaaa');
        }

        let srvTypes = ['authorization', 'userinfo', 'accessToken'];
        for (var i = 0; i < srvTypes.length; i++){
            let srvType = srvTypes[i];
            let srv = client.service[srvType];
            let endpoint = client.serviceContext.provider_info[srv.endpointName];
            assert.deepEqual(endpoint, srv.endpoint);
        }

        assert.deepEqual(rph.hash2issuer[context.issuer], context.issuer);
        
    });

    it('Test client setup', function() {      
        let client = rph.clientSetUp('github');
    
        let context = client.serviceContext;

        assert.deepEqual(context.client_id, 'eeeeeeeee');
        assert.deepEqual(context.client_secret, 'aaaaaaaaaaaaa');
        assert.deepEqual(context.issuer, "https://github.com/login/oauth/authorize");


        /* TODO
        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.*/

        assert.deepEqual(context.keyjar.owners(), ['']);
        
        let keyBundle = context.keyjar.issuerKeys[''];
        let keys = keyBundle.keys;
        
        assert.deepEqual(keys.length, 2);
        
        for (var i =0; i <keys.length; i++){
            let key = keys[i]
            assert.deepEqual(key.kty, 'oct');
            assert.deepEqual(key.k, 'aaaaaaaaaaaaa');
        }

        
        let srvTypes = ['authorization', 'userinfo', 'accessToken'];
        for (var i = 0; i < srvTypes.length; i++){
            let srvType = srvTypes[i];
            let srv = client.service[srvType];
            let endpoint = client.serviceContext.provider_info[srv.endpointName];
            assert.deepEqual(endpoint, srv.endpoint);
        }

        assert.deepEqual(rph.hash2issuer[context.issuer], context.issuer);
    });

    it('Test create callbacks', function() {      
        let cb = rph.createCallbacks('https://op.example.com/');
        assert.deepEqual(Object.keys(cb), ['code', 'implicit', 'form_post']);
        assert.deepEqual(cb, {
            'code': 'https://example.com/rp/authz_cb/46e8c08e3a6c3ab199fcb0b58a36cdf079a301004987f246c5c72c67a4501dc1',
            'implicit':
                'https://example.com/rp/authz_im_cb/46e8c08e3a6c3ab199fcb0b58a36cdf079a301004987f246c5c72c67a4501dc1',
            'form_post':
                'https://example.com/rp/authz_fp_cb/46e8c08e3a6c3ab199fcb0b58a36cdf079a301004987f246c5c72c67a4501dc1'});
        assert.deepEqual(Object.keys(rph.hash2issuer), [
            "46e8c08e3a6c3ab199fcb0b58a36cdf079a301004987f246c5c72c67a4501dc1"]);
        assert.deepEqual(rph.hash2issuer[
            "46e8c08e3a6c3ab199fcb0b58a36cdf079a301004987f246c5c72c67a4501dc1"
        ], 'https://op.example.com/');
    });

    it('Test begin', function() {      
        let res = rph.begin('github');
        assert.deepEqual(Object.keys(res), ['url', 'state_key']);
        
        let session = rph.sessionInterface.getState(res['state_key']);
        client = rph.issuer2rp[session['iss']];
        
        assert.deepEqual(client.serviceContext.issuer, "https://github.com/login/oauth/authorize");
        
        let parts = urlParse(res['url']);
        
        let scheme = parts.protocol;
        let netloc = parts.hostname;
        let path = parts.path;
        let query = parts.query;
        let msg = Message.fromUrlEncoded(query.substring(1, query.length));
        let parsedQ = parseQs(msg);
        
        assert.deepEqual(Object.keys(parsedQ).length, 6);
        
        assert.deepEqual(parsedQ.client_id, ['eeeeeeeee']);
        assert.deepEqual(parsedQ.redirect_uri, [
            'https://example.com/rp/authz_cb/github']);
        assert.deepEqual(parsedQ.response_type, ['code']);
        assert.deepEqual(parsedQ.scope, ['user,public_repo,openid']);
    });

    it('Test get session information', function() {
        let res = rph.begin('github');
        let session = rph.getSessionInformation(res['state_key']);
        assert.deepEqual(rph.clientConfigs['github']['issuer'], session['iss']);
    });

    it('Test get client authn method', function() {
        let res = rph.begin('github');
        let session = rph.getSessionInformation(res['state_key']);
        client = rph.issuer2rp[session['iss']];
        let authnMethod = rph.getClientAuthnMethod(client, 'token_endpoint');
        assert.deepEqual(authnMethod, '');
        
        res = rph.begin('linkedin');
        session = rph.getSessionInformation(res['state_key']);
        client = rph.issuer2rp[session['iss']];
        authnMethod = rph.getClientAuthnMethod(client, 'token_endpoint');
        assert.deepEqual(authnMethod, 'client_secret_post')
    });

    it('Test finalize auth', function() {
        let res = rph.begin('linkedin');
        let session = rph.getSessionInformation(res['state_key']);
        client = rph.issuer2rp[session['iss']];
        let authnMethod = rph.getClientAuthnMethod(client, 'token_endpoint');
        
        let authResponse = new AuthorizationResponse({code:'access_code', state: res['state_key']});
        let resp = rph.finalizeAuth(client, session['iss'], authResponse.claims);
        
        assert.deepEqual(Object.keys(resp.claims), ['code', 'state']);
        
        let aresp = client.service['authorization'].getItem(AuthorizationResponse, 'auth_response', res['state_key']);
        
        assert.deepEqual(Object.keys(aresp), ['code', 'state']);
    });
});

function makeServer(content) {
    var express = require('express');
    var app = express();
    app.get('/', function (req, res) {
      res.send(content);
    });
    var server = app.listen(3000, function () {
      var port = server.address().port;
      console.log('Example app listening at port %s', port);
    });
    return server;
  }

describe('Test get access token', function () {
  var server;
  let rph = null;
  beforeEach(function() {
    rph = new RPHandler({baseUrl: BASEURL, clientConfigs: CLIENT_CONFIG});
  });
  afterEach(function () {
    //server.close();
  });
  it('responds to /', function testSlash(done) {
    let res = rph.begin('github');
    let session = rph.getSessionInformation(res['state_key']);
    client = rph.issuer2rp[session['iss']];
    
    let nonce = session['auth_request']['nonce'];
    let iss = session['iss'];
    let aud = client.serviceContext.client_id;
    let payload = {'nonce': nonce, 'sub': 'EndUserSubject', 'iss': iss,
    'aud': aud};
    let token = new Message();
    token.addOptionalClaims(payload);
    token.toJWT('shhh', {algorithm: 'HS256'}).then(function(jws) {
        let info = {"access_token": "accessTok", "id_token": jws,
        "token_type": "Bearer", "expires_in": 3600}
        let at = new AccessTokenResponse(info);
        server = makeServer(at.toJSON());
        port = server.address().port;
        client.service['accessToken'].endpoint = 'http://localhost:'+ port;
        
        let authResponse = new AuthorizationResponse({code: 'access_code', state: res['state_key']});
        let resp = rph.finalizeAuth(client, session.claims['iss'], authResponse.claims);
        
        request(server)
        .get('/')
        .expect(200, function(err, response){
            
            resp = rph.getAccessToken(res['state_key'], client, response);        
        
            assert.deepEqual(Object.keys(resp.claims).length, 5);
        
        
            let atResp = client.service['accessToken'].getItem(AccessTokenResponse, 'token_response', res['state_key']);
            
            assert.deepEqual(Object.keys(atResp.claims).length, 5);

            done();
            
        });
    
    }).catch(function(err) {
        assert.isNull(err);
        done();
    });
    done();
  });
  it('Test access and id token', function testSlash(done) {

    let res = rph.begin('github');
    let session = rph.getSessionInformation(res['state_key']);
    client = rph.issuer2rp[session['iss']];
    
    let nonce = session['auth_request']['nonce'];
    let iss = session['iss'];
    let aud = client.serviceContext.client_id;
    let payload = {'nonce': nonce, 'sub': 'EndUserSubject', 'iss': iss,
    'aud': aud};
    
    let token = new Message();
    token.addOptionalClaims(payload);
   token.toJWT('shhh', {algorithm: 'HS256'}).then(function(jws) {
        
        let info = {"access_token": "accessTok", "id_token": jws,
        "token_type": "Bearer", "expires_in": 3600};
        
        let at = new AccessTokenResponse(info);
    
    
        server = makeServer(at.toJSON());
        
                
        client.service['accessToken'].endpoint = 'http://localhost:3000/';
        
        let response = new AuthorizationResponse({code:'access_code',
        state:res['state_key']});
        
        let authResponse = rph.finalizeAuth(client, session.claims['iss'], response.claims);
        
        request(server)
        .get('/')
        .expect(200, function(err, response){
            
            let resp = rph.getAccessAndIdToken(authResponse, null, client, response);
            
            assert.deepEqual(resp['access_token'], 'accessTok');
            assert.isNotNull(resp['id_token']);
            done();
        });
    }).catch(function(err) {
        assert.isNull(err);
        done();
    });
    done();
  });

  it('Test getUserInfo', function testSlash(done) {
    let res = rph.begin('github');
    let session = rph.getSessionInformation(res['state_key']);
    client = rph.issuer2rp[session['iss']];
    
    let nonce = session['auth_request']['nonce'];
    let iss = session['iss'];
    let aud = client.serviceContext.client_id;
    let payload = {'nonce': nonce, 'sub': 'EndUserSubject', 'iss': iss,
    'aud': aud};
    
    let token = new Message();
    token.addOptionalClaims(payload);
    token.toJWT('shhh', {algorithm: 'HS256'}).then(function(jws) {
    
        let info = {"access_token": "accessTok", "id_token": jws,
        "token_type": "Bearer", "expires_in": 3600};
        
        let at = new AccessTokenResponse(info);
        
        
        server = makeServer(at.toJSON());
        
        client.service['accessToken'].endpoint = 'http://localhost:3000/';
        
        let response = new AuthorizationResponse({code:'access_code',
        state:res['state_key']});
        
        let authResponse = rph.finalizeAuth(client, session.claims['iss'], response.claims);
        
        let tokenResponse = null;
        
        request(server)
        .get('/')
        .expect(200, function(err, response){
            
        tokenResponse = rph.getAccessAndIdToken(authResponse, null, client, response);
        
        server.close();
        
        let server2 = makeServer({"sub":"EndUserSubject"});
        
        client.service['userinfo'].endpoint = 'http://localhost:3000/';
        
        request(server2)
        .get('/')
        .expect(200, function(err, response){
            
            let userInfoResp = rph.getUserInfo(res['state_key'], client, tokenResponse['access_token'], {response: response});
            
            assert.isNotNull(userInfoResp);

            done();
        });
        });
    }).catch(function(err) {
        assert.isNull(err);
        done();
    });
    done();
  });
  
  it('Test user info in id token', function() {
    let res = rph.begin('github');
    let session = rph.getSessionInformation(res['state_key']);
    client = rph.issuer2rp[session['iss']];
    
    let nonce = session['auth_request']['nonce'];
    let iss = session['iss'];
    let aud = client.serviceContext.client_id;
    let payload = {'nonce': nonce, 'sub': 'EndUserSubject', 'iss': iss,
    'aud': aud, 'given_name': 'Diana', 'family_name': 'Krall',
    'occupation': 'Jazz pianist'}
    
    let token = new Message(payload);
    token.addOptionalClaims({'occupation': 'Jazz pianist'});
    
    let userInfo = rph.userInfoInIdToken(token);
    assert.deepEqual(Object.keys(userInfo), ['sub', 'occupation', 'given_name', 'family_name']);
   });
});