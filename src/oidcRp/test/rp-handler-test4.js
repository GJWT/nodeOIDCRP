
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
let port = 0;

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

function makeServer(content) {
    var express = require('express');
    var app = express();
    app.get('/', function (req, res) {
      res.send(content);
      //res.status(200).send('ok');
    });
    var server = app.listen(1080, function () {
      var port = server.address().port;
      console.log('Example app listening at port %s', port);
    });
    return server;
  }

describe('RPHandlerTier2', function () {
    let rph = null;
    let res = null;
    let session = null;
    let client = null;
    let server = null;
    beforeEach(function (){
       rph = new RPHandler({baseUrl: BASEURL, clientConfigs: CLIENT_CONFIG});
    });
    it('Test getUserInfo 3', function testSlash(done) {
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
        
        client.service['accessToken'].endpoint = 'http://localhost:1080/';
        
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
          
          client.service['userinfo'].endpoint = 'http://localhost:1080/';
          
          request(server2)
          .get('/')
          .expect(200, function(err, response){
              
            let userInfoResp = rph.getUserInfo(res['state_key'], client, tokenResponse['access_token'], {response: response});
              
            assert.isNotNull(userInfoResp);
      
            let stateKey = res['state_key'];
            
            session = rph.getSessionInformation(stateKey)
            client = rph.issuer2rp[session.claims['iss']];
            server2.close();
            
            let server3 = makeServer({"sub":"EndUserSubject", "mail":"foo@example.com"});
                
            client.service['userinfo'].endpoint = 'http://localhost:1080/';
            
            request(server3)
            .get('/')
            .expect(200, function(err, response){
                resp = rph.getUserInfo(res['state_key'], client, null, {response: response});
                assert.deepEqual(Object.keys(resp.claims), ['sub', 'mail']);
                assert.deepEqual(resp.claims['mail'], 'foo@example.com');
                done();
            });
        });
    });
    });
    done();
    }); 
});