
const assert = require('chai').assert;
const RP = require('../oic/init').RP;
const State = require('../nodeOIDCService/src/OIDCClient/src/state').State;
const AuthorizationRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse = require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const AccessTokenResponse = require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;

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

describe('Test Client', function() {
    let client = null;
    beforeEach(function() {
        this.redirectUri = "http://example.com/redirect";
        let conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop'
        }
        client = new RP({stateDb:new DB(), config:conf});
        client.stateDb.set('ABCDE', new State().toJSON({iss:'issuer'}));
    });

    it('Test construct authorization request', function() {      
        let reqArgs = {'state': 'ABCDE',
        'redirect_uri': 'https://example.com/auth_cb',
        'response_type': ['code']};
        let msg = client.service['authorization'].construct({requestArgs: reqArgs});
        assert.deepEqual(msg.claims['redirect_uri', 'https://example.com/auth_cb']);
    });

    it('Test construct accesstoken request', function() { 
        let reqArgs = {}; 
        let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
        let authResponse = new AuthorizationResponse({code:'access_code'});
        let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
        client.stateDb.set('ABCDE', _state.toJSON());
        let msg = client.service['accessToken'].construct(reqArgs, {state: 'ABCDE'});
        assert.deepEqual(Object.keys(msg.claims).length, 6);
    });

    it('Test construct refreshtoken request', function() { 
        let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
        let tokenResponse = new AccessTokenResponse({refresh_token:'refresh_with_me', access_token:'access'});
        let authResponse = new AuthorizationResponse({code:'access_code'});
        let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON(), token_response: tokenResponse.toJSON()});
        client.stateDb.set('ABCDE', _state.toJSON());
        let reqArgs = {};

        let msg = client.service['refresh_token'].construct(reqArgs, {state: 'ABCDE'});
        assert.deepEqual(Object.keys(msg.claims).length, 4);
    });
    it('Test userinfo request init', function() { 
        let authRequest = new AuthorizationRequest({redirect_uri:'https://example.com/cli/authz_cb', state: 'state'});
        let tokenResponse = new AccessTokenResponse({refresh_token:'refresh_with_me', access_token:'access'});
        let authResponse = new AuthorizationResponse({code:'access_code'});
        let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON(), token_response: tokenResponse.toJSON()});
        client.stateDb.set('ABCDE', _state.toJSON());
        let reqArgs = {};

        let srv = client.service['userinfo'];
        srv.endpoint = "https://example.com/userinfo";
        let info = srv.getRequestParameters({params:{state:'ABCDE'}});
        assert.deepEqual(info['headers'], {'Authorization': 'Bearer access'});
        assert.deepEqual(info['url'], 'https://example.com/userinfo');
    });
});