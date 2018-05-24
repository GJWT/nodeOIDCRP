const assert = require('chai').assert;
var CLIENT_AUTHN_METHOD =
    require('../src/clientAuth/privateKeyJWT').CLIENT_AUTHN_METHOD;
var ServiceContext = require('../src/ServiceContext.js').ServiceContext;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const Service = require('../src/service.js').Service;
const factory = require('../src/oauth2/service/service').Factory;
const AuthorizationRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const AccessTokenResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
var AccessTokenRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const State = require('../src/state').State;

class Response {
  constructor(statusCode, text, headers) {
    headers = headers || null;
    this.statusCode = statusCode;
    this.text = text;
    this.headers = headers || {'content-type': 'text/plain'};
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

function testServiceFactory() {
  var req = new factory('Service', new ServiceContext(), new DB());
  assert.deepEqual(typeof req, Service);
}

describe('Test Authorization', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    let config = {
      'client_id': 'client_id',
      'client_secret': 'password',
      'redirect_uris': ['https://example.com/cli/authz_cb']
    };
    serviceContext = new ServiceContext(null, config);
    service = new factory('Authorization', serviceContext, new DB());
  });
  it('Test construct', function() {
    let reqArgs = {'foo': 'bar'};
    let req = service.construct(reqArgs, {state: 'state'});
    assert.deepEqual(Object.keys(req.claims).length, 4);
  });
  it('Test get request parameters', function() {
    var reqArgs = {'response_type': 'code'};
    service.endpoint = 'https://example.com/authorize';
    var info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    var msg = AuthorizationRequest.fromUrlEncoded(
      service.getUrlInfo(info['url']));
    assert.deepEqual(Object.keys(msg).length, 4);    
  });
  it('Test request init', function() {
    let resp = {client_id:'client_id', redirect_uri: 'https://example.com/cli/authz_cb', response_type : 'code', state:'state'};
    var reqArgs = {'response_type': 'code', 'state': 'state'};
    service.endpoint = 'https://example.com/authorize';
    var info = service.getRequestParameters({requestArgs :reqArgs});
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    assert.deepEqual(info['httpArgs'], undefined);
    var msg = AuthorizationRequest.fromUrlEncoded(
      service.getUrlInfo(info['url']));
    assert.deepEqual(msg, resp);
  });
});

describe('Test Access Token Request', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
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
  });
  it('Test construct', function() {
    let reqArgs = {'foo': 'bar', 'state': 'state'};
    let req = service.construct(reqArgs);
    assert.deepEqual(Object.keys(req.claims).length, 7);
  });
  it('Test construct 2', function() {
    let reqArgs = {'foo': 'bar'};
    let req = service.construct(reqArgs, {state: 'state'});
    assert.deepEqual(Object.keys(req.claims).length, 7);
  });
  it('Test get request parameters', function() {
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
    var msg = AccessTokenRequest.fromUrlEncoded(
      service.getUrlInfo(info['body']));
    assert.deepEqual(msg, {
      'client_id': 'client_id',
      'code': 'access_code',
      'grant_type': 'authorization_code',
      'redirect_uri': 'https://example.com/cli/authz_cb',
      'state': 'state'
    });
    assert.deepEqual(Object.keys(msg).indexOf('client_secret'), -1);
    assert.isNotNull(Object.keys(info['headers'].Authorization)); 
  });
  it('Test request init', function() {
    var reqArgs = {
      'redirect_uri': 'https://example.com/cli/authz_cb',
      'code': 'access_code'
    };
    service.endpoint = 'https://example.com/authorize';
    var info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
    assert.deepEqual(Object.keys(info).length, 4);
    assert.deepEqual(info['url'], 'https://example.com/authorize');
    var msg = AccessTokenRequest.fromUrlEncoded(
      service.getUrlInfo(info['body']));
    assert.deepEqual(msg, {
      'client_id': 'client_id',
      'state': 'state',
      'code': 'access_code',
      'grant_type': 'authorization_code',
      'redirect_uri': 'https://example.com/cli/authz_cb'
    });
  });
});

describe('Test Provider Info', function() {
  let service;
  let serviceContext;
  let iss;
  beforeEach(function() {
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
  });
  it('Test construct', function() {
    let req = service.construct();
    assert.deepEqual(Object.keys(req.claims).length, 0);
  });
  it('Test getRequestParameters', function() {
    let info = service.getRequestParameters()
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    assert.deepEqual(info['url'], iss + '/.well-known/openid-configuration');
  });
});

describe('Test Refresh Access Token Request', function() {
  let service;
  let serviceContext;
  let iss;
  beforeEach(function() {
    let config = {
      'client_id': 'client_id',
      'client_secret': 'password',
      'redirect_uris': ['https://example.com/cli/authz_cb']
    };
    serviceContext = new ServiceContext(null, config);
    let db = new DB();
    let tokenResponse = new AccessTokenResponse({access_token:'bearer_token', refresh_token:'refresh'});
    let authResponse = new AuthorizationResponse({code:'access_code'});
    //let _state = new State({token_response: tokenResponse.toJSON(), auth_response: authResponse.toJSON()});
    //db.set('abcdef', _state.toJSON());
    db.set('abcdef', State.toJSON({token_response: AccessTokenResponse.toJSON({access_token:'bearer_token', refresh_token:'refresh'}), auth_response: AuthorizationResponse.toJSON({code:'access_code'})}))
    service = new factory('RefreshAccessToken', serviceContext, db);
    service.endpoint = 'https://example.com/token';
  });

  it('Test construct', function() {
    let req = service.construct(null, {state: 'abcdef'});
    assert.deepEqual(Object.keys(req.claims).length, 4);
    assert.deepEqual(
      Object.keys(req.claims),
      ['grant_type', 'refresh_token', 'client_id', 'client_secret']);
  });
  it('Test request info', function() {
    let info = service.getRequestParameters({params: {state: 'abcdef'}})
    assert.deepEqual(Object.keys(info), ['method', 'url', 'body', 'headers']);
  });
});

describe('Test access token srv conf', function() {
  let service;
  let serviceContext;
  let iss;
  beforeEach(function() {
    let config = {
      'client_id': 'client_id',
      'client_secret': 'password',
      'redirect_uris': ['https://example.com/cli/authz_cb']
    };
    serviceContext = new ServiceContext(null, config);
    let db = new DB();
    //let authRequest = new AuthorizationRequest({redirect_uri: 'https://example.com/cli/authz_cb', state:'state'});
    //let authResponse = new AuthorizationResponse({code:'access_code'});
    let _state = State;
    db.set('state', _state.toJSON({auth_request: AuthorizationRequest.toJSON({redirect_uri: 'https://example.com/cli/authz_cb', state:'state'}), auth_response: AuthorizationResponse.toJSON({code:'access_code'})}));
    service = new factory('AccessToken', serviceContext, db, null, {'default_authn_method': 'client_secret_post'});
    service.endpoint = 'https://example.com/authorize';    
  });
  it('Test request info', function() {
    let reqArgs = {
      'redirect_uri': 'https://example.com/cli/authz_cb',
      'code': 'access_code'
    };
    let info = service.getRequestParameters({requestArgs: reqArgs, params: {state: 'state'}});
    let msg = AccessTokenRequest.fromUrlEncoded(service.getUrlInfo(info['body']));
    assert.isNotNull(msg.client_secret);
  });
});