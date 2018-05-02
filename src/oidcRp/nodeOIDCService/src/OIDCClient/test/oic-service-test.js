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

//var KeyJar = require('../oicMsg/src/models/keystore-dependency/keyJar.js');

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

describe('Test Authorization', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']}
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('Authorization', serviceContext, new DB(), CLIENT_AUTHN_METHOD)
  });

  it('test construct authorization request', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'code',
    'state': 'state'}
    let msg = service.construct(requestArgs);
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type', 'state', 'redirect_uri', 'scope',
    'nonce', 'client_id']);
  });

  it('test construct token', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'token',
    'state': 'state'}
    let msg = service.construct(requestArgs);
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type', 'state', 'redirect_uri', 'scope','client_id']);
  });
  it('test construct nonce', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'token', 'nonce': 'nonce',
    'state': 'state'}
    let msg = service.construct(requestArgs); 
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type',  'nonce', 'state', 'redirect_uri', 'scope', 'client_id']);
  });
  it('test get request parameters', function() {
    let requestArgs = {'response_type': 'code', 'state': 'state'}
    service.endpoint = 'https://example.com/authorize'
    info = service.getRequestParameters({requestArgs:requestArgs});
    assert.deepEqual(Object.keys(info), ['method', 'url'])
    let msg = new AuthorizationRequest().fromUrlEncoded(service.getUrlInfo(info['url']));
    assert.deepEqual(Object.keys(msg.claims), ['response_type', 'state', 'redirect_uri', 'scope', 'nonce', 'client_id']);
  });
  it('test get request init', function() {
    let requestArgs = {'response_type': 'code', 'state': 'state'}
    service.endpoint = 'https://example.com/authorize'
    info = service.getRequestParameters({requestArgs:requestArgs});
    assert.deepEqual(Object.keys(info), ['method', 'url'])
    let msg = new AuthorizationRequest().fromUrlEncoded(service.getUrlInfo(info['url']));
    assert.deepEqual(Object.keys(msg.claims), ['response_type', 'state', 'redirect_uri', 'scope', 'nonce', 'client_id']);
  });
  it('test request init request method', function() {
    let requestArgs = {'response_type': 'code', 'state': 'state'}
    service.endpoint = 'https://example.com/authorize'
    info = service.getRequestParameters({requestArgs:requestArgs, params: {requestMethod: 'value'}});
    assert.deepEqual(Object.keys(info), ['method', 'url'])
    let msg = new AuthorizationRequest().fromUrlEncoded(service.getUrlInfo(info['url']));
    assert.deepEqual(Object.keys(msg.claims), ['response_type', 'state', 'redirect_uri', 'scope', 'nonce', 'client_id']);
  });
  it('test request param', function() {
    let requestArgs = {'response_type': 'code', 'state': 'state'}
    service.endpoint = 'https://example.com/authorize'
    service.serviceContext.registrationResponse = {'redirect_uris': ['https://example.com/cb'],
    'request_uris': ['https://example.com/request123456.jwt']};
    service.serviceContext.baseUrl = 'https://example.com/';
    info = service.getRequestParameters({requestArgs:requestArgs, params: {requestMethod: 'reference'}})
    assert.deepEqual(Object.keys(info), ['method', 'url']);
  });
})

describe('Test Authorization callback', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'callback': {
        'code': 'https://example.com/cli/authz_cb',
        'implicit': 'https://example.com/cli/authz_im_cb',
        'form_post': 'https://example.com/cli/authz_fp_cb'
    }};
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('Authorization', serviceContext, new DB(), CLIENT_AUTHN_METHOD)
  });

  it('test construct code', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'code',
    'state': 'state'}
    let msg = service.construct(requestArgs);
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type', 'state', 'redirect_uri', 'scope',
    'nonce', 'client_id']);
    assert.deepEqual(msg.claims['redirect_uri'], 'https://example.com/cli/authz_cb');
  });

  it('test construct implicit', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'id_token token',
    'state': 'state'}
    let msg = service.construct(requestArgs);
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type', 'state', 'redirect_uri', 'scope',
    'nonce', 'client_id']);
    assert.deepEqual(msg.claims['redirect_uri'], 'https://example.com/cli/authz_im_cb');
  });
  it('test construct form post', function() {
    let requestArgs = {'foo': 'bar', 'response_type': 'code id_token token',
    'state': 'state', 'response_mode': 'form_post'}
    let msg = service.construct(requestArgs);
    assert.deepEqual(Object.keys(msg.claims), ['foo',
    'response_type', 'state', 'response_mode', 'redirect_uri', 'scope',
    'nonce', 'client_id']);
    assert.deepEqual(msg.claims['redirect_uri'], 'https://example.com/cli/authz_im_cb');
  });
});

describe('Test access token request', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
    let clientConfig ={'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb']};
    serviceContext = new ServiceContext(null, clientConfig);
    let db = new DB();
    let authRequest = new AuthorizationRequest({redirect_uri: 'https://example.com/cli/authz_cb', state:'state', response_type:'code'});
    let authResponse = new AuthorizationResponse({code:'access_code'});
    let _state = new State({auth_request: authRequest.toJSON(), auth_response: authResponse.toJSON()});
    db.set('state', _state.toJSON());
    service = new factory('AccessToken', serviceContext, db, CLIENT_AUTHN_METHOD);
  });

  it('test construct', function() {
    let requestArgs = {'foo': 'bar'}
    let msg = service.construct(requestArgs, {'state': 'state'});
    assert.deepEqual(Object.keys(msg.claims), ['foo', 'redirect_uri', 'state', 'code', 'grant_type', 'client_id', 'client_secret']);
  });
  it('test get request parameters', function() {
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
  });
  it('test get request init', function() {
    let requestArgs = {'redirect_uri': 'https://example.com/cli/authz_cb',
    'code': 'access_code'}
    service.endpoint = 'https://example.com/authorize'
    info = service.getRequestParameters({requestArgs:requestArgs, params: {state: 'state'}});
    assert.deepEqual(Object.keys(info), ['method', 'url', 'body', 'headers']);
    assert.deepEqual(info.url, 'https://example.com/authorize');
    let msg = new AccessTokenRequest().fromUrlEncoded(service.getUrlInfo(info['body']));
    assert.deepEqual(msg.claims, {
      'client_id': 'client_id', 'code': 'access_code',
      'grant_type': 'authorization_code', 'state': 'state',
      'redirect_uri': 'https://example.com/cli/authz_cb'});
  });
  it('test id token none match', function() {
    service.storeNonce2State('nonce', 'state');
    let resp = new AccessTokenResponse({verifiedIdToken:{nonce:'nonce'}});
    service.storeNonce2State('nonce2', 'state2');
    try{
        service.updateServiceContext(resp, 'state2')
    }catch(err){
        console.log(err)
    }
  });
});

describe('Test provider info', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig ={'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss,
    'client_preferences': {
        'id_token_signed_response_alg': 'RS384',
        'userinfo_signed_response_alg': 'RS384'
    }}
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('ProviderInfoDiscovery', serviceContext, null, CLIENT_AUTHN_METHOD);
  });

  it('test construct', function() {
    let msg = service.construct();
    assert.deepEqual(Object.keys(msg.claims).length, 0);
  });
  it('Test getRequestParameters', function() {
    let info = service.getRequestParameters()
    assert.deepEqual(Object.keys(info), ['method', 'url']);
    assert.deepEqual(info['url'], iss + '/.well-known/openid-configuration');
  });
});

describe('Test registration', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss, 'requests_dir': 'requests',
    'base_url': 'https://example.com/cli/'};
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
  });
  it('test construct', function() {
    let msg = service.construct();
    assert.deepEqual(Object.keys(msg.claims).length, 4);
  });
  it('test config with post logout', function() {
    /*service.serviceContext.postLogoutRedirectUris = ['https://example.com/post_logout'];
    let req = service.construct();
    assert.deepEqual(Object.keys(req.claims).length, 5);
    assert.isTrue(Object.keys(req.claims).indexOf('post_logout_redirect_uris') !== -1);*/
  });
  it('test config with required request uri', function() {
    service.serviceContext.providerInfo['require_request_uri_registration'] = true
    let req = service.construct();
    assert.deepEqual(Object.keys(req.claims).length, 5);
    assert.isTrue(Object.keys(req.claims).indexOf('request_uris') !== -1);
  });
});

describe('Test user info', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss, 'requests_dir': 'requests',
    'base_url': 'https://example.com/cli/'};
    serviceContext = new ServiceContext(null, clientConfig);

    let db = new DB();
    let tokenResponse = new AccessTokenResponse({access_token:'access_token', id_token:'a.signed.jwt', verified_id_token:{sub:'diana'}});
    let authResponse = new AuthorizationResponse({code:'access_code'});
    let _state = new State({token_response: tokenResponse.toJSON(), auth_response: authResponse.toJSON()});
    db.set('abcde', _state.toJSON());
    service = new factory('UserInfo', serviceContext, db, CLIENT_AUTHN_METHOD);
  });
  it('test construct', function() {
    let msg = service.construct(null, {state: 'abcde'});
    assert.deepEqual(Object.keys(msg.claims).length, 1);
    assert.isTrue(Object.keys(msg.claims).indexOf('access_token') !== -1)
  });
  it('test unpack simple response', function() {
    let resp = new OpenIDSchema({sub:'diana', given_name:'Diana', family_name:'krall'});
    resp = service.parseResponse(resp.toJSON(), null, null, {state:'abcde'});
    assert.isNotNull(resp);
  });
  it('test unpack aggregated response', function() {
    let resp = new OpenIDSchema({sub:'diana', given_name:'Diana', family_name:'krall'});
    resp = service.parseResponse(resp.toJSON(), null, null, {state:'abcde'});
    assert.isNotNull(resp);
  });
});

describe('Test check session', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss, 'requests_dir': 'requests',
    'base_url': 'https://example.com/cli/'};
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('CheckSession', serviceContext, new DB(), CLIENT_AUTHN_METHOD);
  });
  it('test construct', function() {
    service.storeItem(new Message({'id_token': 'a.signed.jwt'}), 'token_response', 'abcde');
    let msg = service.construct(null, {state: 'abcde'});
    assert.deepEqual(Object.keys(msg.claims).length, 1);
  });
});

describe('Test check id', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss, 'requests_dir': 'requests',
    'base_url': 'https://example.com/cli/'}
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('CheckId', serviceContext, new DB(), CLIENT_AUTHN_METHOD);
  });
  it('test construct', function() {
    service.storeItem(new Message({'id_token': 'a.signed.jwt'}), 'token_response', 'abcde');
    let msg = service.construct(null, {state: 'abcde'});
    assert.deepEqual(Object.keys(msg.claims).length, 1);
  });
});

describe('Test end session', function() {
  let service;
  let serviceContext;
  let iss = 'https://example.com/as';
  beforeEach(function() {
    let clientConfig = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': iss, 'requests_dir': 'requests',
    'base_url': 'https://example.com/cli/'}
    serviceContext = new ServiceContext(null, clientConfig);
    service = new factory('EndSession', serviceContext, new DB(), CLIENT_AUTHN_METHOD);
  });
  it('test construct', function() {
    service.storeItem(new Message({'id_token': 'a.signed.jwt'}), 'token_response', 'abcde');
    let msg = service.construct(null, {state: 'abcde'});
    assert.deepEqual(Object.keys(msg.claims).length, 1);
  });
});

describe('Test  add jwks uri or jwks0', function() {
  it('should work', function() {
    let iss = 'https://example.com/as';
    let client_config = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'jwks_uri': 'https://example.com/jwks/jwks.json',
    'issuer': 'https://example.com/as',
    'client_preferences': {
        'id_token_signed_response_alg': 'RS384',
        'userinfo_signed_response_alg': 'RS384'
    }}
    let serviceContext= new ServiceContext(null, client_config);
    let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
    let list = addJwksUriOrJwks({}, service);
    let reqArgs = list[0];
    let postArgs = list[1];
    assert.deepEqual(reqArgs['jwks_uri'], 'https://example.com/jwks/jwks.json');
  });
});

describe('Test  add jwks uri or jwks1', function() {
  it('should work', function() {
    let iss = 'https://example.com/as';
    let client_config = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'jwks_uri': 'https://example.com/jwks/jwks.json',
    'jwks': '{"keys":[]}',
    'issuer': 'https://example.com/as',
    'client_preferences': {
        'id_token_signed_response_alg': 'RS384',
        'userinfo_signed_response_alg': 'RS384'
    }}
    let serviceContext= new ServiceContext(null, client_config);
    let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
    let list = addJwksUriOrJwks({}, service);
    let reqArgs = list[0];
    let postArgs = list[1];
    assert.deepEqual(reqArgs['jwks_uri'], 'https://example.com/jwks/jwks.json');
  });
});

describe('Test  add jwks uri or jwks2', function() {
  it('should work', function() {
    let client_config = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': 'https://example.com/as',
    'client_preferences': {
        'id_token_signed_response_alg': 'RS384',
        'userinfo_signed_response_alg': 'RS384'
    }}
    let serviceContext= new ServiceContext(null, client_config, {jwks_uri:'https://example.com/jwks/jwks.json'});
    let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
    let list = addJwksUriOrJwks({}, service);
    let reqArgs = list[0];
    let postArgs = list[1];
    assert.deepEqual(reqArgs['jwks_uri'], 'https://example.com/jwks/jwks.json');
  });
});

describe('Test  add jwks uri or jwks3', function() {
  it('should work', function() {
    let client_config = {'client_id': 'client_id', 'client_secret': 'password',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'issuer': 'https://example.com/as',
    'client_preferences': {
        'id_token_signed_response_alg': 'RS384',
        'userinfo_signed_response_alg': 'RS384'
    }}
    let serviceContext= new ServiceContext(null, client_config, {jwks:'{"keys":[]}'});
    let service = new factory('Registration', serviceContext, null, CLIENT_AUTHN_METHOD);
    let list = addJwksUriOrJwks({}, service);
    let reqArgs = list[0];
    let postArgs = list[1];
    assert.deepEqual(reqArgs['jwks'], '{"keys":[]}');
  });
});

/*
describe('Test authz service conf', function() {
  let service;
  let serviceContext;
  beforeEach(function() {
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
  });

  it('test construct', function() {
    let req = service.construct();
    assert.isTrue(Object.keys(req).indexOf('claims') !== -1);
    assert.deepEqual(Object.keys(req.claims), ['id_token']);
  });
});*/