const assert = require('chai').assert;
const AccessTokenRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const Client = require('../src/oauth2/init').Client;
const CLIENT_AUTHN_METHOD =
    require('../src/clientAuth/clientAuth').CLIENT_AUTHN_METHOD;
const ClientSecretPost =
    require('../src/clientAuth/clientSecretPost').ClientSecretPost;
const AuthorizationRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const State = require('../src/state').State;
const buildServices = require('../src/service').buildServices;
const DEFAULT_SERVICES = require('../src/oic/init').DEFAULT_SERVICES;
const OicFactory = require('../src/oic/service/service').OicFactory;
const ServiceContext = require('../src/serviceContext').ServiceContext;
const AuthorizationResponse =
require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;

const CLIENT_ID = 'A';

const CLIENT_CONF = {
  'issuer': 'https://example.com/as',
  'redirect_uris': ['https://example.com/cli/authz_cb'],
  'client_secret': 'boarding pass',
  'client_id': CLIENT_ID
};

const REQ_ARGS = {
  'redirect_uri': 'https://example.com/rp/cb',
  'response_type': 'code'
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

describe('Test client secret post', function() {
  let services = getServices();
  it('test construct', function() {
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
  });
});