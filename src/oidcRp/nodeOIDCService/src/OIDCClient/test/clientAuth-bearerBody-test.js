const assert = require('chai').assert;
const AccessTokenResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const BearerBody = require('../src/clientAuth/bearerBody').BearerBody;
const Client = require('../src/oauth2/init').Client;
const CLIENT_AUTHN_METHOD =
    require('../src/clientAuth/clientAuth').CLIENT_AUTHN_METHOD;
const ResourceRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').ResourceRequest;
const State = require('../src/state').State;
const buildServices = require('../src/service').buildServices;
const DEFAULT_SERVICES = require('../src/oic/init').DEFAULT_SERVICES;
const OicFactory = require('../src/oic/service/service').OicFactory;
const ServiceContext = require('../src/serviceContext').ServiceContext;
const AuthorizationRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;

const CLIENT_ID = 'A';

const CLIENT_CONF = {
  issuer: 'https://example.com/as',
  redirect_uris: ['https://example.com/cli/authz_cb'],
  client_secret: 'boarding pass',
  client_id: CLIENT_ID,
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
  let authRequest = AuthorizationRequest.toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
  let authResponse = AuthorizationResponse.toJSON({access_token: 'token', state: 'ABCDE'});
  db.set('ABCDE', State.toJSON({iss:'Issuer', auth_request:authRequest, auth_response:authResponse}));
  return buildServices(DEFAULT_SERVICES, OicFactory, getServiceContext(), db, CLIENT_AUTHN_METHOD);
}

describe('Test bearer body', () => {
  let services = getServices();
  let authSrv = services['authorization'];
  let accessTokenSrv = services['accessToken'];
  
  it('test construct with request args', () => {
    const requestArgs = {access_token: 'Sesame'};
    let request = new ResourceRequest(requestArgs);
    const list = new BearerBody().construct(request, accessTokenSrv); 
    const httpArgs = list[0];
    request = list[1];
    assert.deepEqual(request.access_token, 'Sesame');
    assert.deepEqual(httpArgs, undefined);
  });

  it('test construct with state', () => {
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
  });

  it('test construct with request', () => {
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
  });
});