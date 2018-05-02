const assert = require('chai').assert;
const AccessTokenRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const AccessTokenResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
const AuthorizationRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const BearerHeader = require('../src/clientAuth/bearerHeader').BearerHeader;
const Client = require('../src/oauth2/init').Client;
const CLIENT_AUTHN_METHOD = require('../src/clientAuth/clientAuth').CLIENT_AUTHN_METHOD;
const ResourceRequest = require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').ResourceRequest;
const State = require('../src/state').State;
const buildServices = require('../src/service').buildServices;
const DEFAULT_SERVICES = require('../src/oic/init').DEFAULT_SERVICES;
const OicFactory = require('../src/oic/service/service').OicFactory;
const ServiceContext = require('../src/serviceContext').ServiceContext;

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

describe('Test bearer header', () => {
  let services = getServices();

  it('test construct', () => {
    const request = new ResourceRequest({access_token: 'Sesame'});
    const bh = new BearerHeader();
    const httpArgs = bh.construct(request);
    const testDict = {headers: {Authorization: 'Bearer Sesame'}};
    assert.deepEqual(testDict, httpArgs);
  });

  it('test construct with http args', () => {
    const request = new ResourceRequest({access_token: 'Sesame'});
    const bh = new BearerHeader();
    const httpArgs = bh.construct(request, null, {foo: 'bar'});
    assert.deepEqual(Object.keys(httpArgs), ['foo', 'headers']);
    const testDict = {Authorization: 'Bearer Sesame'};
    assert.deepEqual(testDict, httpArgs.headers);
  });

  it('test construct with headers in http args', () => {
    const request = new ResourceRequest({access_token: 'Sesame'});
    const bh = new BearerHeader();
    const httpArgs = bh.construct(request, null, {headers: {xfoo: 'bar'}});
    assert.deepEqual(Object.keys(httpArgs), ['headers']);
    assert.deepEqual(Object.keys(httpArgs.headers), ['xfoo', 'Authorization']);
    assert.deepEqual(httpArgs.headers['Authorization'], 'Bearer Sesame');
  });

  it('test construct with resource request', () => {
    const bh = new BearerHeader();
    const request = new ResourceRequest({access_token: 'Sesame'});
    const httpArgs = bh.construct(request, getService());
    assert.isUndefined(request.access_token);
    assert.deepEqual(httpArgs, {headers: {Authorization: 'Bearer Sesame'}});
  });

  it('test construct with token', () => {
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
  });
});