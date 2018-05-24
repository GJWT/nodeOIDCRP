const assert = require('chai').assert;
const AccessTokenRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AccessTokenRequest;
const AccessTokenResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AccessTokenResponse;
const AuthorizationRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').AuthorizationRequest;
const AuthorizationResponse =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/responses').AuthorizationResponse;
const CCAccessTokenRequest =
    require('../nodeOIDCMsg/src/oicMsg/oauth2/requests').CCAccessTokenRequest;
const Client = require('../src/oauth2/init').Client;
const CLIENT_AUTHN_METHOD =
    require('../src/clientAuth/clientAuth').CLIENT_AUTHN_METHOD;
const ClientSecretBasic =
    require('../src/clientAuth/clientSecretBasic').ClientSecretBasic;
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
    let authRequest = AuthorizationRequest.toJSON({redirect_uri: 'http://example.com', state: 'ABCDE'});
    let authResponse = AuthorizationResponse.toJSON({access_token: 'token', state: 'ABCDE'});
    db.set('ABCDE', State.toJSON({iss:'Issuer', auth_request:authRequest, auth_response:authResponse}));
    return buildServices(DEFAULT_SERVICES, OicFactory, getServiceContext(), db, CLIENT_AUTHN_METHOD);
  }

describe('Test client secret basic', () => {
  /*let services = getServices();
  let request = services['accessToken'].construct(null, null, {'redirect_uri':
  'http://example.com', 'state': 'ABCDE'})
  const csb = new ClientSecretBasic();
  let httpArgs = csb.construct((request, services['accessToken']))*/
  //assert.deepEqual(httpArgs, {'headers': {'Authorization': 'Basic QTpib2FyZGluZyBwYXNz'}})

  it('test construct', () => {
   /* const credentialsDict = {};
    credentialsDict['A'] = 'boarding pass';
    const authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    const headersDict = {};
    headersDict.headers = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);*/
  });

  it('test does not remove padding', () => {
    const request = new AccessTokenRequest(
      {code: 'foo', redirect_uri: 'http://example.com'});
    const csb = new ClientSecretBasic();
    const httpArgs = csb.construct(
      request, null, null, {user: 'ab', password: 'c'});
    const credentialsDict = {};
    credentialsDict['ab'] = 'c';
    const authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    const headersDict = {};
    headersDict.headers = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);
  });

  it('test construct cc', () => {
    const request = new CCAccessTokenRequest({grant_type: 'client_credentials'});
    const csb = new ClientSecretBasic();
    const httpArgs = csb.construct(
      request, null, null,
      {user: 'service1', password: 'secret'});
    const credentialsDict = {};
    credentialsDict['service1'] = 'secret';
    const authorizationDict = {};
    authorizationDict['Authorization'] = credentialsDict;
    const headersDict = {};
    headersDict.headers = authorizationDict;
    assert.deepEqual(headersDict, httpArgs);
  });
});