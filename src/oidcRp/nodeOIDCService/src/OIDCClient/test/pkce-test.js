const assert = require('chai').assert;
const ServiceContext = require('../src/serviceContext.js').ServiceContext;
const addCodeChallenge = require('../src/oic/pkce.js').addCodeChallenge;
const addCodeVerifier = require('../src/oic/pkce.js').addCodeVerifier;
const base64url = require('base64url');
const SINGLE_REQUIRED_STRING =
require('../nodeOIDCMsg/src/oicMsg/oauth2/init').SINGLE_REQUIRED_STRING;
const Message = require('../nodeOIDCMsg/src/oicMsg/message');
const Service = require('../src/service').Service;
const State = require('../src/state').State;



class DummyMessage extends Message{
  constructor(){
    super();
    this.cParam = {'req_str': SINGLE_REQUIRED_STRING}
    return this;
  }
}

class DummyService extends Service{
  constructor(ci, db){
    super(ci, db);
    this.msgType = DummyMessage;
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

describe('Test PKCE', function() {
  let ci;
  let spec;
  let service;
  let state;
  beforeEach(function() {
    let config = {
      'client_id': 'client_id',
      'issuer': 'issuer',
      'client_secret': 'client_secret',
      'base_url': 'https://example.com',
      'requests_dir': 'requests',
    };

    ci = new ServiceContext(null, config, {client_id:'client_id', issuer: 'https://www.example.org/as'});
    service = new DummyService(ci, new DB());
    //state = new State({iss:'Issuer'});
    //service.stateDb.set('state', state.toJSON())
    service.stateDb.set('state', State.toJSON({iss:'Issuer'}))
    spec = addCodeChallenge({state: 'state'}, service);
  });

  it('Test add code challenge default values', function() {
    assert.deepEqual(
      Object.keys(spec), ['state', 'code_challenge', 'code_challenge_method']);
    assert.deepEqual(spec['code_challenge_method'], 'sha256');

    let codeVerifier = addCodeVerifier({}, service, {state: 'state'});
    assert.deepEqual(codeVerifier.length, 64);
  });
});

describe('Test PKCE', function() {
  let ci;
  let spec;
  let service;
  let state;
  beforeEach(function() {
    let config = {
      'client_id': 'client_id',
      'issuer': 'issuer',
      'client_secret': 'client_secret',
      'base_url': 'https://example.com',
      'requests_dir': 'requests',
      'code_challenge': {'length': 128, 'method': 'sha384'}
    };

    ci = new ServiceContext(null, config, {client_id:'client_id', issuer: 'https://www.example.org/as'});
    service = new DummyService(ci, new DB());
    state = new State({iss:'Issuer'});
    //service.stateDb.set('state', state.toJSON())
    service.stateDb.set('state', State.toJSON({iss:'Issuer'}))
    spec = addCodeChallenge({state: 'state'}, service);
  });

  it('Test add code challenge default values', function() {
    assert.deepEqual(
      Object.keys(spec), ['state', 'code_challenge', 'code_challenge_method']);
    assert.deepEqual(spec['code_challenge_method'], 'sha384');

    let codeVerifier = addCodeVerifier({}, service, {state: 'state'});
    assert.deepEqual(codeVerifier.length, 128);
  });
});